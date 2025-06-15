from flask import Flask, jsonify, request, render_template, send_file
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import base58
import hashlib
import json
import time
import threading
import io
import qrcode
from collections import defaultdict

app = Flask(__name__)

# Constants
MAX_SUPPLY = 21_000_000
REWARD_INITIAL = 50
HALVING_INTERVAL = 210000
DIFFICULTY_ADJUST_INTERVAL = 2016
TARGET_BLOCK_TIME = 10 * 60

# ----------------- Helper Functions -----------------
def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def public_key_to_address(pubkey_bytes: bytes) -> str:
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    return base58check_encode(b'\x00' + ripe)

# ----------------- Wallet System -----------------
class Wallet:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()

    def serialize_private_key(self) -> str:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def serialize_public_key(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

    def get_address(self) -> str:
        return public_key_to_address(self.serialize_public_key())

wallets = {}

# ----------------- Transaction Model -----------------
class TransactionInput:
    def __init__(self, txid: str, vout: int, signature: str = None, pubkey: str = None):
        self.txid = txid
        self.vout = vout
        self.signature = signature
        self.pubkey = pubkey

    def to_dict(self):
        return self.__dict__

class TransactionOutput:
    def __init__(self, amount: float, address: str):
        self.amount = amount
        self.address = address

    def to_dict(self):
        return self.__dict__

class Transaction:
    def __init__(self, vin, vout, timestamp=None):
        self.vin = vin
        self.vout = vout
        self.timestamp = timestamp or int(time.time())
        self.txid = self.calculate_txid()

    def calculate_txid(self):
        content = json.dumps(self.to_dict(include_txid=False), sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()

    def to_dict(self, include_txid=True):
        data = {
            "vin": [inp.to_dict() for inp in self.vin],
            "vout": [out.to_dict() for out in self.vout],
            "timestamp": self.timestamp
        }
        if include_txid:
            data["txid"] = self.txid
        return data

# ----------------- Block Model -----------------
def merkle_root(txids):
    if not txids:
        return ''
    while len(txids) > 1:
        if len(txids) % 2 == 1:
            txids.append(txids[-1])
        txids = [hashlib.sha256((txids[i] + txids[i+1]).encode()).hexdigest() for i in range(0, len(txids), 2)]
    return txids[0]

class Block:
    def __init__(self, index, previous_hash, transactions, difficulty, nonce=0, timestamp=None):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp or int(time.time())
        self.nonce = nonce
        self.difficulty = difficulty
        self.merkle_root = merkle_root([tx.txid for tx in transactions])
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        header = f"{self.index}{self.previous_hash}{self.merkle_root}{self.timestamp}{self.nonce}{self.difficulty}"
        return hashlib.sha256(header.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
            "merkle_root": self.merkle_root,
            "transactions": [tx.to_dict() for tx in self.transactions]
        }

# ----------------- Blockchain Logic -----------------
class Blockchain:
    def __init__(self):
        self.chain = []
        self.mempool = []
        self.utxos = {}
        self.difficulty = 4
        self.block_time_log = []

        coinbase_tx = Transaction([], [TransactionOutput(REWARD_INITIAL, "genesis")])
        self.utxos[f"{coinbase_tx.txid}:0"] = {"address": "genesis", "amount": REWARD_INITIAL}
        genesis = Block(0, "0" * 64, [coinbase_tx], self.difficulty)
        self.chain.append(genesis)
        self.block_time_log.append(genesis.timestamp)

    def get_latest_block(self):
        return self.chain[-1]

    def get_block_reward(self):
        halvings = len(self.chain) // HALVING_INTERVAL
        return max(REWARD_INITIAL >> halvings, 0)

    def get_balance(self, address):
        return sum(utxo['amount'] for utxo in self.utxos.values() if utxo['address'] == address)

    def validate_transaction(self, tx):
        total_in, total_out = 0, 0
        for txin in tx.vin:
            key = f"{txin.txid}:{txin.vout}"
            utxo = self.utxos.get(key)
            if not utxo:
                return False
            total_in += utxo['amount']
        total_out = sum(out.amount for out in tx.vout)
        return total_out <= total_in

    def add_transaction(self, tx):
        if self.validate_transaction(tx):
            self.mempool.append(tx)
            return True
        return False

    def update_utxos(self, block):
        for tx in block.transactions:
            for txin in tx.vin:
                key = f"{txin.txid}:{txin.vout}"
                self.utxos.pop(key, None)
            for i, txout in enumerate(tx.vout):
                self.utxos[f"{tx.txid}:{i}"] = {"address": txout.address, "amount": txout.amount}

    def mine_block(self, miner_address):
        reward = self.get_block_reward()
        coinbase = Transaction([], [TransactionOutput(reward, miner_address)])
        block_txs = [coinbase] + self.mempool.copy()
        prev = self.get_latest_block()
        new_block = Block(prev.index + 1, prev.hash, block_txs, self.difficulty)

        while not new_block.hash.startswith("0" * self.difficulty):
            new_block.nonce += 1
            new_block.timestamp = int(time.time())
            new_block.hash = new_block.calculate_hash()

        self.chain.append(new_block)
        self.block_time_log.append(new_block.timestamp)
        self.update_utxos(new_block)
        self.mempool.clear()
        return new_block

blockchain = Blockchain()
miner_rewards = defaultdict(float)

# ----------------- Flask Routes -----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/wallet/new')
def wallet_new():
    wallet = Wallet()
    addr = wallet.get_address()
    wallets[addr] = wallet
    return jsonify({
        "address": addr,
        "private_key": wallet.serialize_private_key(),
        "public_key": base58.b58encode(wallet.serialize_public_key()).decode()
    })

@app.route('/wallet/key/<address>')
def export_key(address):
    if address not in wallets:
        return jsonify({"error": "Not found"}), 404
    return send_file(io.BytesIO(wallets[address].serialize_private_key().encode()), download_name=f"{address}_key.txt", as_attachment=True)

@app.route('/wallet/qr/<address>')
def qr(address):
    img = qrcode.make(address)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/balance/<address>')
def balance(address):
    return jsonify({"address": address, "balance": blockchain.get_balance(address)})

@app.route('/utxos/<address>')
def get_utxos(address):
    result = []
    for key, utxo in blockchain.utxos.items():
        if utxo['address'] == address:
            txid, vout = key.split(":")
            result.append({"txid": txid, "vout": int(vout), "amount": utxo['amount']})
    return jsonify(result)

@app.route('/transaction/send', methods=['POST'])
def send_tx():
    data = request.json
    vin = [TransactionInput(**i) for i in data.get("vin", [])]
    vout = [TransactionOutput(**o) for o in data.get("vout", [])]
    tx = Transaction(vin, vout)
    if blockchain.add_transaction(tx):
        return jsonify({"message": "Transaction added", "txid": tx.txid})
    return jsonify({"error": "Invalid tx"}), 400

@app.route('/mine', methods=['POST'])
def mine():
    addr = request.json.get("miner_address")
    if not addr or addr not in wallets:
        return jsonify({"error": "Invalid address"}), 400
    block = blockchain.mine_block(addr)
    for tx in block.transactions:
        for out in tx.vout:
            if out.address == addr:
                miner_rewards[addr] += out.amount
    return jsonify({"message": f"Block #{block.index} mined", "block": block.to_dict()})

@app.route('/chain')
def full_chain():
    return jsonify({
        "length": len(blockchain.chain),
        "difficulty": blockchain.difficulty,
        "chain": [b.to_dict() for b in blockchain.chain]
    })

@app.route('/block/hash/<hash>')
def get_block(hash):
    for block in blockchain.chain:
        if block.hash == hash:
            return jsonify(block.to_dict())
    return jsonify({"error": "Not found"}), 404

@app.route('/tx/<txid>')
def get_tx(txid):
    for block in blockchain.chain:
        for tx in block.transactions:
            if tx.txid == txid:
                return jsonify(tx.to_dict())
    return jsonify({"error": "Not found"}), 404

@app.route('/leaderboard')
def leaderboard():
    sorted_rewards = sorted(miner_rewards.items(), key=lambda x: -x[1])
    return jsonify([{"address": k, "mined": v} for k, v in sorted_rewards])

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
