# ShadowChain V4 - Mega Backend (app.py)

from flask import Flask, jsonify, request, render_template, send_file
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import hashlib, base58, json, time, io, qrcode
from collections import defaultdict
import requests
import random

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Blockchain constants
MAX_SUPPLY = 21_000_000
REWARD_INITIAL = 50
HALVING_INTERVAL = 100  # shortened for testing

# Wallet system
class Wallet:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

    def get_address(self):
        pub_bytes = self.serialize_public_key()
        sha = hashlib.sha256(pub_bytes).digest()
        ripe = hashlib.new('ripemd160', sha).digest()
        payload = b'\x00' + ripe
        return base58.b58encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]).decode()

wallets = {}

# Blockchain models
class Transaction:
    def __init__(self, vin, vout):
        self.vin = vin
        self.vout = vout
        self.timestamp = int(time.time())
        self.txid = self.calculate_txid()

    def calculate_txid(self):
        content = json.dumps(self.to_dict(include_txid=False), sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()

    def to_dict(self, include_txid=True):
        d = {
            "vin": self.vin,
            "vout": self.vout,
            "timestamp": self.timestamp
        }
        if include_txid:
            d["txid"] = self.txid
        return d

class Block:
    def __init__(self, index, previous_hash, transactions, difficulty):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = int(time.time())
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(self.to_dict(include_hash=False), sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self, include_hash=True):
        d = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "nonce": self.nonce,
            "difficulty": self.difficulty
        }
        if include_hash:
            d["hash"] = self.hash
        return d

class Blockchain:
    def __init__(self):
        self.chain = []
        self.utxos = {}
        self.difficulty = 4
        self.mempool = []
        self.nodes = set()
        self.mined_per_address = defaultdict(float)
        self.total_mined = 0
        self.init_genesis()

    def init_genesis(self):
        coinbase = Transaction([], [{"amount": REWARD_INITIAL, "address": "genesis"}])
        genesis = Block(0, "0"*64, [coinbase], self.difficulty)
        self.chain.append(genesis)
        self.update_utxos(genesis)

    def get_last_block(self):
        return self.chain[-1]

    def get_block_reward(self):
        return max(REWARD_INITIAL >> (len(self.chain) // HALVING_INTERVAL), 1)

    def add_transaction(self, tx):
        self.mempool.append(tx)

    def update_utxos(self, block):
        for tx in block.transactions:
            for vin in tx.vin:
                key = f"{vin['txid']}:{vin['vout']}"
                self.utxos.pop(key, None)
            for i, vout in enumerate(tx.vout):
                self.utxos[f"{tx.txid}:{i}"] = {"amount": vout['amount'], "address": vout['address']}

    def mine_block(self, miner_address):
        reward = self.get_block_reward()
        coinbase = Transaction([], [{"amount": reward, "address": miner_address}])
        txs = [coinbase] + self.mempool
        new_block = Block(
            len(self.chain),
            self.get_last_block().hash,
            txs,
            self.difficulty
        )
        while not new_block.hash.startswith("0" * self.difficulty):
            new_block.nonce += 1
            new_block.hash = new_block.compute_hash()
        self.chain.append(new_block)
        self.update_utxos(new_block)
        self.mempool.clear()
        self.mined_per_address[miner_address] += reward
        self.total_mined += reward
        return new_block

blockchain = Blockchain()

# ----------------- Flask Routes -----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/wallet/new')
def wallet_new():
    w = Wallet()
    addr = w.get_address()
    wallets[addr] = w
    return jsonify({
        "address": addr,
        "private_key": w.serialize_private_key(),
        "public_key": base58.b58encode(w.serialize_public_key()).decode()
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
    bal = sum(utxo['amount'] for utxo in blockchain.utxos.values() if utxo['address'] == address)
    return jsonify({"address": address, "balance": bal})

@app.route('/utxos/<address>')
def utxos(address):
    result = []
    for k, v in blockchain.utxos.items():
        if v['address'] == address:
            txid, vout = k.split(":")
            result.append({"txid": txid, "vout": int(vout), "amount": v['amount']})
    return jsonify(result)

@app.route('/transaction/send', methods=['POST'])
def send_tx():
    data = request.json
    tx = Transaction(data['vin'], data['vout'])
    blockchain.add_transaction(tx)
    return jsonify({"message": "tx added", "txid": tx.txid})

@app.route('/mine', methods=['POST'])
def mine():
    miner_address = request.json.get("miner_address")
    block = blockchain.mine_block(miner_address)
    socketio.emit('new_block', block.to_dict())
    return jsonify({"message": f"Block #{block.index} mined", "block": block.to_dict()})

@app.route('/chain')
def full_chain():
    return jsonify({"length": len(blockchain.chain), "chain": [b.to_dict() for b in blockchain.chain]})

@app.route('/tx/<txid>')
def get_tx(txid):
    for b in blockchain.chain:
        for tx in b.transactions:
            if tx.txid == txid:
                return jsonify(tx.to_dict())
    return jsonify({"error": "not found"})

@app.route('/block/hash/<hash>')
def get_block(hash):
    for b in blockchain.chain:
        if b.hash == hash:
            return jsonify(b.to_dict())
    return jsonify({"error": "not found"})

@app.route('/leaderboard')
def leaderboard():
    return jsonify([{"address": k, "mined": v} for k, v in sorted(blockchain.mined_per_address.items(), key=lambda x: -x[1])])

@app.route('/tokenomics')
def tokenomics():
    return jsonify({
        "total_mined": blockchain.total_mined,
        "remaining_supply": MAX_SUPPLY - blockchain.total_mined,
        "block_reward": blockchain.get_block_reward(),
        "current_height": len(blockchain.chain)
    })

@app.route('/analyze/tx', methods=['POST'])
def analyze():
    tx = request.json
    score = random.uniform(0, 1)
    level = "⚠️ Risky" if score > 0.7 else "✅ Clean"
    return jsonify({"risk_score": round(score, 3), "status": level})

@app.route('/mint/token', methods=['POST'])
def mint_token():
    data = request.json
    amount = data.get('amount', 0)
    address = data.get('address')
    tx = Transaction([], [{"amount": amount, "address": address}])
    blockchain.add_transaction(tx)
    return jsonify({"message": "token minted", "txid": tx.txid})

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    nodes = request.json.get('nodes')
    if not nodes:
        return jsonify({'error': 'No nodes provided'}), 400
    for node in nodes:
        blockchain.nodes.add(node)
    return jsonify({'message': 'Nodes registered', 'total': list(blockchain.nodes)})

@app.route('/nodes/resolve')
def resolve():
    replaced = False
    max_len = len(blockchain.chain)
    for node in blockchain.nodes:
        try:
            r = requests.get(f"http://{node}/chain")
            if r.status_code == 200:
                data = r.json()
                if data['length'] > max_len:
                    blockchain.chain = [Block(**b) for b in data['chain']]
                    replaced = True
        except:
            continue
    return jsonify({'message': 'Chain replaced' if replaced else 'Chain is authoritative'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
