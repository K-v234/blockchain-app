# ShadowChain V4+ CORE (Real Coin Version)
# Full UTXO-based Blockchain Engine w/ Wallets, Mining, TX, QR, Tokenomics

from flask import Flask, jsonify, request, render_template, send_file
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import serialization, hashes
import hashlib, base58, json, time, io, qrcode, os
from collections import defaultdict

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# === CONFIG ===
CHAIN_FILE = "chain.json"
UTXO_FILE = "utxos.json"
MAX_SUPPLY = 21_000_000
INITIAL_REWARD = 50
HALVING_INTERVAL = 100

# === WALLET ===
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
        return pubkey_to_address(self.serialize_public_key())

wallets = {}

def pubkey_to_address(pubkey_bytes):
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    payload = b'\x00' + ripe
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def signature_message(tx):
    sanitized_vin = [{"txid": vin["txid"], "vout": vin["vout"]} for vin in tx.vin]
    payload = {
        "vin": sanitized_vin,
        "vout": tx.vout,
        "timestamp": tx.timestamp
    }
    return json.dumps(payload, sort_keys=True).encode()

def verify_utxo_signature(tx, vin, utxo):
    try:
        signature = bytes.fromhex(vin['signature'])
        pubkey_bytes = bytes.fromhex(vin['pubkey'])
        if pubkey_to_address(pubkey_bytes) != utxo['address']:
            return False
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey_bytes)
        digest = hashlib.sha256(signature_message(tx)).digest()
        public_key.verify(signature, digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
        return True
    except Exception:
        return False

# === TX ===
class Transaction:
    def __init__(self, vin, vout):
        self.vin = vin  # list of {txid, vout, signature, pubkey}
        self.vout = vout  # list of {amount, address}
        self.timestamp = int(time.time())
        self.txid = self.calculate_txid()

    def calculate_txid(self):
        content = json.dumps(self.to_dict(include_txid=False), sort_keys=True).encode()
        return hashlib.sha256(content).hexdigest()

    def to_dict(self, include_txid=True):
        d = {"vin": self.vin, "vout": self.vout, "timestamp": self.timestamp}
        if include_txid:
            d["txid"] = self.txid
        return d

    @staticmethod
    def from_dict(data):
        tx = Transaction(data['vin'], data['vout'])
        tx.timestamp = data['timestamp']
        tx.txid = data.get('txid', tx.calculate_txid())
        return tx

# === BLOCK ===
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

    @staticmethod
    def from_dict(data):
        transactions = [Transaction.from_dict(tx) for tx in data['transactions']]
        block = Block(data['index'], data['previous_hash'], transactions, data['difficulty'])
        block.timestamp = data['timestamp']
        block.nonce = data['nonce']
        block.hash = data.get('hash', block.compute_hash())
        return block

# === BLOCKCHAIN CORE ===
class Blockchain:
    def __init__(self):
        self.chain = []
        self.utxos = {}
        self.difficulty = 4
        self.mempool = []
        self.load()

    def load(self):
        if os.path.exists(CHAIN_FILE):
            with open(CHAIN_FILE) as f:
                self.chain = [Block.from_dict(b) for b in json.load(f)]
        else:
            self.create_genesis()

        if os.path.exists(UTXO_FILE):
            with open(UTXO_FILE) as f:
                self.utxos = json.load(f)

    def save(self):
        with open(CHAIN_FILE, 'w') as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2)
        with open(UTXO_FILE, 'w') as f:
            json.dump(self.utxos, f, indent=2)

    def create_genesis(self):
        tx = Transaction([], [{"amount": INITIAL_REWARD, "address": "genesis"}])
        block = Block(0, "0"*64, [tx], self.difficulty)
        self.chain.append(block)
        self.update_utxos(block)
        self.save()

    def get_last_block(self):
        return self.chain[-1]

    def get_reward(self):
        return max(INITIAL_REWARD >> (len(self.chain) // HALVING_INTERVAL), 1)

    def update_utxos(self, block):
        for tx in block.transactions:
            for vin in tx.vin:
                key = f"{vin['txid']}:{vin['vout']}"
                self.utxos.pop(key, None)
            for i, out in enumerate(tx.vout):
                self.utxos[f"{tx.txid}:{i}"] = {"amount": out['amount'], "address": out['address']}

    def validate_transaction(self, tx):
        if not tx.vin:
            return False, "transaction has no inputs"
        seen_inputs = set()
        for vin in tx.vin:
            if not all(k in vin for k in ("txid", "vout", "signature", "pubkey")):
                return False, "missing signature data"
            utxo_key = f"{vin['txid']}:{vin['vout']}"
            if utxo_key in seen_inputs:
                return False, "duplicate input"
            seen_inputs.add(utxo_key)
            utxo = self.utxos.get(utxo_key)
            if not utxo:
                return False, "referenced utxo not found"
            if not verify_utxo_signature(tx, vin, utxo):
                return False, "invalid signature"
        return True, None

    def mine_block(self, miner_addr):
        reward = self.get_reward()
        coinbase = Transaction([], [{"amount": reward, "address": miner_addr}])
        block = Block(
            len(self.chain),
            self.get_last_block().hash,
            [coinbase] + self.mempool[:5],
            self.difficulty
        )
        while not block.hash.startswith("0" * self.difficulty):
            block.nonce += 1
            block.hash = block.compute_hash()
        self.chain.append(block)
        self.update_utxos(block)
        self.mempool.clear()
        self.save()
        return block

blockchain = Blockchain()

# === ROUTES ===
@app.route('/')
def home(): return render_template("index.html")

@app.route('/wallet/new')
def wallet():
    w = Wallet()
    addr = w.get_address()
    wallets[addr] = w
    return jsonify({"address": addr, "private_key": w.serialize_private_key()})

@app.route('/wallet/key/<address>')
def wallet_key(address):
    if address not in wallets: return jsonify({"error": "not found"}), 404
    return send_file(io.BytesIO(wallets[address].serialize_private_key().encode()), download_name=f"{address}_key.txt", as_attachment=True)

@app.route('/wallet/qr/<address>')
def wallet_qr(address):
    img = qrcode.make(address)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/balance/<addr>')
def balance(addr):
    bal = sum(utxo['amount'] for utxo in blockchain.utxos.values() if utxo['address'] == addr)
    return jsonify({"balance": round(bal, 4)})

@app.route('/utxos/<addr>')
def utxo_list(addr):
    return jsonify([
        {"txid": k.split(":")[0], "vout": int(k.split(":")[1]), **v}
        for k, v in blockchain.utxos.items() if v['address'] == addr
    ])

@app.route('/transaction/send', methods=['POST'])
def send():
    tx = Transaction.from_dict(request.json)
    is_valid, error = blockchain.validate_transaction(tx)
    if not is_valid:
        return jsonify({"error": error}), 400
    blockchain.mempool.append(tx)
    return jsonify({"message": "tx added", "txid": tx.txid})

@app.route('/mine', methods=['POST'])
def mine():
    data = request.json
    block = blockchain.mine_block(data['miner_address'])
    socketio.emit("new_block", block.to_dict())
    return jsonify({"message": f"block {block.index} mined", "block": block.to_dict()})

@app.route('/chain')
def chain():
    return jsonify({"length": len(blockchain.chain), "chain": [b.to_dict() for b in blockchain.chain]})

@app.route('/tx/<txid>')
def tx_view(txid):
    for b in blockchain.chain:
        for tx in b.transactions:
            if tx.txid == txid:
                return jsonify(tx.to_dict())
    return jsonify({"error": "tx not found"})

@app.route('/block/hash/<hash>')
def block_view(hash):
    for b in blockchain.chain:
        if b.hash == hash:
            return jsonify(b.to_dict())
    return jsonify({"error": "block not found"})

@app.route('/leaderboard')
def leaderboard():
    scores = defaultdict(float)
    for b in blockchain.chain:
        for tx in b.transactions:
            for vout in tx.vout:
                scores[vout['address']] += vout['amount']
    return jsonify(sorted(scores.items(), key=lambda x: -x[1]))

@app.route('/tokenomics')
def tokenomics():
    total = sum(v['amount'] for v in blockchain.utxos.values())
    mined = sum(tx.vout[0]['amount'] for b in blockchain.chain for tx in b.transactions if tx.vout and tx.vout[0]['address'] == 'genesis')
    return jsonify({
        "total_mined": mined,
        "remaining": MAX_SUPPLY - mined,
        "reward": blockchain.get_reward(),
        "height": len(blockchain.chain)
    })

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=10000, allow_unsafe_werkzeug=True)
