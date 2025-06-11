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

app = Flask(__name__)

# Constants
MAX_SUPPLY = 21_000_000  # Max coins
REWARD_INITIAL = 50  # Starting block reward (coins)
HALVING_INTERVAL = 210000  # Blocks per halving
DIFFICULTY_ADJUST_INTERVAL = 2016  # Blocks for difficulty adjust
TARGET_BLOCK_TIME = 10 * 60  # 10 minutes target in seconds

# -----------------
# Helper Functions
# -----------------

def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def hash_to_hex(b: bytes) -> str:
    return b[::-1].hex()  # Reverse for display (Bitcoin style)

def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def base58check_decode(s: str) -> bytes:
    b = base58.b58decode(s)
    payload, checksum = b[:-4], b[-4:]
    calc_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != calc_checksum:
        raise ValueError("Invalid checksum")
    return payload

def public_key_to_address(pubkey_bytes: bytes) -> str:
    # SHA256 then RIPEMD160
    sha = hashlib.sha256(pubkey_bytes).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    # Prepend version byte (0x00 for mainnet)
    versioned_payload = b'\x00' + ripe
    return base58check_encode(versioned_payload)

# -----------------
# Wallet System
# -----------------

class Wallet:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256K1())
        self.public_key = self.private_key.public_key()

    def serialize_private_key(self) -> str:
        # PEM format, no encryption (can add password)
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def serialize_public_key(self) -> bytes:
        # Compressed public key (33 bytes)
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        return pub_bytes

    def get_address(self) -> str:
        return public_key_to_address(self.serialize_public_key())

    def sign(self, msg: bytes) -> bytes:
        signature = self.private_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify(self, signature: bytes, msg: bytes) -> bool:
        try:
            self.public_key.verify(signature, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

wallets = {}  # address => Wallet instance (only for demo; in reality private keys never stored on server)
balances = {}  # address => coin balance (derived from UTXO set)
utxos = {}  # txid:vout => {'address':..., 'amount':...}

# -----------------
# Transaction Model (UTXO)
# -----------------

class TransactionInput:
    def __init__(self, txid: str, vout: int, signature: str = None, pubkey: str = None):
        self.txid = txid
        self.vout = vout
        self.signature = signature
        self.pubkey = pubkey

    def to_dict(self):
        return {
            "txid": self.txid,
            "vout": self.vout,
            "signature": self.signature,
            "pubkey": self.pubkey
        }

class TransactionOutput:
    def __init__(self, amount: float, address: str):
        self.amount = amount
        self.address = address

    def to_dict(self):
        return {
            "amount": self.amount,
            "address": self.address
        }

class Transaction:
    def __init__(self, vin: list, vout: list, timestamp=None):
        self.vin = vin  # list of TransactionInput
        self.vout = vout  # list of TransactionOutput
        self.timestamp = timestamp or int(time.time())
        self.txid = self.calculate_txid()

    def to_dict(self):
        return {
            "vin": [i.to_dict() for i in self.vin],
            "vout": [o.to_dict() for o in self.vout],
            "timestamp": self.timestamp,
            "txid": self.txid
        }

    def calculate_txid(self) -> str:
        tx_content = json.dumps({
            "vin": [i.to_dict() for i in self.vin],
            "vout": [o.to_dict() for o in self.vout],
            "timestamp": self.timestamp
        }, sort_keys=True).encode()
        return hashlib.sha256(tx_content).hexdigest()

# -----------------
# Block Model with Merkle Tree
# -----------------

def merkle_root(txids):
    if len(txids) == 0:
        return ''
    if len(txids) == 1:
        return txids[0]

    new_level = []
    for i in range(0, len(txids), 2):
        left = txids[i]
        right = txids[i+1] if i+1 < len(txids) else left
        new_hash = hashlib.sha256((left + right).encode()).hexdigest()
        new_level.append(new_hash)
    return merkle_root(new_level)

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
        header = (str(self.index) + self.previous_hash + self.merkle_root +
                  str(self.timestamp) + str(self.nonce) + str(self.difficulty))
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

# -----------------
# Blockchain and Mining
# -----------------

class Blockchain:
    def __init__(self):
        self.chain = []
        self.difficulty = 4  # Initial difficulty (number of leading zeros)
        self.mempool = []  # List of pending Transaction objects
        self.utxos = {}  # key = txid:vout index, value = {'address':..., 'amount':...}
        self.block_time_log = []  # For difficulty adjustment

        # Genesis block
        genesis_tx = Transaction(vin=[], vout=[TransactionOutput(REWARD_INITIAL, "genesis")])
        self.utxos[f"{genesis_tx.txid}:0"] = {'address': "genesis", 'amount': REWARD_INITIAL}
        genesis_block = Block(0, "0" * 64, [genesis_tx], self.difficulty, nonce=0)
        self.chain.append(genesis_block)
        self.block_time_log.append(genesis_block.timestamp)

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, tx: Transaction) -> bool:
        # Validate transaction inputs (all UTXOs exist and signatures valid)
        if not self.validate_transaction(tx):
            return False
        self.mempool.append(tx)
        return True

    def validate_transaction(self, tx: Transaction) -> bool:
        total_in = 0
        total_out = 0
        for txin in tx.vin:
            key = f"{txin.txid}:{txin.vout}"
            if key not in self.utxos:
                print(f"Invalid input UTXO {key} not found")
                return False
            utxo = self.utxos[key]

            # Verify signature
            if not txin.signature or not txin.pubkey:
                print("Missing signature or pubkey")
                return False
            pubkey_bytes = base58.b58decode(txin.pubkey)
            # Rebuild public key object
            try:
                public_key = serialization.load_der_public_key(pubkey_bytes)
            except Exception:
                # Fallback to compressed point
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pubkey_bytes)
            # Construct message to verify (simplify: txid + vout)
            msg = f"{txin.txid}:{txin.vout}".encode()

            try:
                public_key.verify(base58.b58decode(txin.signature), msg, ec.ECDSA(hashes.SHA256()))
            except Exception as e:
                print(f"Signature invalid: {e}")
                return False

            total_in += utxo['amount']

        for txout in tx.vout:
            total_out += txout.amount

        # Check total output <= total input (allow fee if less)
        if total_out > total_in:
            print("Output exceeds input")
            return False

        return True

    def mine_block(self, miner_address):
        # Construct coinbase tx for reward + fees
        reward = self.get_block_reward()
        fee_total = 0
        for tx in self.mempool:
            # Calculate fee = input sum - output sum
            in_sum = 0
            out_sum = 0
            for vin in tx.vin:
                key = f"{vin.txid}:{vin.vout}"
                in_sum += self.utxos.get(key, {'amount':0})['amount']
            for vout in tx.vout:
                out_sum += vout.amount
            fee_total += (in_sum - out_sum)

        coinbase_tx = Transaction(vin=[], vout=[TransactionOutput(reward + fee_total, miner_address)])

        block_txs = [coinbase_tx] + self.mempool.copy()

        last_block = self.get_latest_block()
        new_block = Block(
            index=last_block.index + 1,
            previous_hash=last_block.hash,
            transactions=block_txs,
            difficulty=self.difficulty,
            nonce=0
        )

        # Proof-of-Work loop
        target = "0" * self.difficulty
        while not new_block.hash.startswith(target):
            new_block.nonce += 1
            new_block.timestamp = int(time.time())
            new_block.hash = new_block.calculate_hash()

        # Add block to chain
        self.chain.append(new_block)
        self.block_time_log.append(new_block.timestamp)
        if len(self.block_time_log) > DIFFICULTY_ADJUST_INTERVAL:
            self.block_time_log.pop(0)
            self.adjust_difficulty()

        # Update UTXO set
        self.update_utxos(new_block)

        # Clear mempool
        self.mempool.clear()

        return new_block

    def get_block_reward(self):
        halvings = len(self.chain) // HALVING_INTERVAL
        reward = REWARD_INITIAL >> halvings  # divide by 2^halvings
        return max(reward, 0)

    def update_utxos(self, block):
        # Remove spent UTXOs, add new ones
        for tx in block.transactions:
            # Remove inputs
            for txin in tx.vin:
                key = f"{txin.txid}:{txin.vout}"
                if key in self.utxos:
                    del self.utxos[key]
            # Add outputs
            for i, txout in enumerate(tx.vout):
                key = f"{tx.txid}:{i}"
                self.utxos[key] = {'address': txout.address, 'amount': txout.amount}

    def adjust_difficulty(self):
        # Adjust difficulty based on time taken for last DIFFICULTY_ADJUST_INTERVAL blocks
        if len(self.chain) < DIFFICULTY_ADJUST_INTERVAL + 1:
            return
        time_expected = TARGET_BLOCK_TIME * DIFFICULTY_ADJUST_INTERVAL
        time_taken = self.block_time_log[-1] - self.block_time_log[0]
        if time_taken < time_expected / 2:
            self.difficulty += 1
        elif time_taken > time_expected * 2 and self.difficulty > 1:
            self.difficulty -= 1

    def get_balance(self, address: str) -> float:
        # Sum UTXOs for address
        total = 0
        for utxo in self.utxos.values():
            if utxo['address'] == address:
                total += utxo['amount']
        return total

# Instantiate blockchain
blockchain = Blockchain()

# -----------------
# Flask Routes
# -----------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    wallet = Wallet()
    addr = wallet.get_address()
    wallets[addr] = wallet
    # Return PEM keys & address (private key string + compressed pubkey in base58)
    priv_key_str = wallet.serialize_private_key()
    pub_key_b58 = base58.b58encode(wallet.serialize_public_key()).decode()
    balance = blockchain.get_balance(addr)
    return jsonify({
        "address": addr,
        "private_key": priv_key_str,
        "public_key": pub_key_b58,
        "balance": balance
    })

@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    bal = blockchain.get_balance(address)
    return jsonify({"address": address, "balance": bal})

@app.route('/transaction/send', methods=['POST'])
def send_transaction():
    data = request.json
    # Expected: vin = [{txid, vout, signature, pubkey}], vout = [{amount, address}]
    vin = [TransactionInput(**inp) for inp in data.get('vin', [])]
    vout = [TransactionOutput(**outp) for outp in data.get('vout', [])]

    tx = Transaction(vin=vin, vout=vout)

    if blockchain.add_transaction(tx):
        return jsonify({"message": "Transaction added to mempool", "txid": tx.txid})
    else:
        return jsonify({"error": "Invalid transaction"}), 400

@app.route('/mine', methods=['POST'])
def mine():
    data = request.json
    miner_address = data.get('miner_address')
    if not miner_address or miner_address not in wallets:
        return jsonify({"error": "Miner address missing or invalid"}), 400
    block = blockchain.mine_block(miner_address)
    return jsonify({
        "message": f"Block #{block.index} mined with hash {block.hash}",
        "block": block.to_dict()
    })

@app.route('/chain', methods=['GET'])
def full_chain():
    chain_data = [block.to_dict() for block in blockchain.chain]
    circulating_supply = sum([blockchain.get_block_reward() for block in blockchain.chain])
    return jsonify({
        "length": len(blockchain.chain),
        "chain": chain_data,
        "difficulty": blockchain.difficulty,
        "circulating_supply": circulating_supply,
    })

@app.route('/block/<int:index>', methods=['GET'])
def get_block(index):
    if index < 0 or index >= len(blockchain.chain):
        return jsonify({"error": "Block not found"}), 404
    return jsonify(blockchain.chain[index].to_dict())

@app.route('/transactions/<address>', methods=['GET'])
def get_transactions_for_address(address):
    txs = []
    for block in blockchain.chain:
        for tx in block.transactions:
            for out in tx.vout:
                if out.address == address:
                    txs.append(tx.to_dict())
                    break
    return jsonify(txs)

# -----------------
# Run Flask App
# -----------------

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
