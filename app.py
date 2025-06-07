from flask import Flask, jsonify, request, render_template
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import json
from time import time
import random
import requests
import os

app = Flask(__name__)

# ====== Constants for Tokenomics ======
MAX_SUPPLY = 1_000_000  # max total tokens supply
INITIAL_REWARD = 50     # initial mining reward tokens
HALVING_INTERVAL = 10   # blocks after which reward halves
DIFFICULTY_TARGET = 15  # target seconds per block (for difficulty adjustment)

# ====== Wallet Class =======
class Wallet:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.public_key = self.private_key.public_key()

    def get_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

    def get_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def sign_transaction(self, transaction):
        transaction_json = json.dumps(transaction, sort_keys=True).encode()
        signature = self.private_key.sign(
            transaction_json,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature.hex()

    def verify_transaction(self, transaction, signature):
        transaction_json = json.dumps(transaction, sort_keys=True).encode()
        try:
            self.public_key.verify(
                bytes.fromhex(signature),
                transaction_json,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# ===== Blockchain Class =====
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.balances = {}
        self.mined_rewards = {}      # Track total rewards mined per wallet
        self.difficulty = 4          # initial difficulty (number of leading zeros)
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'difficulty': self.difficulty,
        }

        # Apply transactions to balances
        for tx in self.current_transactions:
            sender = tx['sender']
            recipient = tx['recipient']
            amount = tx['amount']
            fee = tx.get('fee', 0)

            # Deduct amount + fee from sender, add to recipient, fee goes to miner
            if sender != "0":
                self.balances[sender] -= (amount + fee)
            self.balances[recipient] = self.balances.get(recipient, 0) + amount

        # Reset current transactions
        self.current_transactions = []
        self.chain.append(block)

        # Difficulty adjustment every HALVING_INTERVAL blocks
        if len(self.chain) % HALVING_INTERVAL == 0 and len(self.chain) > 1:
            self.adjust_difficulty()

        return block

    def new_transaction(self, sender, recipient, amount, signature, fee=0):
        # Validate transaction inputs
        if amount <= 0 or sender not in wallets or recipient not in wallets:
            return False, 'Invalid sender or recipient or amount'

        total_amount = amount + fee

        if self.balances.get(sender, 0) < total_amount:
            return False, 'Insufficient balance'

        transaction = {'sender': sender, 'recipient': recipient, 'amount': amount, 'fee': fee}
        if not wallets[sender].verify_transaction(transaction, signature):
            return False, 'Invalid signature'

        self.current_transactions.append(transaction)
        return True, self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        # SHA256 hash of block JSON
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        prefix = '0' * self.difficulty
        while True:
            guess = f'{last_proof}{proof}'.encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            if guess_hash.startswith(prefix):
                return proof
            proof += 1

    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        prefix = '0' * self.difficulty
        return guess_hash.startswith(prefix)

    def adjust_difficulty(self):
        # Adjust difficulty based on block times
        if len(self.chain) < HALVING_INTERVAL + 1:
            return
        latest_block = self.chain[-1]
        prev_adjust_block = self.chain[-(HALVING_INTERVAL + 1)]
        time_taken = latest_block['timestamp'] - prev_adjust_block['timestamp']

        expected_time = HALVING_INTERVAL * DIFFICULTY_TARGET
        if time_taken < expected_time / 2:
            self.difficulty += 1
        elif time_taken > expected_time * 2 and self.difficulty > 1:
            self.difficulty -= 1

    def get_mining_reward(self):
        halvings = len(self.chain) // HALVING_INTERVAL
        reward = INITIAL_REWARD // (2 ** halvings)
        return max(reward, 1)

    def register_node(self, address):
        self.nodes.add(address)

    def resolve_conflicts(self):
        new_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except Exception as e:
                print(f'Error contacting node {node}: {e}')

        if new_chain:
            self.chain = new_chain
            return True
        return False

    def valid_chain(self, chain):
        for i in range(1, len(chain)):
            if chain[i]['previous_hash'] != self.hash(chain[i - 1]):
                return False
            if not self.valid_proof(chain[i - 1]['proof'], chain[i]['proof']):
                return False
        return True

# Global wallets and blockchain instance
wallets = {}
blockchain = Blockchain()

# ====== Routes ======

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')  # Create your frontend HTML accordingly

@app.route('/wallet/new', methods=['GET'])
def create_wallet():
    wallet = Wallet()
    public_key = wallet.get_public_key()
    wallets[public_key] = wallet
    blockchain.balances[public_key] = blockchain.balances.get(public_key, 100)  # Initial balance
    blockchain.mined_rewards[public_key] = 0
    return jsonify({'private_key': wallet.get_private_key(), 'public_key': public_key}), 200

@app.route('/wallet/balance/<public_key>', methods=['GET'])
def wallet_balance(public_key):
    balance = blockchain.balances.get(public_key)
    rewards = blockchain.mined_rewards.get(public_key, 0)
    if balance is None:
        return jsonify({'error': 'Wallet not found'}), 404
    return jsonify({'balance': balance, 'mined_rewards': rewards}), 200

@app.route('/wallet/transactions/<public_key>', methods=['GET'])
def wallet_transactions(public_key):
    txs = []
    for block in blockchain.chain:
        for tx in block['transactions']:
            if tx['sender'] == public_key or tx['recipient'] == public_key:
                txs.append({
                    'block': block['index'],
                    'sender': tx['sender'],
                    'recipient': tx['recipient'],
                    'amount': tx['amount'],
                    'fee': tx.get('fee', 0),
                    'timestamp': block['timestamp']
                })
    if not txs:
        return jsonify({'message': 'No transactions found'}), 404
    return jsonify(txs), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature']
    if not all(k in values for k in required):
        return jsonify({'error': 'Missing values'}), 400

    sender = values['sender']
    recipient = values['recipient']
    amount = values['amount']
    signature = values['signature']
    fee = values.get('fee', 0)

    success, result = blockchain.new_transaction(sender, recipient, amount, signature, fee)
    if success:
        return jsonify({'message': 'Transaction verified and added', 'block': result}), 201
    else:
        return jsonify({'error': result}), 400

@app.route('/mine', methods=['GET'])
def mine():
    # Select miner (here we pick first wallet if exists)
    if not wallets:
        return jsonify({'error': 'No wallets available for mining reward'}), 400
    miner_public_key = list(wallets.keys())[0]

    # Mining reward transaction (from "0" address)
    reward_amount = blockchain.get_mining_reward()
    reward_tx = {'sender': "0", 'recipient': miner_public_key, 'amount': reward_amount, 'fee': 0}
    blockchain.current_transactions.append(reward_tx)

    # Proof of work
    last_proof = blockchain.last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    # Create new block
    block = blockchain.new_block(proof)

    # Track rewards mined
    blockchain.balances[miner_public_key] = blockchain.balances.get(miner_public_key, 0) + reward_amount
    blockchain.mined_rewards[miner_public_key] = blockchain.mined_rewards.get(miner_public_key, 0) + reward_amount

    return jsonify({
        'message': 'New Block Forged',
        'index': block['index'],
        'mining_reward': reward_amount,
        'difficulty': blockchain.difficulty,
        'balance': blockchain.balances[miner_public_key]
    }), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'balances': blockchain.balances, 'length': len(blockchain.chain), 'difficulty': blockchain.difficulty}), 200

@app.route('/block/<int:index>', methods=['GET'])
def get_block(index):
    if 0 < index <= len(blockchain.chain):
        block = blockchain.chain[index - 1]
        return jsonify(block), 200
    return jsonify({'error': 'Block not found'}), 404

@app.route('/block/hash/<block_hash>', methods=['GET'])
def get_block_by_hash(block_hash):
    for block in blockchain.chain:
        if blockchain.hash(block) == block_hash:
            return jsonify(block), 200
    return jsonify({'error': 'Block not found'}), 404

@app.route('/transactions/<public_key>', methods=['GET'])
def get_transactions(public_key):
    txs = []
    for block in blockchain.chain:
        for tx in block['transactions']:
            if tx['sender'] == public_key or tx['recipient'] == public_key:
                txs.append({
                    'block': block['index'],
                    'sender': tx['sender'],
                    'recipient': tx['recipient'],
                    'amount': tx['amount'],
                    'fee': tx.get('fee', 0),
                    'timestamp': block['timestamp']
                })
    if not txs:
        return jsonify({'message': 'No transactions found'}), 404
    return jsonify(txs), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    if 'nodes' not in values:
        return jsonify({'error': 'Missing node list'}), 400
    for node in values['nodes']:
        blockchain.register_node(node)
    return jsonify({'message': 'Nodes added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Our chain was replaced', 'new_chain': blockchain.chain}), 200
    return jsonify({'message': 'Our chain is authoritative', 'chain': blockchain.chain}), 200

# Run app
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
