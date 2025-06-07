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

MAX_SUPPLY = 21000000  # Max tokens (like Bitcoin)
BLOCK_REWARD_INITIAL = 50
HALVING_INTERVAL = 10  # Number of blocks per halving

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

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()
        self.balances = {}
        self.total_mined = 0  # Total tokens mined so far
        self.new_block(previous_hash='1', proof=100)

    def current_block_reward(self):
        halvings = len(self.chain) // HALVING_INTERVAL
        reward = BLOCK_REWARD_INITIAL // (2 ** halvings)
        return max(reward, 0)

    def new_block(self, proof, previous_hash=None):
        block_reward = self.current_block_reward()

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions.copy(),
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
            'reward': block_reward,
        }

        # Apply transaction amounts to balances
        for tx in self.current_transactions:
            sender = tx['sender']
            recipient = tx['recipient']
            amount = tx['amount']

            if sender != "0":  # normal tx
                self.balances[sender] -= amount
            self.balances[recipient] = self.balances.get(recipient, 0) + amount

        # Add mining reward if supply allows
        if self.total_mined + block_reward <= MAX_SUPPLY and block_reward > 0:
            miner = self.miner_address if hasattr(self, 'miner_address') else None
            if miner:
                self.balances[miner] = self.balances.get(miner, 0) + block_reward
                self.total_mined += block_reward
                block['reward_to'] = miner
            else:
                block['reward_to'] = None
        else:
            block['reward'] = 0
            block['reward_to'] = None

        self.current_transactions = []
        self.chain.append(block)
        self.miner_address = None  # reset miner address after block created
        return block

    def new_transaction(self, sender, recipient, amount, signature):
        if amount <= 0 or sender not in wallets:
            return False

        if self.balances.get(sender, 0) < amount:
            return False

        transaction = {'sender': sender, 'recipient': recipient, 'amount': amount}
        if not wallets[sender].verify_transaction(transaction, signature):
            return False

        self.current_transactions.append(transaction)
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        return hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

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
        return True

wallets = {}
blockchain = Blockchain()

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/wallet/new', methods=['GET'])
def create_wallet():
    wallet = Wallet()
    public_key = wallet.get_public_key()
    wallets[public_key] = wallet
    # Start wallet with some initial balance to trade (optional, e.g., 100 tokens)
    blockchain.balances[public_key] = blockchain.balances.get(public_key, 0) + 100
    return jsonify({'private_key': wallet.get_private_key(), 'public_key': public_key}), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature']
    if not values or not all(k in values for k in required):
        return jsonify({'error': 'Missing values'}), 400

    sender = values['sender']
    recipient = values['recipient']
    amount = values['amount']
    signature = values['signature']

    if blockchain.new_transaction(sender, recipient, amount, signature):
        return jsonify({'message': 'Transaction verified and added'}), 201
    else:
        return jsonify({'error': 'Invalid transaction or insufficient balance'}), 400

@app.route('/mine', methods=['POST'])
def mine():
    data = request.get_json()
    miner_address = data.get('miner_address') if data else None

    if not miner_address or miner_address not in wallets:
        return jsonify({'error': 'Miner address missing or invalid'}), 400

    blockchain.miner_address = miner_address

    last_proof = blockchain.last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    block = blockchain.new_block(proof)

    return jsonify({
        'message': 'New Block Forged',
        'index': block['index'],
        'transactions': block['transactions'],
        'reward': block['reward'],
        'reward_to': block['reward_to'],
        'total_mined': blockchain.total_mined,
        'balances': blockchain.balances
    }), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'balances': blockchain.balances, 'length': len(blockchain.chain)}), 200

@app.route('/block/<int:index>', methods=['GET'])
def get_block(index):
    if 0 < index <= len(blockchain.chain):
        block = blockchain.chain[index - 1]
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
                    'timestamp': block['timestamp']
                })
    if not txs:
        return jsonify({'message': 'No transactions found'}), 404
    return jsonify(txs), 200

@app.route('/balance/<public_key>', methods=['GET'])
def get_balance(public_key):
    balance = blockchain.balances.get(public_key, 0)
    return jsonify({'public_key': public_key, 'balance': balance}), 200

@app.route('/wallets', methods=['GET'])
def get_wallets():
    return jsonify({'wallets': list(wallets.keys())}), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    if not values or 'nodes' not in values:
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

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
