from flask import Flask, jsonify, request, render_template
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import hashlib
import json
from time import time
import random
import requests

app = Flask(__name__)

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
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Apply transaction amounts to balances
        for tx in self.current_transactions:
            sender = tx['sender']
            recipient = tx['recipient']
            amount = tx['amount']

            if sender != "0":
                self.balances[sender] -= amount
            self.balances[recipient] = self.balances.get(recipient, 0) + amount

        self.current_transactions = []
        self.chain.append(block)
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
    blockchain.balances[public_key] = 100
    return jsonify({'private_key': wallet.get_private_key(), 'public_key': public_key}), 200

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

    if blockchain.new_transaction(sender, recipient, amount, signature):
        return jsonify({'message': 'Transaction verified and added'}), 201
    else:
        return jsonify({'error': 'Invalid transaction or insufficient balance'}), 400

@app.route('/mine', methods=['GET'])
def mine():
    # Simulate a reward
    reward_recipient = list(wallets.keys())[0] if wallets else "0"
    reward_tx = {'sender': "0", 'recipient': reward_recipient, 'amount': 10}
    blockchain.current_transactions.append(reward_tx)

    last_proof = blockchain.last_block['proof']
    proof = blockchain.proof_of_work(last_proof)
    block = blockchain.new_block(proof)

    return jsonify({'message': 'New Block Forged', 'index': block['index']}), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    return jsonify({'chain': blockchain.chain, 'balances': blockchain.balances, 'length': len(blockchain.chain)}), 200

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

import os
port = int(os.environ.get("PORT", 5000))
app.run(debug=True, host='0.0.0.0', port=port)

