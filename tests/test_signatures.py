import hashlib
import unittest

from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import hashes

from app import Blockchain, Transaction, Wallet, signature_message


def sign_input(private_key, tx):
    digest = hashlib.sha256(signature_message(tx)).digest()
    signature = private_key.sign(digest, ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
    return signature.hex()


class TransactionSignatureTests(unittest.TestCase):
    def setUp(self):
        self.blockchain = Blockchain()
        self.blockchain.utxos = {}

    def test_valid_transaction_signature(self):
        sender = Wallet()
        recipient = Wallet()
        txid = "a" * 64
        utxo_key = f"{txid}:0"
        self.blockchain.utxos[utxo_key] = {"amount": 10, "address": sender.get_address()}

        vin = [{
            "txid": txid,
            "vout": 0,
            "signature": "",
            "pubkey": sender.serialize_public_key().hex()
        }]
        vout = [{"amount": 5, "address": recipient.get_address()}]
        tx = Transaction(vin, vout)
        signature = sign_input(sender.private_key, tx)
        tx.vin[0]["signature"] = signature
        tx.txid = tx.calculate_txid()

        is_valid, error = self.blockchain.validate_transaction(tx)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_invalid_transaction_signature(self):
        sender = Wallet()
        recipient = Wallet()
        attacker = Wallet()
        txid = "b" * 64
        utxo_key = f"{txid}:0"
        self.blockchain.utxos[utxo_key] = {"amount": 10, "address": sender.get_address()}

        vin = [{
            "txid": txid,
            "vout": 0,
            "signature": "",
            "pubkey": sender.serialize_public_key().hex()
        }]
        vout = [{"amount": 4, "address": recipient.get_address()}]
        tx = Transaction(vin, vout)
        signature = sign_input(attacker.private_key, tx)
        tx.vin[0]["signature"] = signature
        tx.txid = tx.calculate_txid()

        is_valid, error = self.blockchain.validate_transaction(tx)
        self.assertFalse(is_valid)
        self.assertEqual(error, "invalid signature")


if __name__ == "__main__":
    unittest.main()
