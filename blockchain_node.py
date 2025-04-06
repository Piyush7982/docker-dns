#!/usr/bin/env python3
import json
import hashlib
import time
import threading
import socket
import sys
import argparse
import os
from flask import Flask, request, jsonify
import requests
from web3 import Web3
from web3.middleware import geth_poa_middleware

app = Flask(__name__)


# Get the current node's IP address
def get_ip_address():
    try:
        # This gets the IP that can be reached externally
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # Fallback to localhost if no external IP
        return "127.0.0.1"


# Blockchain Node Class
class BlockchainNode:
    def __init__(self, node_id, is_validator=False, genesis_block=None):
        self.node_id = node_id
        self.is_validator = is_validator
        self.peers = set()
        self.chain = []
        self.pending_transactions = []
        self.dns_records = {}  # Local cache of DNS records
        self.ip_address = get_ip_address()

        print(f"Node initialized with ID: {self.node_id}")
        print(f"Node IP address: {self.ip_address}")

        # Create genesis block if not provided
        if genesis_block:
            self.chain.append(genesis_block)
        else:
            self.create_genesis_block()

        # Set up consensus (Proof of Authority)
        self.validators = set()
        if self.is_validator:
            self.validators.add(self.node_id)

    def create_genesis_block(self):
        """Creates the genesis block with default DNS entries"""
        genesis_block = {
            "index": 0,
            "timestamp": time.time(),
            "transactions": [],
            "previous_hash": "0",
            "validator": "genesis",
            "signature": "genesis_signature",
        }

        # Add hash to the genesis block
        genesis_block["hash"] = self.hash_block(genesis_block)
        self.chain.append(genesis_block)

    def hash_block(self, block):
        """Hashes a block using SHA-256"""
        # Remove the hash field if it exists to avoid including it in the hash calculation
        block_string = json.dumps(
            {k: v for k, v in block.items() if k != "hash"}, sort_keys=True
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def add_peer(self, peer_address):
        """Adds a peer node to the network"""
        own_address = f"http://{self.ip_address}:{args.port}"
        if peer_address not in self.peers and peer_address != own_address:
            self.peers.add(peer_address)
            print(f"Added peer: {peer_address}")
            return True
        return False

    def register_validator(self, validator_id):
        """Registers a validator node"""
        self.validators.add(validator_id)
        print(f"Registered validator: {validator_id}")

    def create_transaction(
        self, sender, action, domain_name, ip_address=None, new_owner=None
    ):
        """Creates a new DNS transaction"""
        transaction = {
            "sender": sender,
            "action": action,  # 'register', 'update', 'transfer', 'renew'
            "domain_name": domain_name,
            "ip_address": ip_address,
            "new_owner": new_owner,
            "timestamp": time.time(),
        }

        self.pending_transactions.append(transaction)

        # Broadcast transaction to peers
        self.broadcast_transaction(transaction)

        return transaction

    def broadcast_transaction(self, transaction):
        """Broadcasts a transaction to all peers"""
        for peer in self.peers:
            try:
                requests.post(f"{peer}/transactions/new", json=transaction)
            except requests.exceptions.RequestException as e:
                print(f"Error broadcasting to {peer}: {e}")

    def validate_transaction(self, transaction):
        """Validates a transaction based on DNS rules"""
        action = transaction.get("action")
        domain_name = transaction.get("domain_name")

        if not domain_name:
            return False

        # Check if the domain exists in our records
        domain_exists = domain_name in self.dns_records

        if action == "register":
            # For registration, domain should not exist
            return not domain_exists

        elif action in ["update", "transfer", "renew"]:
            # For other actions, domain should exist and sender should be the owner
            if not domain_exists:
                return False

            return transaction.get("sender") == self.dns_records[domain_name].get(
                "owner"
            )

        return False

    def create_new_block(self, validator, signature):
        """Creates a new block with pending transactions"""
        if not self.pending_transactions:
            return None

        previous_block = self.chain[-1]
        new_block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": self.pending_transactions.copy(),
            "previous_hash": previous_block["hash"],
            "validator": validator,
            "signature": signature,
        }

        # Add hash to the new block
        new_block["hash"] = self.hash_block(new_block)

        # Apply transactions to DNS records
        for transaction in new_block["transactions"]:
            self.apply_transaction(transaction)

        # Clear pending transactions
        self.pending_transactions = []

        return new_block

    def apply_transaction(self, transaction):
        """Applies a transaction to the local DNS records"""
        action = transaction.get("action")
        domain_name = transaction.get("domain_name")

        if action == "register":
            self.dns_records[domain_name] = {
                "owner": transaction.get("sender"),
                "ip_address": transaction.get("ip_address"),
                "registered_at": transaction.get("timestamp"),
                "expires_at": transaction.get("timestamp")
                + 31536000,  # 1 year in seconds
            }

        elif action == "update" and domain_name in self.dns_records:
            self.dns_records[domain_name]["ip_address"] = transaction.get("ip_address")

        elif action == "transfer" and domain_name in self.dns_records:
            self.dns_records[domain_name]["owner"] = transaction.get("new_owner")

        elif action == "renew" and domain_name in self.dns_records:
            self.dns_records[domain_name]["expires_at"] += 31536000  # Extend by 1 year

    def add_block_to_chain(self, block):
        """Adds a validated block to the blockchain"""
        # Validate block before adding
        if self.validate_block(block):
            self.chain.append(block)

            # Apply transactions to DNS records
            for transaction in block["transactions"]:
                self.apply_transaction(transaction)

            print(f"Added block {block['index']} to chain")
            return True
        return False

    def validate_block(self, block):
        """Validates a block before adding it to the chain"""
        # Check if the block is properly formed
        required_fields = [
            "index",
            "timestamp",
            "transactions",
            "previous_hash",
            "validator",
            "signature",
            "hash",
        ]
        if not all(field in block for field in required_fields):
            return False

        # Check if the block index is correct
        if block["index"] != len(self.chain):
            return False

        # Check if the previous hash matches the hash of the last block in the chain
        if block["previous_hash"] != self.chain[-1]["hash"]:
            return False

        # Check if the block hash is valid
        if self.hash_block(block) != block["hash"]:
            return False

        # In a real implementation, we would also check the validator's signature here

        return True

    def consensus(self):
        """Consensus algorithm to resolve conflicts in the blockchain"""
        longest_chain = None
        max_length = len(self.chain)

        # Check chains from all peers
        for peer in self.peers:
            try:
                response = requests.get(f"{peer}/chain")
                if response.status_code == 200:
                    chain = response.json().get("chain")
                    length = len(chain)

                    # Check if the chain is longer and valid
                    if length > max_length and self.validate_chain(chain):
                        max_length = length
                        longest_chain = chain
            except requests.exceptions.RequestException as e:
                print(f"Error communicating with {peer}: {e}")

        # Replace our chain if a longer valid chain is found
        if longest_chain:
            self.chain = longest_chain

            # Rebuild DNS records from the new chain
            self.rebuild_dns_records()

            print(f"Replaced chain with a longer valid chain of length {max_length}")
            return True

        return False

    def rebuild_dns_records(self):
        """Rebuilds DNS records from the blockchain"""
        self.dns_records = {}

        for block in self.chain:
            for transaction in block.get("transactions", []):
                self.apply_transaction(transaction)

    def validate_chain(self, chain):
        """Validates a blockchain"""
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            # Check if the hash of the block is correct
            if block["previous_hash"] != self.hash_block(last_block):
                return False

            # Check if the block hash is valid
            if self.hash_block(block) != block["hash"]:
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_domain(self, domain_name):
        """Resolves a domain name to an IP address"""
        if domain_name in self.dns_records:
            record = self.dns_records[domain_name]
            if record.get("expires_at", 0) > time.time():
                return record.get("ip_address")
        return None


# Flask routes
@app.route("/transactions/new", methods=["POST"])
def new_transaction():
    values = request.get_json()

    # Check if the transaction is valid
    if blockchain_node.validate_transaction(values):
        blockchain_node.pending_transactions.append(values)
        return (
            jsonify(
                {
                    "message": f"Transaction will be added to Block {len(blockchain_node.chain)}"
                }
            ),
            201,
        )

    return jsonify({"message": "Invalid transaction"}), 400


@app.route("/mine", methods=["GET"])
def mine():
    if not blockchain_node.is_validator:
        return jsonify({"message": "This node is not a validator"}), 403

    if not blockchain_node.pending_transactions:
        return jsonify({"message": "No pending transactions to mine"}), 200

    # Create a new block
    new_block = blockchain_node.create_new_block(
        validator=blockchain_node.node_id, signature="validator_signature"
    )

    if not new_block:
        return jsonify({"message": "Failed to create a new block"}), 500

    # Add the new block to the chain
    blockchain_node.chain.append(new_block)

    # Broadcast the new block to all peers
    for peer in blockchain_node.peers:
        try:
            requests.post(f"{peer}/blocks/new", json=new_block)
        except requests.exceptions.RequestException as e:
            print(f"Error broadcasting to {peer}: {e}")

    return (
        jsonify(
            {
                "message": "New block created",
                "index": new_block["index"],
                "transactions": new_block["transactions"],
                "hash": new_block["hash"],
            }
        ),
        200,
    )


@app.route("/blocks/new", methods=["POST"])
def receive_block():
    block = request.get_json()

    # Add the block to the chain if it's valid
    if blockchain_node.add_block_to_chain(block):
        return jsonify({"message": "Block added to the chain"}), 201

    return jsonify({"message": "Invalid block"}), 400


@app.route("/chain", methods=["GET"])
def full_chain():
    return (
        jsonify({"chain": blockchain_node.chain, "length": len(blockchain_node.chain)}),
        200,
    )


@app.route("/peers/register", methods=["POST"])
def register_peer():
    values = request.get_json()
    peer = values.get("peer")

    if peer:
        if blockchain_node.add_peer(peer):
            return jsonify({"message": f"Peer {peer} registered successfully"}), 201
        else:
            return jsonify({"message": f"Peer {peer} already registered"}), 200

    return jsonify({"message": "Invalid peer address"}), 400


@app.route("/peers", methods=["GET"])
def get_peers():
    return jsonify({"peers": list(blockchain_node.peers)}), 200


@app.route("/validators/register", methods=["POST"])
def register_validator_route():
    values = request.get_json()
    validator_id = values.get("validator_id")

    if validator_id:
        blockchain_node.register_validator(validator_id)
        return (
            jsonify({"message": f"Validator {validator_id} registered successfully"}),
            201,
        )

    return jsonify({"message": "Invalid validator ID"}), 400


@app.route("/dns/register", methods=["POST"])
def register_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")
    ip_address = values.get("ip_address")

    if sender and domain_name and ip_address:
        transaction = blockchain_node.create_transaction(
            sender=sender,
            action="register",
            domain_name=domain_name,
            ip_address=ip_address,
        )

        return (
            jsonify(
                {
                    "message": "Domain registration transaction created",
                    "transaction": transaction,
                }
            ),
            201,
        )

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/update", methods=["POST"])
def update_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")
    ip_address = values.get("ip_address")

    if sender and domain_name and ip_address:
        transaction = blockchain_node.create_transaction(
            sender=sender,
            action="update",
            domain_name=domain_name,
            ip_address=ip_address,
        )

        return (
            jsonify(
                {
                    "message": "Domain update transaction created",
                    "transaction": transaction,
                }
            ),
            201,
        )

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/transfer", methods=["POST"])
def transfer_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")
    new_owner = values.get("new_owner")

    if sender and domain_name and new_owner:
        transaction = blockchain_node.create_transaction(
            sender=sender,
            action="transfer",
            domain_name=domain_name,
            new_owner=new_owner,
        )

        return (
            jsonify(
                {
                    "message": "Domain transfer transaction created",
                    "transaction": transaction,
                }
            ),
            201,
        )

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/renew", methods=["POST"])
def renew_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")

    if sender and domain_name:
        transaction = blockchain_node.create_transaction(
            sender=sender, action="renew", domain_name=domain_name
        )

        return (
            jsonify(
                {
                    "message": "Domain renewal transaction created",
                    "transaction": transaction,
                }
            ),
            201,
        )

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/resolve/<domain_name>", methods=["GET"])
def resolve_domain(domain_name):
    ip_address = blockchain_node.resolve_domain(domain_name)

    if ip_address:
        return jsonify({"domain_name": domain_name, "ip_address": ip_address}), 200

    return jsonify({"message": f"Domain {domain_name} not found or expired"}), 404


@app.route("/dns/records", methods=["GET"])
def get_dns_records():
    return jsonify({"dns_records": blockchain_node.dns_records}), 200


@app.route("/node/status", methods=["GET"])
def node_status():
    return (
        jsonify(
            {
                "node_id": blockchain_node.node_id,
                "ip_address": blockchain_node.ip_address,
                "is_validator": blockchain_node.is_validator,
                "peers_count": len(blockchain_node.peers),
                "peers": list(blockchain_node.peers),
                "chain_length": len(blockchain_node.chain),
                "pending_transactions": len(blockchain_node.pending_transactions),
                "dns_records_count": len(blockchain_node.dns_records),
            }
        ),
        200,
    )


# Consensus mechanism - run periodically
def consensus_task():
    while True:
        blockchain_node.consensus()
        time.sleep(10)  # Run consensus every 10 seconds


# Validator mining - run periodically
def mining_task():
    while True:
        if blockchain_node.is_validator and blockchain_node.pending_transactions:
            # Use the current node's IP instead of localhost
            node_url = f"http://{blockchain_node.ip_address}:{args.port}"
            try:
                requests.get(f"{node_url}/mine")
            except requests.exceptions.RequestException as e:
                print(f"Error mining: {e}")
        time.sleep(5)  # Check for pending transactions every 5 seconds


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blockchain Node")
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to run the node on"
    )
    parser.add_argument(
        "--validator", action="store_true", help="Run as a validator node"
    )
    parser.add_argument("--id", type=str, default=None, help="Node ID")
    args = parser.parse_args()

    # Generate a node ID if not provided
    node_id = args.id if args.id else f"node_{args.port}"

    # Create the blockchain node
    blockchain_node = BlockchainNode(node_id=node_id, is_validator=args.validator)

    # Start consensus and mining threads
    consensus_thread = threading.Thread(target=consensus_task)
    consensus_thread.daemon = True
    consensus_thread.start()

    if args.validator:
        mining_thread = threading.Thread(target=mining_task)
        mining_thread.daemon = True
        mining_thread.start()

    # Run the Flask app
    app.run(host="0.0.0.0", port=args.port)
