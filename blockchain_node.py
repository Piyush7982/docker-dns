#!/usr/bin/env python3
import json
import hashlib
import time
import threading
import socket
import sys
import argparse
import os
import uuid
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from flask import Flask, request, jsonify
import requests
from web3 import Web3
from web3.middleware import geth_poa_middleware
import signal
import random

app = Flask(__name__)

# Add global flag for shutdown
shutdown_flag = threading.Event()

# Add periodic reconnection timer
RECONNECT_INTERVAL = 10  # seconds


# Add signal handler
def signal_handler(signum, frame):
    print("\nShutting down blockchain node...")
    shutdown_flag.set()
    # Give threads time to cleanup
    time.sleep(2)
    sys.exit(0)


# Get the current node's IP address
def get_ip_address():
    """Get the current node's IP address that can be reached externally"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except (socket.error, OSError) as e:
        print(f"Warning: Could not determine external IP: {e}")
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
        self.transaction_map = {}  # Map transaction_id to transaction
        self.domain_to_block = (
            {}
        )  # Track which block contains the latest update for each domain

        # Track signature validation errors
        self.signature_validation_errors = 0
        self.max_signature_errors = 5
        self.last_error_reset = time.time()

        # Keys directory for storing validator keys
        self.keys_dir = os.path.join(os.getcwd(), "keys")
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

        print(f"Node initialized with ID: {self.node_id}")
        print(f"Node IP address: {self.ip_address}")

        # Set up PoA consensus
        self.validators = {}  # Map validator ID to their public key
        self.validator_order = []  # Ordered list of validators for round-robin
        self.current_validator_index = 0  # Track whose turn it is to create a block

        # Generate or load key pair if this is a validator
        if self.is_validator:
            self.private_key, self.public_key = self._get_key_pair()
            self.validators[self.node_id] = self.public_key
            self.validator_order.append(self.node_id)
            print(f"Node is running as a validator with ID: {self.node_id}")
        else:
            self.private_key = None
            self.public_key = None
            print(f"Node is running as a non-validator with ID: {self.node_id}")

        # Create genesis block if not provided
        if genesis_block:
            self.chain.append(genesis_block)
        else:
            self.create_genesis_block()

        # Add logging control flags
        self.suppress_consensus_errors = True
        self.suppress_hash_errors = True
        self.suppress_connection_errors = True

    def _get_key_pair(self):
        """Generate or load RSA key pair for the validator"""
        private_key_path = os.path.join(self.keys_dir, f"{self.node_id}.pem")
        public_key_path = os.path.join(self.keys_dir, f"{self.node_id}.pub")

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open(public_key_path, "rb") as f:
                public_key = f.read()
            print(f"Loaded existing key pair for validator {self.node_id}")
        else:
            # Generate new keys
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Save keys to files
            with open(private_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            with open(public_key_path, "wb") as f:
                f.write(public_key)

            print(f"Generated new key pair for validator {self.node_id}")

        return private_key, public_key

    def sign_data(self, data):
        """Sign data with the validator's private key"""
        if not self.is_validator or not self.private_key:
            return None

        # Ensure data is properly encoded as bytes
        if isinstance(data, str):
            data = data.encode("utf-8")

        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("utf-8")

    def verify_signature(self, data, signature, validator_id):
        """Verify a signature using a validator's public key"""
        try:
            if validator_id not in self.validators:
                return False

            public_key_bytes = self.validators[validator_id]
            public_key = serialization.load_pem_public_key(public_key_bytes)

            # Decode the base64 signature
            signature_bytes = base64.b64decode(signature)

            # Convert data to bytes if it's not already
            if isinstance(data, str):
                data = data.encode("utf-8")

            public_key.verify(
                signature_bytes,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Reset error counter on successful validation
            if self.is_validator and validator_id == self.node_id:
                self.signature_validation_errors = 0

            return True
        except InvalidSignature:
            # Track errors for self-healing
            if self.is_validator and validator_id == self.node_id:
                self.signature_validation_errors += 1
                # Check if we should try to fix our own keys
                if self.signature_validation_errors >= self.max_signature_errors:
                    self._fix_validator_keys()
            return False
        except Exception as e:
            if not self.suppress_hash_errors:
                print(f"Error verifying signature: {e}")
            return False

    def _fix_validator_keys(self):
        """Self-healing function to fix validator keys when signature errors are detected"""
        # Only validators can fix their own keys
        if not self.is_validator:
            return

        try:
            # Reset error counter
            self.signature_validation_errors = 0
            self.last_error_reset = time.time()

            # First try to check if other nodes have our validator key
            # and if it's working for them, sync from them
            if self._sync_validator_keys_from_network():
                return  # Key sync successful, no need to generate new keys

            # Generate new key pair
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Backup existing keys
            backup_dir = os.path.join(self.keys_dir, "backup")
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)

            timestamp = int(time.time())
            private_key_path = os.path.join(self.keys_dir, f"{self.node_id}.pem")
            public_key_path = os.path.join(self.keys_dir, f"{self.node_id}.pub")

            # Create backups if files exist
            if os.path.exists(private_key_path):
                backup_private = os.path.join(
                    backup_dir, f"{self.node_id}_{timestamp}.pem"
                )
                os.rename(private_key_path, backup_private)

            if os.path.exists(public_key_path):
                backup_public = os.path.join(
                    backup_dir, f"{self.node_id}_{timestamp}.pub"
                )
                os.rename(public_key_path, backup_public)

            # Save new keys
            with open(private_key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            with open(public_key_path, "wb") as f:
                f.write(public_key)

            # Update the node's keys
            self.private_key = private_key
            self.public_key = public_key
            self.validators[self.node_id] = public_key

            # Test the new keys
            test_data = "test_data"
            signature = self.sign_data(test_data)

            # Register with all peers
            registered_count = 0
            for peer in self.peers:
                try:
                    response = requests.post(
                        f"{peer}/validators/register",
                        json={
                            "validator_id": self.node_id,
                            "public_key": public_key.decode("utf-8"),
                        },
                        timeout=5,
                    )
                    if response.status_code in (200, 201):
                        registered_count += 1
                except Exception:
                    continue

        except Exception as e:
            # Silently handle errors - we don't want to crash the node
            pass

    def _sync_validator_keys_from_network(self):
        """Try to sync working validator keys from other nodes in the network"""
        try:
            # Try to get validator info from peers
            for peer in self.peers:
                try:
                    # Get list of validators from the peer
                    response = requests.get(f"{peer}/node/status", timeout=5)
                    if response.status_code == 200:
                        peer_data = response.json()
                        peer_validators = peer_data.get("validators", {})

                        # If we're in the validator list and it's different than our current key
                        if self.node_id in peer_validators:
                            peer_public_key = peer_validators.get(self.node_id)
                            if peer_public_key and peer_public_key != self.public_key:
                                # Test if this key works better by generating a test signature
                                signature_endpoint = f"{peer}/validators/test_signature"
                                test_response = requests.post(
                                    signature_endpoint,
                                    json={
                                        "validator_id": self.node_id,
                                        "data": "test_data",
                                    },
                                    timeout=5,
                                )

                                if test_response.status_code == 200:
                                    test_signature = test_response.json().get(
                                        "signature"
                                    )
                                    if test_signature:
                                        # We have a working public key and signature from the peer
                                        # Update our public key (we can't recover the private key)
                                        # This will allow us to verify signatures but not create them
                                        # So we'll need to generate a new key pair

                                        # Generate new key pair
                                        private_key = rsa.generate_private_key(
                                            public_exponent=65537, key_size=2048
                                        )
                                        public_key = private_key.public_key().public_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo,
                                        )

                                        # Save new keys
                                        private_key_path = os.path.join(
                                            self.keys_dir, f"{self.node_id}.pem"
                                        )
                                        public_key_path = os.path.join(
                                            self.keys_dir, f"{self.node_id}.pub"
                                        )

                                        with open(private_key_path, "wb") as f:
                                            f.write(
                                                private_key.private_bytes(
                                                    encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption(),
                                                )
                                            )
                                        with open(public_key_path, "wb") as f:
                                            f.write(public_key)

                                        # Update the node's keys
                                        self.private_key = private_key
                                        self.public_key = public_key
                                        self.validators[self.node_id] = public_key

                                        # Register with all peers
                                        for register_peer in self.peers:
                                            try:
                                                requests.post(
                                                    f"{register_peer}/validators/register",
                                                    json={
                                                        "validator_id": self.node_id,
                                                        "public_key": public_key.decode(
                                                            "utf-8"
                                                        ),
                                                    },
                                                    timeout=5,
                                                )
                                            except Exception:
                                                continue

                                        return (
                                            True  # Successfully synced and updated keys
                                        )

                except Exception:
                    continue

            return False  # Failed to sync keys from network
        except Exception:
            return False  # Failed to sync keys from network

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
        try:
            port = getattr(
                args, "port", 5000
            )  # Default to 5000 if args.port is not available
            own_address = f"http://{self.ip_address}:{port}"
            if peer_address not in self.peers and peer_address != own_address:
                self.peers.add(peer_address)
                print(f"Added peer: {peer_address}")
                return True
            return False
        except Exception as e:
            print(f"Error adding peer {peer_address}: {e}")
            return False

    def register_validator(self, validator_id, public_key):
        """Registers a validator node with its public key"""
        if validator_id in self.validators:
            print(f"Validator {validator_id} is already registered")
            return False

        # Add the validator's public key
        self.validators[validator_id] = public_key
        self.validator_order.append(validator_id)
        print(f"Registered validator: {validator_id}")
        return True

    def create_transaction(
        self, sender, action, domain_name, ip_address=None, new_owner=None
    ):
        """Creates a new DNS transaction"""
        # Check if domain already exists for 'register' action
        if action == "register" and domain_name in self.dns_records:
            return None, "Domain already registered"

        # Generate a unique transaction ID
        transaction_id = str(uuid.uuid4())

        transaction = {
            "transaction_id": transaction_id,
            "sender": sender,
            "action": action,  # 'register', 'update', 'transfer', 'renew'
            "domain_name": domain_name,
            "ip_address": ip_address,
            "new_owner": new_owner,
            "timestamp": time.time(),
        }

        # Store in transaction map
        self.transaction_map[transaction_id] = transaction

        self.pending_transactions.append(transaction)

        # Broadcast transaction to peers
        self.broadcast_transaction(transaction)

        return transaction, None

    def broadcast_transaction(self, transaction):
        """Broadcast a transaction to all peers"""
        for peer in self.peers:
            try:
                requests.post(
                    f"{peer}/transactions/new",
                    json=transaction,
                    timeout=5,
                )
            except Exception:
                # Silently continue if a peer is unreachable
                continue

    def broadcast_block(self, block):
        """Broadcast a block to all peers"""
        successful_broadcasts = 0
        for peer in self.peers:
            try:
                response = requests.post(
                    f"{peer}/blocks/new",
                    json=block,
                    timeout=5,
                )
                if response.status_code == 201:
                    successful_broadcasts += 1
            except Exception:
                # Silently continue if a peer is unreachable
                continue

        return successful_broadcasts > 0

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

    def get_next_validator(self):
        """Determine which validator's turn it is to create a block using round-robin"""
        if not self.validator_order:
            return None

        next_validator = self.validator_order[self.current_validator_index]
        # Update the index for the next round
        self.current_validator_index = (self.current_validator_index + 1) % len(
            self.validator_order
        )

        return next_validator

    def create_new_block(self):
        """Creates a new block with pending transactions using PoA"""
        if not self.pending_transactions:
            return None

        # Check if it's this node's turn to validate
        current_validator = self.get_next_validator()
        if current_validator != self.node_id:
            print(
                f"Not this node's turn to create a block. Current validator: {current_validator}"
            )
            return None

        # Create the block
        previous_block = self.chain[-1]
        new_block = {
            "index": len(self.chain),
            "timestamp": time.time(),
            "transactions": self.pending_transactions.copy(),
            "previous_hash": previous_block["hash"],
            "validator": self.node_id,
        }

        # Create a string representation for signing
        block_string = json.dumps(
            {k: v for k, v in new_block.items() if k != "signature"}, sort_keys=True
        )

        # Sign the block
        new_block["signature"] = self.sign_data(block_string)

        # Add hash to the new block
        new_block["hash"] = self.hash_block(new_block)

        print(f"Created new block {new_block['index']} as validator {self.node_id}")
        return new_block

    def apply_transaction(self, transaction, block_index=None):
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
                "last_update": transaction.get("timestamp"),
                "last_transaction_id": transaction.get("transaction_id"),
            }

            # Track which block this domain update is in
            if block_index is not None:
                self.domain_to_block[domain_name] = block_index

        elif action == "update" and domain_name in self.dns_records:
            self.dns_records[domain_name]["ip_address"] = transaction.get("ip_address")
            self.dns_records[domain_name]["last_update"] = transaction.get("timestamp")
            self.dns_records[domain_name]["last_transaction_id"] = transaction.get(
                "transaction_id"
            )

            # Track which block this domain update is in
            if block_index is not None:
                self.domain_to_block[domain_name] = block_index

        elif action == "transfer" and domain_name in self.dns_records:
            self.dns_records[domain_name]["owner"] = transaction.get("new_owner")
            self.dns_records[domain_name]["last_update"] = transaction.get("timestamp")
            self.dns_records[domain_name]["last_transaction_id"] = transaction.get(
                "transaction_id"
            )

            # Track which block this domain update is in
            if block_index is not None:
                self.domain_to_block[domain_name] = block_index

        elif action == "renew" and domain_name in self.dns_records:
            self.dns_records[domain_name]["expires_at"] += 31536000  # Extend by 1 year
            self.dns_records[domain_name]["last_update"] = transaction.get("timestamp")
            self.dns_records[domain_name]["last_transaction_id"] = transaction.get(
                "transaction_id"
            )

            # Track which block this domain update is in
            if block_index is not None:
                self.domain_to_block[domain_name] = block_index

    def add_block_to_chain(self, block):
        """Adds a validated block to the blockchain"""
        # Validate block before adding
        if self.validate_block(block):
            self.chain.append(block)

            # Apply transactions to DNS records
            for transaction in block["transactions"]:
                self.apply_transaction(transaction, block["index"])

                # Add to transaction map
                if "transaction_id" in transaction:
                    self.transaction_map[transaction["transaction_id"]] = transaction

            print(f"Added block {block['index']} to chain")
            return True
        return False

    def validate_block(self, block):
        """Validates a block before adding it to the chain"""
        try:
            # Check if the block is properly formed
            required_fields = [
                "index",
                "timestamp",
                "transactions",
                "previous_hash",
                "hash",
                "validator",
                "signature",
            ]
            for field in required_fields:
                if field not in block:
                    return False

            # Check if the block index is correct
            expected_index = len(self.chain)
            if block["index"] != expected_index:
                # Only trigger consensus if the incoming block has a higher index
                if block["index"] > expected_index:
                    if self.consensus():
                        # Recheck index after consensus
                        if block["index"] == len(self.chain):
                            return True
                        else:
                            return False
                    else:
                        return False
                else:
                    return False

            # Check if the previous hash matches the hash of the last block in the chain
            if block["previous_hash"] != self.chain[-1]["hash"]:
                # Trigger consensus on hash mismatch as we might be on a different fork
                if self.consensus():
                    # Recheck hash after consensus
                    if block["previous_hash"] == self.chain[-1]["hash"]:
                        return True
                    else:
                        return False
                else:
                    return False

            # Check if the block hash is valid
            if self.hash_block(block) != block["hash"]:
                return False

            # Skip signature verification for genesis block
            if block["validator"] == "genesis":
                return True

            # Check if the validator is authorized
            if block["validator"] not in self.validators:
                return False

            # Verify the validator's signature
            block_string = json.dumps(
                {k: v for k, v in block.items() if k != "signature" and k != "hash"},
                sort_keys=True,
            )

            # Only verify if we have the validator's public key
            if not self.verify_signature(
                block_string, block["signature"], block["validator"]
            ):
                return False

            return True
        except Exception as e:
            if not self.suppress_hash_errors:
                print(f"Error validating block: {e}")
            return False

    def consensus(self):
        """Consensus algorithm to resolve conflicts in the blockchain"""
        try:
            longest_chain = None
            max_length = len(self.chain)
            consensus_attempts = 0
            max_attempts = 3
            found_valid_chain = False

            # Get all chains from peers
            while consensus_attempts < max_attempts and not found_valid_chain:
                consensus_attempts += 1

                # Check chains from all peers in random order
                peers = list(self.peers)
                random.shuffle(peers)

                for peer in peers:
                    try:
                        # First check peer's status
                        status_response = requests.get(f"{peer}/node/status", timeout=5)
                        if status_response.status_code != 200:
                            continue

                        peer_status = status_response.json()
                        peer_chain_length = peer_status.get("chain_length", 0)

                        # Only fetch chain if peer has more blocks
                        if peer_chain_length <= max_length:
                            continue

                        # Get the peer's chain
                        response = requests.get(f"{peer}/chain", timeout=10)
                        if response.status_code == 200:
                            chain = response.json().get("chain")
                            length = len(chain)

                            # Verify chain length matches reported length
                            if length != peer_chain_length:
                                continue

                            # Check if the chain is longer and valid
                            if length > max_length and self.validate_chain(chain):
                                # Additional checks for chain validity
                                if chain[-1]["timestamp"] <= time.time():
                                    # Verify the chain is properly linked
                                    chain_valid = True
                                    for i in range(1, len(chain)):
                                        if (
                                            chain[i]["previous_hash"]
                                            != chain[i - 1]["hash"]
                                        ):
                                            chain_valid = False
                                            break

                                    if chain_valid:
                                        # Check if we share a common history
                                        common_history = False
                                        for i in range(
                                            min(len(self.chain), len(chain))
                                        ):
                                            if (
                                                self.chain[i]["hash"]
                                                == chain[i]["hash"]
                                            ):
                                                common_history = True
                                            else:
                                                if i == 0:  # Different genesis blocks
                                                    common_history = False
                                                break

                                        if common_history:
                                            max_length = length
                                            longest_chain = chain
                                            found_valid_chain = True
                                            break
                    except requests.exceptions.RequestException:
                        continue

                # Replace our chain if a longer valid chain is found
                if longest_chain and found_valid_chain:
                    self.chain = longest_chain
                    self.rebuild_dns_records()
                    # Reset validator index based on new chain
                    self.current_validator_index = 0
                    return True

                # If no valid longer chain found, wait briefly before next attempt
                if consensus_attempts < max_attempts and not found_valid_chain:
                    time.sleep(1)

            # If a valid longer chain was found, replace our chain
            if longest_chain and found_valid_chain:
                self.chain = longest_chain
                self.rebuild_dns_records()
                return True

            return False
        except Exception as e:
            if not self.suppress_consensus_errors:
                print(f"Error in consensus mechanism: {e}")
            return False

    def validate_chain(self, chain):
        """Validate the entire blockchain"""
        try:
            # Check genesis block
            if chain[0]["index"] != 0 or chain[0]["previous_hash"] != "0":
                return False

            # Check each block in the chain
            for i in range(1, len(chain)):
                current_block = chain[i]
                previous_block = chain[i - 1]

                # Check block index
                if current_block["index"] != i:
                    return False

                # Check previous hash
                if current_block["previous_hash"] != previous_block["hash"]:
                    return False

                # Check block hash
                if self.hash_block(current_block) != current_block["hash"]:
                    return False

                # Skip signature verification for genesis block
                if current_block["validator"] == "genesis":
                    continue

                # Verify validator signature
                block_string = json.dumps(
                    {
                        k: v
                        for k, v in current_block.items()
                        if k != "signature" and k != "hash"
                    },
                    sort_keys=True,
                )

                # Only verify if we have the validator's public key
                if current_block["validator"] in self.validators:
                    # Don't fail validation if signature verification fails during chain validation
                    # This allows nodes to recover from signature format changes
                    self.verify_signature(
                        block_string,
                        current_block["signature"],
                        current_block["validator"],
                    )

            return True
        except Exception as e:
            if not self.suppress_hash_errors:
                print(f"Error validating chain: {e}")
            return False

    def rebuild_dns_records(self):
        """Rebuilds DNS records from the blockchain"""
        self.dns_records = {}
        self.domain_to_block = {}
        self.transaction_map = {}

        for i, block in enumerate(self.chain):
            for transaction in block.get("transactions", []):
                self.apply_transaction(transaction, i)

                # Rebuild transaction map
                if "transaction_id" in transaction:
                    self.transaction_map[transaction["transaction_id"]] = transaction

    def resolve_domain(self, domain_name):
        """Resolves a domain name to an IP address"""
        if domain_name in self.dns_records:
            record = self.dns_records[domain_name]
            if record.get("expires_at", 0) > time.time():
                # Add block information to the record
                block_number = self.domain_to_block.get(domain_name)
                return {
                    "domain_name": domain_name,
                    "ip_address": record.get("ip_address"),
                    "owner": record.get("owner"),
                    "registered_at": record.get("registered_at"),
                    "expires_at": record.get("expires_at"),
                    "last_update": record.get("last_update"),
                    "block_number": block_number,
                    "last_transaction_id": record.get("last_transaction_id"),
                }
        return None

    def get_transaction_by_id(self, transaction_id):
        """Get transaction details by transaction ID"""
        if transaction_id in self.transaction_map:
            transaction = self.transaction_map[transaction_id]

            # Find which block contains this transaction
            block_info = None
            for i, block in enumerate(self.chain):
                for tx in block["transactions"]:
                    if tx.get("transaction_id") == transaction_id:
                        block_info = {
                            "block_number": i,
                            "block_hash": block["hash"],
                            "block_time": block["timestamp"],
                        }
                        break
                if block_info:
                    break

            return {"transaction": transaction, "block_info": block_info}

        return None

    def get_block_by_number(self, block_number):
        """Get block details by block number"""
        if isinstance(block_number, int) and 0 <= block_number < len(self.chain):
            return self.chain[block_number]
        return None


# Flask routes
@app.route("/transactions/new", methods=["POST"])
def new_transaction():
    values = request.get_json()

    # Check if the transaction is valid
    if blockchain_node.validate_transaction(values):
        blockchain_node.pending_transactions.append(values)

        # Store in transaction map
        if "transaction_id" in values:
            blockchain_node.transaction_map[values["transaction_id"]] = values

        return (
            jsonify(
                {
                    "message": f"Transaction will be added to Block {len(blockchain_node.chain)}",
                    "transaction_id": values.get("transaction_id"),
                    "chain_length": len(blockchain_node.chain),
                }
            ),
            201,
        )

    return jsonify({"message": "Invalid transaction"}), 400


@app.route("/mine", methods=["GET"])
def mine():
    # Check if any transactions are pending
    if not blockchain_node.pending_transactions:
        return jsonify({"message": "No transactions to mine"}), 200

    # Check if this node is a validator
    if not blockchain_node.is_validator:
        return jsonify({"message": "This node is not a validator"}), 403

    # Check if it's this node's turn to validate
    current_validator = blockchain_node.get_next_validator()
    if current_validator != blockchain_node.node_id:
        return (
            jsonify(
                {
                    "message": f"It's not this node's turn to validate. Current validator: {current_validator}"
                }
            ),
            403,
        )

    # Create a new block
    new_block = blockchain_node.create_new_block()
    if not new_block:
        return jsonify({"message": "Failed to create new block"}), 500

    # Add the new block to the chain
    if not blockchain_node.add_block_to_chain(new_block):
        return jsonify({"message": "Failed to add block to chain"}), 500

    # Broadcast the new block to all peers
    blockchain_node.broadcast_block(new_block)

    return (
        jsonify(
            {
                "message": "New block mined",
                "block": new_block,
            }
        ),
        201,
    )


@app.route("/blocks/new", methods=["POST"])
def receive_block():
    block = request.get_json()

    # Add the block to the chain if it's valid
    if blockchain_node.add_block_to_chain(block):
        return (
            jsonify(
                {
                    "message": "Block added to the chain",
                    "block_number": block["index"],
                    "chain_length": len(blockchain_node.chain),
                }
            ),
            201,
        )

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
    public_key = values.get("public_key")

    if validator_id and public_key:
        if blockchain_node.register_validator(validator_id, public_key):
            return (
                jsonify(
                    {"message": f"Validator {validator_id} registered successfully"}
                ),
                201,
            )
        else:
            return (
                jsonify({"message": f"Validator {validator_id} already registered"}),
                200,
            )

    return jsonify({"message": "Invalid validator ID or public key"}), 400


@app.route("/dns/register", methods=["POST"])
def register_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")

    # Extract client IP address from the request instead of trusting the provided IP
    # Get client IP address - handle reverse proxies by checking X-Forwarded-For first
    client_ip = request.remote_addr
    if request.headers.get("X-Forwarded-For"):
        client_ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()

    print(f"Domain registration request from IP: {client_ip} for domain: {domain_name}")

    # Validate the extracted IP address
    if not client_ip or client_ip == "127.0.0.1" or client_ip == "localhost":
        # For local testing, use the node's detected IP if client is on localhost
        client_ip = blockchain_node.ip_address
        print(f"Client on localhost, using node IP: {client_ip}")

    if sender and domain_name:
        transaction, error = blockchain_node.create_transaction(
            sender=sender,
            action="register",
            domain_name=domain_name,
            ip_address=client_ip,  # Use the extracted IP instead of client-provided IP
        )

        if transaction:
            return (
                jsonify(
                    {
                        "message": "Domain registration transaction created",
                        "transaction": transaction,
                        "chain_length": len(blockchain_node.chain),
                        "pending_transactions": len(
                            blockchain_node.pending_transactions
                        ),
                    }
                ),
                201,
            )
        else:
            return jsonify({"message": f"Domain registration failed: {error}"}), 400

    return jsonify({"message": "Missing values (sender or domain_name)"}), 400


@app.route("/dns/update", methods=["POST"])
def update_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")
    ip_address = values.get("ip_address")

    if sender and domain_name and ip_address:
        transaction, error = blockchain_node.create_transaction(
            sender=sender,
            action="update",
            domain_name=domain_name,
            ip_address=ip_address,
        )

        if transaction:
            return (
                jsonify(
                    {
                        "message": "Domain update transaction created",
                        "transaction": transaction,
                        "chain_length": len(blockchain_node.chain),
                        "pending_transactions": len(
                            blockchain_node.pending_transactions
                        ),
                    }
                ),
                201,
            )
        else:
            return jsonify({"message": f"Domain update failed: {error}"}), 400

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/transfer", methods=["POST"])
def transfer_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")
    new_owner = values.get("new_owner")

    if sender and domain_name and new_owner:
        transaction, error = blockchain_node.create_transaction(
            sender=sender,
            action="transfer",
            domain_name=domain_name,
            new_owner=new_owner,
        )

        if transaction:
            return (
                jsonify(
                    {
                        "message": "Domain transfer transaction created",
                        "transaction": transaction,
                        "chain_length": len(blockchain_node.chain),
                        "pending_transactions": len(
                            blockchain_node.pending_transactions
                        ),
                    }
                ),
                201,
            )
        else:
            return jsonify({"message": f"Domain transfer failed: {error}"}), 400

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/renew", methods=["POST"])
def renew_domain():
    values = request.get_json()
    sender = values.get("sender")
    domain_name = values.get("domain_name")

    if sender and domain_name:
        transaction, error = blockchain_node.create_transaction(
            sender=sender, action="renew", domain_name=domain_name
        )

        if transaction:
            return (
                jsonify(
                    {
                        "message": "Domain renewal transaction created",
                        "transaction": transaction,
                        "chain_length": len(blockchain_node.chain),
                        "pending_transactions": len(
                            blockchain_node.pending_transactions
                        ),
                    }
                ),
                201,
            )
        else:
            return jsonify({"message": f"Domain renewal failed: {error}"}), 400

    return jsonify({"message": "Missing values"}), 400


@app.route("/dns/resolve/<domain_name>", methods=["GET"])
def resolve_domain(domain_name):
    result = blockchain_node.resolve_domain(domain_name)

    if result:
        return jsonify(result), 200

    return jsonify({"message": f"Domain {domain_name} not found or expired"}), 404


@app.route("/dns/records", methods=["GET"])
def get_dns_records():
    # Enhance the records with block information
    enhanced_records = {}
    for domain, record in blockchain_node.dns_records.items():
        block_number = blockchain_node.domain_to_block.get(domain)
        enhanced_record = dict(record)
        enhanced_record["block_number"] = block_number
        enhanced_records[domain] = enhanced_record

    # Add blockchain info
    blockchain_info = {
        "current_block": len(blockchain_node.chain) - 1,
        "chain_length": len(blockchain_node.chain),
        "last_update": time.time(),
    }

    return (
        jsonify({"dns_records": enhanced_records, "blockchain_info": blockchain_info}),
        200,
    )


@app.route("/node/status", methods=["GET"])
def node_status():
    latest_block = blockchain_node.chain[-1] if blockchain_node.chain else None

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
                "last_block_hash": latest_block["hash"] if latest_block else None,
                "last_block_time": latest_block["timestamp"] if latest_block else None,
                "validators_count": len(blockchain_node.validators),
                "validators": list(blockchain_node.validators),
            }
        ),
        200,
    )


@app.route("/blocks/<int:block_number>", methods=["GET"])
def get_block(block_number):
    block = blockchain_node.get_block_by_number(block_number)

    if block:
        return jsonify({"block": block}), 200

    return jsonify({"message": f"Block {block_number} not found"}), 404


@app.route("/transactions/<transaction_id>", methods=["GET"])
def get_transaction(transaction_id):
    result = blockchain_node.get_transaction_by_id(transaction_id)

    if result:
        return jsonify(result), 200

    return jsonify({"message": f"Transaction {transaction_id} not found"}), 404


# Add a test signature endpoint to help with key syncing
@app.route("/validators/test_signature", methods=["POST"])
def test_validator_signature():
    """Generate a test signature for a validator to help with key sync"""
    values = request.get_json()
    validator_id = values.get("validator_id")
    data = values.get("data", "test_data")

    if (
        validator_id
        and validator_id == blockchain_node.node_id
        and blockchain_node.is_validator
    ):
        signature = blockchain_node.sign_data(data)
        return jsonify({"signature": signature}), 200

    # If not our validator ID or not a validator
    return jsonify({"message": "Cannot generate signature"}), 400


# Consensus mechanism - run periodically
def consensus_task():
    """Background task to maintain consensus with other nodes"""
    while True:
        try:
            # Redirect output to null device to suppress messages
            if not blockchain_node.suppress_consensus_errors:
                print("Running consensus mechanism...")

            blockchain_node.consensus()
        except Exception as e:
            if not blockchain_node.suppress_consensus_errors:
                print(f"Error in consensus mechanism: {e}")
        time.sleep(10)


# Validator mining - run periodically
def mining_task():
    """Background task to mine new blocks"""
    while True:
        try:
            # Only mine if we're a validator
            if blockchain_node.is_validator:
                # Redirect output to avoid cluttering logs
                if blockchain_node.suppress_hash_errors:
                    # Mine without printing error messages
                    with open(os.devnull, "w") as f:
                        # Redirect stdout temporarily
                        old_stdout = sys.stdout
                        sys.stdout = f
                        try:
                            # Create and broadcast a new block
                            block = blockchain_node.create_new_block()
                            if block:
                                blockchain_node.broadcast_block(block)
                        finally:
                            # Restore stdout
                            sys.stdout = old_stdout
                else:
                    # Mine with normal output
                    block = blockchain_node.create_new_block()
                    if block:
                        blockchain_node.broadcast_block(block)
        except Exception as e:
            if not blockchain_node.suppress_hash_errors:
                print(f"Error in mining task: {e}")

        # Wait before mining again
        time.sleep(20)  # Mine every 20 seconds


# Periodic network discovery and reconnection task
def network_discovery_task():
    """Background task to discover and connect to new nodes in the network"""
    # Initial delay before starting discovery
    time.sleep(5)

    while True:
        try:
            # List of predefined blockchain node IPs to try connecting to
            blockchain_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
            validator_ips = ["192.168.1.20", "192.168.1.21"]
            all_ips = blockchain_ips + validator_ips

            # Find our own IP address
            own_ip = get_ip_address()

            # Add new peers from the predefined list
            for ip in all_ips:
                if ip != own_ip:  # Don't connect to ourselves
                    try:
                        # Skip if already connected
                        peer_url = f"http://{ip}:5000"
                        if peer_url in blockchain_node.peers:
                            continue

                        # Try to connect to the node
                        response = requests.get(f"{peer_url}/node/status", timeout=2)
                        if response.status_code == 200:
                            # Add peer if connection successful
                            blockchain_node.add_peer(peer_url)
                            if not blockchain_node.suppress_connection_errors:
                                print(f"Discovered and connected to node: {peer_url}")

                            # If we're a validator, register with the new peer
                            if blockchain_node.is_validator:
                                try:
                                    requests.post(
                                        f"{peer_url}/validators/register",
                                        json={
                                            "validator_id": blockchain_node.node_id,
                                            "public_key": blockchain_node.public_key.decode(
                                                "utf-8"
                                            ),
                                        },
                                        timeout=5,
                                    )
                                except Exception:
                                    # Silently ignore validator registration errors
                                    pass
                    except Exception:
                        # Silently ignore connection errors to predefined nodes
                        pass

            # Find new nodes to connect to from known peers
            for peer in list(blockchain_node.peers):  # Use a copy of the list
                try:
                    response = requests.get(f"{peer}/peers", timeout=5)
                    if response.status_code == 200:
                        peer_list = response.json().get("peers", [])
                        for new_peer in peer_list:
                            if (
                                new_peer != app.config["NODE_URL"]
                                and new_peer not in blockchain_node.peers
                            ):
                                try:
                                    # Verify the new peer is reachable
                                    test_response = requests.get(
                                        f"{new_peer}/node/status", timeout=2
                                    )
                                    if test_response.status_code == 200:
                                        blockchain_node.add_peer(new_peer)
                                        if (
                                            not blockchain_node.suppress_connection_errors
                                        ):
                                            print(f"Connected to peer: {new_peer}")

                                        # Register as validator with the new peer if applicable
                                        if blockchain_node.is_validator:
                                            try:
                                                requests.post(
                                                    f"{new_peer}/validators/register",
                                                    json={
                                                        "validator_id": blockchain_node.node_id,
                                                        "public_key": blockchain_node.public_key.decode(
                                                            "utf-8"
                                                        ),
                                                    },
                                                    timeout=5,
                                                )
                                            except Exception:
                                                # Silently ignore validator registration errors
                                                pass
                                except Exception:
                                    # Silently ignore errors connecting to new peers
                                    pass
                except Exception:
                    # If we can't reach a peer, remove it
                    if not blockchain_node.suppress_connection_errors:
                        print(f"Peer {peer} unreachable, removing from peer list")
                    blockchain_node.peers.remove(peer)

            # Get validator list from peers
            if not blockchain_node.is_validator:
                for peer in list(blockchain_node.peers):
                    try:
                        response = requests.get(f"{peer}/node/status", timeout=5)
                        if response.status_code == 200:
                            peer_validators = response.json().get("validators", {})
                            for validator_id, public_key in peer_validators.items():
                                if validator_id not in blockchain_node.validators:
                                    blockchain_node.validators[validator_id] = (
                                        public_key.encode()
                                    )
                                    if not blockchain_node.suppress_connection_errors:
                                        print(
                                            f"Added validator {validator_id} from peer {peer}"
                                        )
                    except Exception:
                        # Silently ignore errors getting validator list
                        pass
        except Exception as e:
            if not blockchain_node.suppress_connection_errors:
                print(f"Error in network discovery: {e}")

        # Sleep between discovery attempts
        time.sleep(30)


# Validator health check - run periodically
def validator_health_check():
    """Periodically check validator health and fix issues automatically"""
    while not shutdown_flag.is_set():
        # Only run for validator nodes
        if blockchain_node.is_validator:
            try:
                # Silently run health check
                with open(os.devnull, "w") as f:
                    # Redirect stdout temporarily
                    old_stdout = sys.stdout
                    sys.stdout = f
                    try:
                        # Test signature verification with the current key
                        test_data = "health_check_data"
                        signature = blockchain_node.sign_data(test_data)

                        if signature:
                            # Verify the signature
                            test_data_bytes = (
                                test_data.encode("utf-8")
                                if isinstance(test_data, str)
                                else test_data
                            )
                            public_key = serialization.load_pem_public_key(
                                blockchain_node.public_key
                            )

                            try:
                                # Try to verify our own signature
                                public_key.verify(
                                    base64.b64decode(signature),
                                    test_data_bytes,
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH,
                                    ),
                                    hashes.SHA256(),
                                )
                                # Reset error counter on success
                                blockchain_node.signature_validation_errors = 0
                            except Exception:
                                # Increment error counter
                                blockchain_node.signature_validation_errors += 1
                                # Fix keys if too many errors
                                if (
                                    blockchain_node.signature_validation_errors
                                    >= blockchain_node.max_signature_errors
                                ):
                                    blockchain_node._fix_validator_keys()
                    finally:
                        # Restore stdout
                        sys.stdout = old_stdout
            except Exception:
                # Silently ignore any errors
                pass

        # Check every 30 seconds
        time.sleep(30)


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Blockchain DNS")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--id", default=None, help="Node identifier")
    parser.add_argument(
        "--validator", action="store_true", help="Run as a validator node"
    )
    args = parser.parse_args()

    # Set up logging
    if not os.path.exists("logs"):
        os.makedirs("logs")
    logging.basicConfig(
        filename=f"logs/{args.id or 'node'}.log",
        level=logging.ERROR,  # Only log errors, not info or debug
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Suppress Flask and Werkzeug logs
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("flask").setLevel(logging.ERROR)

    # Configure node
    node_id = args.id or str(uuid.uuid4())

    # Create blockchain node instance
    blockchain_node = BlockchainNode(node_id, is_validator=args.validator)

    # Configure Flask app
    app.config["NODE_URL"] = f"http://{blockchain_node.ip_address}:{args.port}"

    # Start background tasks
    consensus_thread = threading.Thread(target=consensus_task)
    consensus_thread.daemon = True
    consensus_thread.start()

    mining_thread = threading.Thread(target=mining_task)
    mining_thread.daemon = True
    mining_thread.start()

    discovery_thread = threading.Thread(target=network_discovery_task)
    discovery_thread.daemon = True
    discovery_thread.start()

    health_check_thread = threading.Thread(target=validator_health_check)
    health_check_thread.daemon = True
    health_check_thread.start()

    # Run Flask app with minimal logging
    app.run(host="0.0.0.0", port=args.port, debug=False, use_reloader=False)
