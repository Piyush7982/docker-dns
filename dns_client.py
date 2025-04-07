#!/usr/bin/env python3
import argparse
import requests
import json
import sys
import os
import cmd
import random
import time
import socket
import re
from tabulate import tabulate
from ipaddress import ip_address, IPv4Address


class DNSClientShell(cmd.Cmd):
    intro = (
        "Welcome to the Decentralized DNS Client. Type help or ? to list commands.\n"
    )
    prompt = "dns> "

    # Domain name validation regex
    DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    def __init__(self, blockchain_nodes=None, client_id=None):
        super(DNSClientShell, self).__init__()
        self.blockchain_nodes = blockchain_nodes or []
        self.client_id = client_id or f"client_{random.randint(1000, 9999)}"

        # Local DNS cache with structured data
        self.cached_domains = {}  # Maps domain to IP and expiry
        self.last_transaction = None  # Store the last transaction for reference

        # Debug flag for verbose output
        self.verbose = False

        # Initialize the client
        print(f"Initialized DNS client with ID: {self.client_id}")
        print(f"Connected to blockchain nodes: {', '.join(self.blockchain_nodes)}")

    def _normalize_domain(self, domain_name):
        """Normalize domain name to lowercase for consistent comparisons"""
        if not domain_name:
            return ""
        return domain_name.strip().lower()

    def do_register(self, arg):
        """Register a new domain: register <domain_name>"""
        if not arg:
            print("Usage: register <domain_name>")
            return

        # Parse domain name
        domain_name = arg.strip()

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print("Invalid domain name format. Use: example.com")
            return

        # Normalize domain name
        domain_name = self._normalize_domain(domain_name)

        # Check if domain already exists
        if self._check_domain_exists(domain_name):
            print(f"Domain {domain_name} is already registered")
            self._suggest_similar_domains(domain_name)
            return

        # Get a responsive node
        node = self._get_random_node()
        if not node:
            print("No responsive blockchain nodes found")
            return

        try:
            # Create registration transaction
            transaction = {"sender": self.client_id, "domain_name": domain_name}

            # Send registration request
            response = requests.post(
                f"{node}/dns/register", json=transaction, timeout=10
            )

            if response.status_code == 201:
                data = response.json()
                transaction_data = data.get("transaction", {})
                detected_ip = transaction_data.get("ip_address")

                print(f"✅ Domain {domain_name} registered successfully")
                if detected_ip:
                    print(f"Server detected IP: {detected_ip}")
                print(f"Transaction ID: {transaction_data.get('transaction_id')}")

                # Wait for mining
                print("Waiting for transaction to be mined...")
                time.sleep(5)  # Give time for mining

                # Verify registration
                if self._check_domain_exists(domain_name):
                    print("Registration confirmed in blockchain")
                else:
                    print("Warning: Registration not yet confirmed in blockchain")

            else:
                error_msg = response.json().get("message", "Unknown error")
                print(f"❌ Registration failed: {error_msg}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_update(self, arg):
        """Update an existing domain's IP address: update <domain_name> <new_ip_address>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: update <domain_name> <new_ip_address>")
            return

        domain_name, ip_address = args

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print(f"Invalid domain name format: {domain_name}")
            return

        # Validate IP address
        if not self._validate_ip_address(ip_address):
            print(f"Invalid IP address: {ip_address}")
            return

        # Check if IP is in valid network range
        if not self._is_ip_in_valid_range(ip_address):
            print(
                f"Warning: IP address {ip_address} is not in the expected network range."
            )
            print("This may cause the domain to be unreachable.")
            confirm = input("Continue with update? (y/n): ")
            if confirm.lower() not in ["y", "yes"]:
                return

        # First check if domain exists
        if not self._check_domain_exists(domain_name):
            print(
                f"Domain {domain_name} does not exist. Use 'register' command instead."
            )
            return

        # Check if domain belongs to this client
        if not self._check_domain_ownership(domain_name):
            print(
                f"You don't own the domain {domain_name}. Only the owner can update it."
            )
            return

        # Send update request to a random node
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.post(
                f"{node}/dns/update",
                json={
                    "sender": self.client_id,
                    "domain_name": domain_name,
                    "ip_address": ip_address,
                },
                timeout=10,
            )

            if response.status_code == 201:
                json_response = response.json()
                self.last_transaction = json_response.get("transaction")

                print(f"Domain {domain_name} updated with new IP {ip_address}")

                # Display blockchain information
                self._print_blockchain_info(json_response)

                # Update local cache
                if domain_name in self.cached_domains:
                    self._update_cache(domain_name, ip_address)
            else:
                print(
                    f"Failed to update domain: {response.json().get('message', 'Unknown error')}"
                )

        except requests.exceptions.ConnectionError:
            print(f"Connection error: Could not reach blockchain node at {node}")
            print("Please check your network connection or try another node.")
        except requests.exceptions.Timeout:
            print(f"Connection timed out while reaching {node}")
            print("The blockchain node might be busy. Please try again later.")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def do_transfer(self, arg):
        """Transfer domain ownership: transfer <domain_name> <new_owner_id>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: transfer <domain_name> <new_owner_id>")
            return

        domain_name, new_owner = args

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print(f"Invalid domain name format: {domain_name}")
            return

        # Normalize domain name
        domain_name = self._normalize_domain(domain_name)

        # Check domain existence and ownership
        if not self._check_domain_exists(domain_name):
            print(f"Domain {domain_name} does not exist.")
            return

        if not self._check_domain_ownership(domain_name):
            print(f"You don't own the domain {domain_name}.")
            return

        # Validate new owner ID
        if not new_owner or len(new_owner) < 3:
            print("Invalid new owner ID. Must be at least 3 characters long.")
            return

        if new_owner == self.client_id:
            print("You already own this domain.")
            return

        # Double confirmation for transfer
        print("\n⚠️ WARNING: Domain transfers are permanent!")
        print(f"You are transferring '{domain_name}' to '{new_owner}'")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() != "yes":
            print("Transfer cancelled.")
            return

        # Attempt transfer on all nodes until success
        success = False
        for node in self.blockchain_nodes:
            try:
                response = requests.post(
                    f"{node}/dns/transfer",
                    json={
                        "sender": self.client_id,
                        "domain_name": domain_name,
                        "new_owner": new_owner,
                    },
                    timeout=10,
                )

                if response.status_code == 201:
                    transaction = response.json().get("transaction", {})
                    print(f"\n✅ Transfer initiated for {domain_name}")
                    print(f"Transaction ID: {transaction.get('transaction_id')}")
                    print("Please wait for the transfer to be confirmed...")

                    # Wait for confirmation
                    time.sleep(5)
                    if self._check_domain_ownership(domain_name):
                        print("Transfer pending confirmation...")
                    else:
                        print("Transfer completed successfully!")

                    success = True
                    break
            except requests.exceptions.RequestException as e:
                continue

        if not success:
            print("Failed to transfer domain. Please try again later.")

    def do_renew(self, arg):
        """Renew a domain's registration: renew <domain_name>"""
        domain_name = arg.strip()
        if not domain_name:
            print("Usage: renew <domain_name>")
            return

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print(f"Invalid domain name format: {domain_name}")
            return

        # First check if domain exists
        if not self._check_domain_exists(domain_name):
            print(
                f"Domain {domain_name} does not exist. Cannot renew non-existent domain."
            )
            return

        # Check if domain belongs to this client
        if not self._check_domain_ownership(domain_name):
            print(
                f"You don't own the domain {domain_name}. Only the owner can renew it."
            )
            return

        # Send renew request to a random node
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.post(
                f"{node}/dns/renew",
                json={
                    "sender": self.client_id,
                    "domain_name": domain_name,
                },
            )

            if response.status_code == 201:
                json_response = response.json()
                self.last_transaction = json_response.get("transaction")

                print(f"Domain {domain_name} renewed successfully")

                # Display blockchain information
                self._print_blockchain_info(json_response)

                # Update cache expiry if in cache
                self._refresh_cache_expiry(domain_name)
            else:
                print(f"Failed to renew domain: {response.json().get('message')}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_resolve(self, arg):
        """Resolve a domain name to its IP address: resolve <domain_name>"""
        if not arg:
            print("Usage: resolve <domain_name>")
            return

        # Parse domain name
        domain_name = arg.strip()

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print("Invalid domain name format. Use: example.com")
            return

        # Normalize domain name
        domain_name = self._normalize_domain(domain_name)

        # Try each node until we get a response
        for node in self.blockchain_nodes:
            try:
                # Try direct resolution first
                response = requests.get(f"{node}/dns/resolve/{domain_name}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    ip_address = data.get("ip_address")
                    owner = data.get("owner")
                    expires_at = data.get("expires_at", 0)

                    if ip_address:
                        # Update cache
                        self._update_cache(domain_name, ip_address)

                        # Display results
                        print(f"✅ Domain {domain_name} resolved to {ip_address}")
                        print(f"Owner: {owner}")
                        if expires_at:
                            remaining = max(0, int((expires_at - time.time()) / 86400))
                            print(f"Expires in: {remaining} days")
                        return

                # If direct resolve fails, check DNS records
                response = requests.get(f"{node}/dns/records", timeout=5)
                if response.status_code == 200:
                    records = response.json().get("dns_records", {})
                    if domain_name in records:
                        record = records[domain_name]
                        ip_address = record.get("ip_address")
                        owner = record.get("owner")
                        expires_at = record.get("expires_at", 0)

                        if ip_address:
                            # Update cache
                            self._update_cache(domain_name, ip_address)

                            # Display results
                            print(f"✅ Domain {domain_name} resolved to {ip_address}")
                            print(f"Owner: {owner}")
                            if expires_at:
                                remaining = max(
                                    0, int((expires_at - time.time()) / 86400)
                                )
                                print(f"Expires in: {remaining} days")
                            return

            except requests.exceptions.RequestException as e:
                print(f"Error connecting to node {node}: {e}")
                continue

        print(f"❌ Could not resolve domain {domain_name}")

    def do_list_records(self, arg):
        """List all DNS records in the blockchain"""
        # Clear local cache to ensure fresh data
        self.cached_domains.clear()

        # Try each node until we get a response
        for node in self.blockchain_nodes:
            try:
                response = requests.get(f"{node}/dns/records", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    records = data.get("dns_records", {})

                    if not records:
                        print("No DNS records found")
                        return

                    # Build table data
                    table_data = []
                    for domain, record in records.items():
                        owner = record.get("owner", "Unknown")
                        owner_display = (
                            f"{owner} (You)" if owner == self.client_id else owner
                        )
                        table_data.append(
                            [
                                domain,
                                record.get("ip_address", "N/A"),
                                owner_display,
                                time.strftime(
                                    "%Y-%m-%d %H:%M:%S",
                                    time.localtime(record.get("expires_at", 0)),
                                ),
                            ]
                        )

                    # Sort by domain name
                    table_data.sort(key=lambda x: x[0])

                    # Print table
                    self._print_table(
                        ["Domain", "IP Address", "Owner", "Expires"], table_data
                    )
                    return

            except requests.exceptions.RequestException as e:
                print(f"Error connecting to node {node}: {e}")
                continue

        print("Failed to fetch DNS records from any node")

    def do_node_status(self, arg):
        """Get the status of a blockchain node"""
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/node/status")

            if response.status_code == 200:
                status = response.json()

                print("\n📊 Blockchain Node Status:")
                print(f"Node ID: {status.get('node_id')}")
                print(f"IP Address: {status.get('ip_address')}")
                print(f"Is Validator: {'✓' if status.get('is_validator') else '✗'}")
                print(f"Connected Peers: {status.get('peers_count')}")
                print(f"Chain Length: {status.get('chain_length')} blocks")
                print(f"Pending Transactions: {status.get('pending_transactions')}")
                print(f"DNS Records Count: {status.get('dns_records_count')}")

                # Show more detailed blockchain info
                if "last_block_hash" in status:
                    print(f"\nLast Block Hash: {status.get('last_block_hash')}")
                if "last_block_time" in status:
                    print(
                        f"Last Block Time: {time.ctime(status.get('last_block_time'))}"
                    )
            else:
                print(
                    f"Failed to retrieve node status: {response.json().get('message')}"
                )

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_block_info(self, arg):
        """Get information about a specific block: block_info <block_number>"""
        block_number = arg.strip()
        if not block_number:
            print("Usage: block_info <block_number>")
            return

        try:
            block_number = int(block_number)
        except ValueError:
            print("Block number must be an integer.")
            return

        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/blocks/{block_number}")

            if response.status_code == 200:
                block = response.json().get("block", {})

                print(f"\n🧱 Block #{block.get('index')} Information:")
                print(f"Hash: {block.get('hash')}")
                print(f"Previous Hash: {block.get('previous_hash')}")
                print(f"Timestamp: {time.ctime(block.get('timestamp'))}")
                print(f"Validator: {block.get('validator')}")

                transactions = block.get("transactions", [])
                if transactions:
                    print(f"\nContains {len(transactions)} transactions:")
                    for i, tx in enumerate(transactions, 1):
                        print(
                            f"  {i}. {tx.get('action')} domain '{tx.get('domain_name')}' by {tx.get('sender')}"
                        )
                else:
                    print("\nNo transactions in this block.")
            elif response.status_code == 404:
                print(f"Block #{block_number} not found.")
            else:
                print(
                    f"Failed to retrieve block information: {response.json().get('message')}"
                )

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_transaction_info(self, arg):
        """Get information about the last transaction or a specific transaction by ID"""
        transaction_id = arg.strip()

        if not transaction_id:
            # Show information about last transaction
            if not self.last_transaction:
                print(
                    "No recent transaction available. Make a transaction first or provide a transaction ID."
                )
                return

            print("\n📝 Last Transaction Information:")
            self._print_transaction_details(self.last_transaction)
            return

        # Look up transaction by ID
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/transactions/{transaction_id}")

            if response.status_code == 200:
                transaction = response.json().get("transaction", {})
                block_info = response.json().get("block_info", {})

                print(f"\n📝 Transaction {transaction_id} Information:")
                self._print_transaction_details(transaction)

                # Print block information
                if block_info:
                    print(f"\nIncluded in Block #{block_info.get('block_number')}")
                    print(f"Block Hash: {block_info.get('block_hash')}")
                    print(f"Block Time: {time.ctime(block_info.get('block_time'))}")
            elif response.status_code == 404:
                print(f"Transaction {transaction_id} not found.")
            else:
                print(
                    f"Failed to retrieve transaction: {response.json().get('message')}"
                )

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_connect(self, arg):
        """Connect to a blockchain node: connect <node_url>"""
        node_url = arg.strip()
        if not node_url:
            print("Usage: connect <node_url>")
            return

        # Add http:// prefix if not present
        if not node_url.startswith("http://"):
            node_url = "http://" + node_url

        # Validate node URL format
        if not self._validate_node_url(node_url):
            print(f"Invalid node URL format: {node_url}")
            print(
                "URL should be in the format: http://hostname:port or http://ip-address:port"
            )
            return

        # Check if already connected
        if node_url in self.blockchain_nodes:
            print(f"Already connected to {node_url}")
            return

        # Try to connect to the node
        try:
            response = requests.get(f"{node_url}/node/status", timeout=3)

            if response.status_code == 200:
                self.blockchain_nodes.append(node_url)
                status = response.json()
                print(f"Successfully connected to blockchain node at {node_url}")
                print(f"Node ID: {status.get('node_id')}")
                print(f"Chain Length: {status.get('chain_length')} blocks")
                print(f"DNS Records: {status.get('dns_records_count')}")
            else:
                print(
                    f"Failed to connect to blockchain node: {response.json().get('message')}"
                )

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_disconnect(self, arg):
        """Disconnect from a blockchain node: disconnect <node_url>"""
        node_url = arg.strip()
        if not node_url:
            print("Usage: disconnect <node_url>")
            return

        # Add http:// prefix if not present
        if not node_url.startswith("http://"):
            node_url = "http://" + node_url

        if node_url in self.blockchain_nodes:
            self.blockchain_nodes.remove(node_url)
            print(f"Disconnected from blockchain node at {node_url}")
        else:
            print(f"Not connected to {node_url}")

    def do_list_nodes(self, arg):
        """List all connected blockchain nodes"""
        if not self.blockchain_nodes:
            print("Not connected to any blockchain nodes.")
            return

        print("Connected blockchain nodes:")
        for i, node in enumerate(self.blockchain_nodes, 1):
            # Try to get status
            try:
                response = requests.get(f"{node}/node/status", timeout=2)
                if response.status_code == 200:
                    status = response.json()
                    print(
                        f"{i}. {node} - Node ID: {status.get('node_id')} - {'Validator' if status.get('is_validator') else 'Regular'}"
                    )
                else:
                    print(f"{i}. {node} - [Unavailable]")
            except:
                print(f"{i}. {node} - [Unavailable]")

    def do_exit(self, arg):
        """Exit the DNS client"""
        print("Exiting DNS client...")
        return True

    def do_clear_cache(self, arg):
        """Clear the local DNS cache"""
        self.cached_domains = {}
        print("Local DNS cache cleared.")

    def do_show_cache(self, arg):
        """Show the contents of the local DNS cache"""
        if not self.cached_domains:
            print("Local DNS cache is empty.")
            return

        print("Local DNS cache:")
        headers = ["Domain", "IP Address", "Expires At", "Status"]

        # Build table data
        table_data = []
        current_time = time.time()

        for domain, data in self.cached_domains.items():
            ip_address = data.get("ip_address", "N/A")
            expires_at = data.get("expires_at", 0)
            expires_at_str = time.ctime(expires_at)
            status = "Valid" if current_time < expires_at else "Expired"

            table_data.append([domain, ip_address, expires_at_str, status])

        # Sort by domain name
        table_data.sort(key=lambda x: x[0])

        # Print the table
        self._print_table(headers, table_data)

    def do_help_blockchain(self, arg):
        """Get help on blockchain concepts and commands"""
        print("\n🔗 Blockchain DNS Help")
        print("======================")
        print(
            "\nThis client interacts with a decentralized DNS system built on blockchain technology."
        )
        print("\nKey Concepts:")
        print("  • Blockchain: A distributed ledger storing all DNS records")
        print("  • Transactions: Operations like register, update, transfer, or renew")
        print("  • Blocks: Groups of transactions added to the blockchain")
        print("  • Validators: Special nodes that verify and add blocks")
        print("  • Consensus: How the network agrees on the valid blockchain state")
        print("\nBlockchain-specific commands:")
        print("  • node_status: View blockchain node status")
        print("  • block_info: Get information about a specific block")
        print("  • transaction_info: View details of your last transaction")
        print("\nDNS Management Commands:")
        print("  • register: Register a new domain name")
        print("  • resolve: Look up an IP address for a domain")
        print("  • update: Change a domain's IP address")
        print("  • transfer: Change domain ownership")
        print("  • renew: Extend domain registration")
        print("  • list_records: View all domains in the blockchain")

    def do_blockchain_stats(self, arg):
        """Show blockchain network statistics"""
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            # Get node status
            status_response = requests.get(f"{node}/node/status")

            # Get chain data
            chain_response = requests.get(f"{node}/chain")

            # Get DNS records
            records_response = requests.get(f"{node}/dns/records")

            if status_response.status_code == 200 and chain_response.status_code == 200:
                status = status_response.json()
                chain_info = chain_response.json()

                print("\n📊 Blockchain Network Statistics:")
                print("=" * 50)

                # Node information
                print(f"Node ID: {status.get('node_id')}")
                print(f"Node IP: {status.get('ip_address')}")
                print(
                    f"Role: {'Validator' if status.get('is_validator') else 'Regular'} node"
                )

                # Blockchain statistics
                print(f"\nChain Height: {status.get('chain_length')} blocks")
                print(f"Connected Peers: {status.get('peers_count')}")
                print(f"Validators: {len(status.get('validators', []))}")
                print(f"Pending Transactions: {status.get('pending_transactions')}")

                # Get the latest block
                if "last_block_hash" in status and "last_block_time" in status:
                    print(f"\nLatest Block: #{status.get('chain_length') - 1}")
                    print(f"  Hash: {status.get('last_block_hash')}")
                    print(f"  Time: {time.ctime(status.get('last_block_time'))}")

                    # Calculate time since last block
                    time_since = time.time() - status.get("last_block_time")
                    if time_since < 60:
                        print(f"  Age: {int(time_since)} seconds ago")
                    elif time_since < 3600:
                        print(f"  Age: {int(time_since/60)} minutes ago")
                    else:
                        print(f"  Age: {int(time_since/3600)} hours ago")

                # DNS statistics
                if records_response.status_code == 200:
                    records = records_response.json().get("dns_records", {})
                    print(f"\nTotal DNS Records: {len(records)}")

                    # Count domains by TLD
                    tlds = {}
                    for domain in records:
                        tld = domain.split(".")[-1] if "." in domain else "unknown"
                        tlds[tld] = tlds.get(tld, 0) + 1

                    if tlds:
                        print("\nDomains by TLD:")
                        for tld, count in sorted(
                            tlds.items(), key=lambda x: x[1], reverse=True
                        ):
                            print(f"  .{tld}: {count}")

                # Your records
                if records_response.status_code == 200:
                    records = records_response.json().get("dns_records", {})
                    own_records = [
                        d
                        for d, r in records.items()
                        if r.get("owner") == self.client_id
                    ]
                    print(f"\nYour Records: {len(own_records)} domains")

            else:
                print("Failed to retrieve blockchain statistics.")
                if status_response.status_code != 200:
                    print(f"Node status error: {status_response.json().get('message')}")
                if chain_response.status_code != 200:
                    print(f"Chain data error: {chain_response.json().get('message')}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_my_domains(self, arg):
        """List all domains owned by the current client"""
        if not self.client_id:
            print("No client ID set")
            return

        # Clear local cache to ensure fresh data
        self.cached_domains.clear()

        # Try each node until we get a response
        for node in self.blockchain_nodes:
            try:
                response = requests.get(f"{node}/dns/records", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    records = data.get("dns_records", {})

                    # Filter for domains owned by this client
                    my_domains = {
                        domain: record
                        for domain, record in records.items()
                        if record.get("owner") == self.client_id
                    }

                    if not my_domains:
                        print("You don't own any domains")
                        return

                    # Build table data
                    table_data = []
                    for domain, record in my_domains.items():
                        table_data.append(
                            [
                                domain,
                                record.get("ip_address", "N/A"),
                                time.strftime(
                                    "%Y-%m-%d %H:%M:%S",
                                    time.localtime(record.get("expires_at", 0)),
                                ),
                            ]
                        )

                    # Sort by domain name
                    table_data.sort(key=lambda x: x[0])

                    # Print table
                    self._print_table(["Domain", "IP Address", "Expires"], table_data)
                    return

            except requests.exceptions.RequestException as e:
                print(f"Error connecting to node {node}: {e}")
                continue

        print("Failed to fetch DNS records from any node")

    def do_lookup_ip(self, arg):
        """Find domains associated with an IP address: lookup_ip [ip_address]"""
        ip_addr = arg.strip()

        # If no IP provided, use local IP
        if not ip_addr:
            ip_addr = self._get_local_ip()
            if not ip_addr:
                print("Could not determine your IP address.")
                return

            print(f"Looking up domains for your IP address: {ip_addr}")
        else:
            # Validate IP address format
            if not self._validate_ip_address(ip_addr):
                print(f"Invalid IP address format: {ip_addr}")
                return

        # Find domains with this IP
        domains_found = {}

        # Try all nodes
        for node in self.blockchain_nodes:
            try:
                response = requests.get(f"{node}/dns/records", timeout=10)

                if response.status_code == 200:
                    records = response.json().get("dns_records", {})

                    for domain, record in records.items():
                        record_ip = record.get("ip_address")
                        if record_ip == ip_addr:
                            domains_found[domain] = record

                    if domains_found:  # If found domains, no need to check other nodes
                        break
            except:
                continue

        # If no domains found, try one more time with longer timeout
        if not domains_found and self.blockchain_nodes:
            try:
                random_node = random.choice(self.blockchain_nodes)
                response = requests.get(f"{random_node}/dns/records", timeout=15)

                if response.status_code == 200:
                    records = response.json().get("dns_records", {})

                    for domain, record in records.items():
                        record_ip = record.get("ip_address")
                        if record_ip == ip_addr:
                            domains_found[domain] = record
            except:
                pass

        # Display results
        if not domains_found:
            print(f"No domains found with IP address {ip_addr}.")
            return

        # Display domains in a table
        print(f"\n🔍 Found {len(domains_found)} domains with IP {ip_addr}:")

        headers = ["Domain", "Owner", "Registered", "Block #"]
        table_data = []
        owned_domains = []

        for domain, record in domains_found.items():
            owner = record.get("owner", "Unknown")
            is_owned = owner == self.client_id

            if is_owned:
                owned_domains.append(domain)
                owner_display = f"{owner} (You)"
            else:
                owner_display = owner

            registered_at = time.ctime(record.get("registered_at", 0))

            table_data.append(
                [
                    domain,
                    owner_display,
                    registered_at,
                    record.get("block_number", "?"),
                ]
            )

        # Sort by domain name
        table_data.sort(key=lambda x: x[0])

        # Print the table
        self._print_table(headers, table_data)

        # Show owned domains
        if owned_domains:
            print(
                f"\nYou own {len(owned_domains)} of these domains: {', '.join(owned_domains)}"
            )

    def _get_local_ip(self):
        """Get the local IP address of the client"""
        try:
            # Try socket approach first (most reliable method)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Doesn't need to be reachable, just triggers connection setup
            s.connect(("10.255.255.255", 1))
            ip_address = s.getsockname()[0]
            s.close()
            return ip_address
        except Exception as e:
            try:
                # Try alternate approach using standard socket functions
                hostname = socket.gethostname()
                ip_address = socket.gethostbyname(hostname)
                return ip_address
            except Exception as e:
                try:
                    # Last resort: check if we can connect to a blockchain node
                    # and see what IP the connection is coming from
                    node = self._get_random_node()
                    if node:
                        # Use connection to node to determine our IP
                        response = requests.get(f"{node}/node/status", timeout=5)
                        if response.status_code == 200:
                            # See if a peer connection reveals our IP
                            peers = response.json().get("peers", [])
                            # Extract potential IP addresses from peer URLs
                            for peer in peers:
                                if self.client_id in peer:
                                    # Extract IP from peer URL
                                    parts = peer.split("/")
                                    if len(parts) >= 3:
                                        host_port = parts[2].split(":")
                                        if len(host_port) >= 1:
                                            return host_port[0]
                except:
                    pass

                # If all else fails, return a localhost address
                return "127.0.0.1"

    def do_verify_transfer(self, arg):
        """Verify domain transfers to ensure ownership: verify_transfer <domain_name>"""
        domain_name = arg.strip()
        if not domain_name:
            print("Usage: verify_transfer <domain_name>")
            return

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print(f"Invalid domain name format: {domain_name}")
            return

        # Check if domain exists on the blockchain
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            # Resolve the domain to get current information
            response = requests.get(f"{node}/dns/resolve/{domain_name}", timeout=10)

            if response.status_code == 200:
                record = response.json()

                # Check if the current client is the owner
                if record.get("owner") == self.client_id:
                    print(f"✅ Verified: You are the current owner of {domain_name}")

                    # Print additional domain information
                    print(f"\n📋 Domain Information:")
                    print(f"IP Address: {record.get('ip_address', 'N/A')}")
                    if "registered_at" in record:
                        print(f"Registered: {time.ctime(record.get('registered_at'))}")
                    if "expires_at" in record:
                        expires_at = record.get("expires_at")
                        remaining_days = max(0, int((expires_at - time.time()) / 86400))
                        print(
                            f"Expires: {time.ctime(expires_at)} ({remaining_days} days remaining)"
                        )
                    if "block_number" in record:
                        print(f"Stored in block: #{record.get('block_number')}")

                    # Check recent transactions to see transfer history
                    try:
                        if "last_transaction_id" in record:
                            tx_id = record.get("last_transaction_id")
                            tx_response = requests.get(
                                f"{node}/transactions/{tx_id}", timeout=5
                            )

                            if tx_response.status_code == 200:
                                tx_data = tx_response.json()
                                transaction = tx_data.get("transaction", {})

                                if transaction.get("action") == "transfer":
                                    print(f"\n🔄 Recent Transfer Information:")
                                    print(
                                        f"Transferred from: {transaction.get('sender')}"
                                    )
                                    print(
                                        f"Transferred to: {transaction.get('new_owner')}"
                                    )
                                    print(
                                        f"Transaction time: {time.ctime(transaction.get('timestamp', 0))}"
                                    )
                    except Exception as e:
                        # Non-critical, can continue without this information
                        pass
                else:
                    previous_owner = record.get("owner", "Unknown")
                    print(f"❌ You are NOT the current owner of {domain_name}")
                    print(f"Current owner: {previous_owner}")

                    # Check if this domain was previously owned by this client
                    try:
                        if "last_transaction_id" in record:
                            tx_id = record.get("last_transaction_id")
                            tx_response = requests.get(
                                f"{node}/transactions/{tx_id}", timeout=5
                            )

                            if tx_response.status_code == 200:
                                tx_data = tx_response.json()
                                transaction = tx_data.get("transaction", {})

                                if (
                                    transaction.get("action") == "transfer"
                                    and transaction.get("sender") == self.client_id
                                ):
                                    print(
                                        f"\n⚠️ This domain was previously owned by you and transferred to {transaction.get('new_owner')}"
                                    )
                                    print(
                                        f"Transferred on: {time.ctime(transaction.get('timestamp', 0))}"
                                    )
                    except Exception as e:
                        # Non-critical, can continue without this information
                        pass

                    # Provide suggestions
                    print("\nOptions:")
                    print(
                        f"1. Contact the current owner ({previous_owner}) to request a transfer"
                    )
                    print(f"2. Register a different domain name")
                    self._suggest_similar_domains(domain_name)

            elif response.status_code == 404:
                print(f"Domain {domain_name} is not registered on the blockchain.")
                print("You can register it with the command:")
                print(f"  register {domain_name}")
            else:
                print(
                    f"Failed to verify domain: {response.json().get('message', 'Unknown error')}"
                )

        except requests.exceptions.ConnectionError:
            print(f"Connection error: Could not reach blockchain node at {node}")
        except requests.exceptions.Timeout:
            print(f"Connection timed out while reaching {node}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def _is_ip_in_valid_range(self, ip_addr):
        """Check if IP is in the expected network range and actually reachable"""
        try:
            ip = ip_address(ip_addr)
            # First check if in private address ranges typically used in this network
            if not (
                ip.is_private
                or str(ip).startswith("192.168.")
                or str(ip).startswith("10.")
                or str(ip).startswith("172.16.")
            ):
                return False

            # Now try to check if the IP is actually on the network by pinging
            if self._check_ip_pingable(ip_addr):
                return True

            # If ping fails, try to query a node for network status to see if IP is in list
            node = self._get_random_node()
            if node:
                try:
                    response = requests.get(f"{node}/peers", timeout=3)
                    if response.status_code == 200:
                        peers = response.json().get("peers", [])
                        for peer in peers:
                            if ip_addr in peer:
                                return True
                except:
                    pass

            # If we couldn't verify it's online but it's in a valid range, give it benefit of doubt
            return True

        except ValueError:
            return False

    def _check_ip_pingable(self, ip_addr):
        """Check if an IP address is pingable on the network (cross-platform)"""
        try:
            # Determine the appropriate ping command based on the OS
            import platform

            system = platform.system().lower()

            if system == "windows":
                # Windows ping uses -n for count and -w for timeout in milliseconds
                ping_cmd = f"ping -n 1 -w 1000 {ip_addr} > nul 2>&1"
            elif system in ["linux", "darwin"]:  # Linux or MacOS
                # Linux/MacOS ping uses -c for count and -W for timeout in seconds
                ping_cmd = f"ping -c 1 -W 1 {ip_addr} > /dev/null 2>&1"
            else:
                # Unknown OS, default to network connectivity test without ping
                try:
                    socket.create_connection((ip_addr, 80), timeout=1)
                    return True
                except:
                    return False

            response = os.system(ping_cmd)
            return response == 0
        except:
            # If any error occurs during ping, try a direct socket connection
            try:
                socket.create_connection((ip_addr, 80), timeout=1)
                return True
            except:
                return False

    def _get_node_status(self, node_url, timeout=3):
        """Get the status of a blockchain node with timeout"""
        try:
            response = requests.get(f"{node_url}/node/status", timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

    # Helper methods
    def _get_random_node(self):
        """Get a random blockchain node that is responsive"""
        if not self.blockchain_nodes:
            print("No blockchain nodes available")
            return None

        # Try each node in random order
        nodes = list(self.blockchain_nodes)
        random.shuffle(nodes)

        for node in nodes:
            try:
                # Check if node is responsive
                response = requests.get(f"{node}/node/status", timeout=5)
                if response.status_code == 200:
                    status = response.json()
                    if status.get("is_validator", False):
                        return node
            except:
                continue

        # If no validator nodes found, try any responsive node
        for node in nodes:
            try:
                response = requests.get(f"{node}/node/status", timeout=5)
                if response.status_code == 200:
                    return node
            except:
                continue

        print("No responsive blockchain nodes found")
        return None

    def _validate_domain_name(self, domain_name):
        """Validate domain name format using regex"""
        if not domain_name:
            return False
        return bool(self.DOMAIN_REGEX.match(domain_name))

    def _validate_ip_address(self, ip_addr):
        """Validate IP address format"""
        try:
            ip = ip_address(ip_addr)
            # Only accept IPv4 addresses for simplicity
            return isinstance(ip, IPv4Address)
        except ValueError:
            return False

    def _validate_node_url(self, url):
        """Validate blockchain node URL format"""
        # Simple URL validation
        url_pattern = re.compile(
            r"^http://([a-zA-Z0-9][-a-zA-Z0-9_.]*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:[0-9]{1,5})?$"
        )
        return bool(url_pattern.match(url))

    def _print_table(self, headers, data):
        """Print a formatted table without using external libraries"""
        if not data:
            return

        # Find the maximum width for each column
        col_widths = [len(h) for h in headers]
        for row in data:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))

        # Create format string for rows
        format_str = (
            "| " + " | ".join(["{:<" + str(w) + "}" for w in col_widths]) + " |"
        )

        # Create separator line
        separator = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"

        # Print table header
        print(separator)
        print(format_str.format(*headers))
        print(separator.replace("-", "="))

        # Print table rows
        for row in data:
            print(format_str.format(*[str(cell) for cell in row]))
        print(separator)

    def _check_domain_exists(self, domain_name):
        """Check if a domain exists in the blockchain"""
        if not domain_name:
            return False

        # Normalize domain name
        domain_name = self._normalize_domain(domain_name)

        # Try each node until we get a response
        for node in self.blockchain_nodes:
            try:
                # Try direct resolve first
                response = requests.get(f"{node}/dns/resolve/{domain_name}", timeout=5)
                if response.status_code == 200:
                    return True

                # If direct resolve fails, check DNS records
                response = requests.get(f"{node}/dns/records", timeout=5)
                if response.status_code == 200:
                    records = response.json().get("dns_records", {})
                    if domain_name in records:
                        return True

            except requests.exceptions.RequestException:
                continue

        return False

    def _check_domain_ownership(self, domain_name):
        """Check if the current client owns a domain"""
        if not domain_name or not self.client_id:
            return False

        # Normalize domain name
        domain_name = self._normalize_domain(domain_name)

        # Try each node until we get a response
        for node in self.blockchain_nodes:
            try:
                # Try direct resolve first
                response = requests.get(f"{node}/dns/resolve/{domain_name}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    return data.get("owner") == self.client_id

                # If direct resolve fails, check DNS records
                response = requests.get(f"{node}/dns/records", timeout=5)
                if response.status_code == 200:
                    records = response.json().get("dns_records", {})
                    if domain_name in records:
                        return records[domain_name].get("owner") == self.client_id

            except requests.exceptions.RequestException:
                continue

        return False

    def _update_cache(self, domain_name, ip_address):
        """Update the local DNS cache with a domain resolution"""
        normalized_domain = self._normalize_domain(domain_name)
        self.cached_domains[normalized_domain] = {
            "ip_address": ip_address,
            "expires_at": time.time() + 3600,  # Cache for 1 hour
        }

    def _refresh_cache_expiry(self, domain_name):
        """Refresh the expiry time for a cached domain"""
        normalized_domain = self._normalize_domain(domain_name)
        if normalized_domain in self.cached_domains:
            self.cached_domains[normalized_domain]["expires_at"] = (
                time.time() + 3600
            )  # Extend by 1 hour

    def _print_blockchain_info(self, response):
        """Print blockchain-related information from a response"""
        transaction = response.get("transaction", {})
        if transaction:
            print("\n🔗 Blockchain Transaction Details:")
            self._print_transaction_details(transaction)

        # Print additional blockchain info if available
        if "block_number" in response:
            print(
                f"Transaction will be included in block: {response.get('block_number')}"
            )
        if "chain_length" in response:
            print(f"Current blockchain length: {response.get('chain_length')} blocks")
        if "pending_transactions" in response:
            print(f"Pending transactions: {response.get('pending_transactions')}")

        # If we have a transaction, suggest viewing the transaction later
        if transaction and "transaction_id" in transaction:
            print(
                f"\nTip: Use 'transaction_info {transaction.get('transaction_id')}' to view this transaction after it's mined."
            )

    def _print_transaction_details(self, transaction):
        """Print details of a transaction"""
        if not transaction:
            print("No transaction details available.")
            return

        print(f"Action: {transaction.get('action', 'unknown')}")
        print(f"Domain: {transaction.get('domain_name', 'N/A')}")
        print(f"Sender: {transaction.get('sender', 'N/A')}")

        if transaction.get("ip_address"):
            print(f"IP Address: {transaction.get('ip_address')}")
        if transaction.get("new_owner"):
            print(f"New Owner: {transaction.get('new_owner')}")
        if transaction.get("timestamp"):
            print(f"Timestamp: {time.ctime(transaction.get('timestamp'))}")
        if transaction.get("transaction_id"):
            print(f"Transaction ID: {transaction.get('transaction_id')}")

        # Show transaction status if available
        print(
            f"Status: {'Pending' if transaction.get('pending', True) else 'Confirmed'}"
        )

        # If there's an estimated confirmation time, show it
        if "estimated_confirmation" in transaction:
            est_time = transaction.get("estimated_confirmation")
            if isinstance(est_time, (int, float)):
                print(f"Estimated confirmation: {time.ctime(est_time)}")
            else:
                print(f"Estimated confirmation: {est_time}")

    def _suggest_similar_domains(self, domain_name):
        """Suggest similar domains that exist in the blockchain"""
        if not domain_name:
            return

        # Normalize the domain name
        normalized_domain = self._normalize_domain(domain_name)

        # Split the domain into base name and TLD if possible
        parts = normalized_domain.split(".")
        if len(parts) != 2:
            return

        base_name, tld = parts

        # Get all domain records from all nodes
        all_domains = {}

        for node in self.blockchain_nodes:
            try:
                response = requests.get(f"{node}/dns/records", timeout=10)
                if response.status_code == 200:
                    records = response.json().get("dns_records", {})

                    # Merge with existing records
                    for domain, record in records.items():
                        if domain not in all_domains:
                            all_domains[domain] = record

                    if all_domains:  # If we have records, no need to check more nodes
                        break
            except:
                continue

        # If we couldn't get any records, try one more node with longer timeout
        if not all_domains and self.blockchain_nodes:
            try:
                random_node = random.choice(self.blockchain_nodes)
                response = requests.get(f"{random_node}/dns/records", timeout=15)
                if response.status_code == 200:
                    all_domains = response.json().get("dns_records", {})
            except:
                pass

        if not all_domains:
            return  # No domains found

        # Look for similar domains
        similar_domains = []
        available_suggestions = []

        for existing_domain in all_domains.keys():
            # Normalize for consistent comparison
            norm_existing = self._normalize_domain(existing_domain)

            try:
                existing_parts = norm_existing.split(".")
                if len(existing_parts) != 2:
                    continue

                existing_base, existing_tld = existing_parts

                # Check for similarity
                distance = self._levenshtein_distance(base_name, existing_base)
                if existing_tld == tld and (
                    existing_base.startswith(base_name[:2])
                    or base_name.startswith(existing_base[:2])
                    or distance <= 2
                ):
                    similar_domains.append((existing_domain, distance))
            except:
                continue

        # Sort by similarity (lower distance first)
        similar_domains.sort(key=lambda x: x[1])

        # Generate alternative domain suggestions
        tld_options = [".com", ".net", ".org", ".io", ".app"]

        # Try different TLDs
        for alt_tld in tld_options:
            if alt_tld != "." + tld:
                alt_domain = base_name + alt_tld
                if alt_domain not in all_domains:
                    available_suggestions.append(alt_domain)

        # Try adding prefixes
        prefixes = ["my", "the", "get", "app"]
        for prefix in prefixes:
            alt_domain = prefix + base_name + "." + tld
            if alt_domain not in all_domains:
                available_suggestions.append(alt_domain)

        # Display similar existing domains
        if similar_domains:
            print("\nSimilar domains that already exist:")
            for i, (domain, _) in enumerate(similar_domains[:5], 1):
                record = all_domains.get(domain, {})
                owner = record.get("owner", "Unknown")
                owner_display = f"{owner} (You)" if owner == self.client_id else owner
                print(
                    f"  {i}. {domain} -> {record.get('ip_address', 'N/A')} (Owner: {owner_display})"
                )

        # Display available alternatives
        if available_suggestions:
            print("\nAvailable alternative domains you can register:")
            for i, domain in enumerate(available_suggestions[:5], 1):
                print(f"  {i}. {domain}")
            print("You can register any of these with: register <domain_name>")

    def _levenshtein_distance(self, s1, s2):
        """Calculate the Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def do_verbose(self, arg):
        """Toggle verbose output mode: verbose [on|off]"""
        if arg.lower() in ["on", "true", "1", "yes", "y"]:
            self.verbose = True
            print("Verbose mode enabled. Detailed debugging output will be shown.")
        elif arg.lower() in ["off", "false", "0", "no", "n"]:
            self.verbose = False
            print("Verbose mode disabled.")
        else:
            # Toggle current state
            self.verbose = not self.verbose
            print(f"Verbose mode {'enabled' if self.verbose else 'disabled'}.")

    def _debug(self, message):
        """Print debug message if verbose mode is enabled"""
        if self.verbose:
            print(f"DEBUG: {message}")

    def get_names(self):
        """Hide specified commands from help menu"""
        names = super().get_names()
        return [
            n
            for n in names
            if n
            not in [
                "do_update",
                "do_list_nodes",
                "do_verbose",
                "do_my_domains",
                "do_list_records",
                "do_transfer",
                "do_connect",
                "do_disconnect",
            ]
        ]

    def _update_domain(self, domain_name, ip_address):
        """Internal method to update domain IP address"""
        if not self._check_domain_exists(domain_name):
            print(f"Domain {domain_name} does not exist.")
            return False

        if not self._check_domain_ownership(domain_name):
            print(f"You don't own the domain {domain_name}.")
            return False

        # Validate IP address
        if not self._validate_ip_address(ip_address):
            print(f"Invalid IP address: {ip_address}")
            return False

        # Try update on all nodes until success
        success = False
        for node in self.blockchain_nodes:
            try:
                response = requests.post(
                    f"{node}/dns/update",
                    json={
                        "sender": self.client_id,
                        "domain_name": domain_name,
                        "ip_address": ip_address,
                    },
                    timeout=10,
                )

                if response.status_code == 201:
                    transaction = response.json().get("transaction", {})
                    print(f"\n✅ Update initiated for {domain_name}")
                    print(f"New IP: {ip_address}")
                    print(f"Transaction ID: {transaction.get('transaction_id')}")
                    success = True
                    break
            except requests.exceptions.RequestException:
                continue

        return success


def main():
    parser = argparse.ArgumentParser(description="Decentralized DNS Client")
    parser.add_argument("--nodes", nargs="+", help="Blockchain node URLs")
    parser.add_argument("--id", type=str, help="Client ID")
    args = parser.parse_args()

    # Initialize the blockchain node URLs
    nodes = args.nodes or []
    nodes = [
        "http://" + node if not node.startswith("http://") else node for node in nodes
    ]

    # Create and start the DNS client shell
    client_shell = DNSClientShell(blockchain_nodes=nodes, client_id=args.id)
    client_shell.cmdloop()


if __name__ == "__main__":
    main()
