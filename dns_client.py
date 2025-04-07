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
        self.cached_domains = {}  # Local DNS cache
        self.cache_expiry = {}  # Expiry times for cached domains
        self.last_transaction = None  # Store the last transaction for reference

        # Initialize the client
        print(f"Initialized DNS client with ID: {self.client_id}")
        print(f"Connected to blockchain nodes: {', '.join(self.blockchain_nodes)}")

    def do_register(self, arg):
        """Register a new domain name: register <domain_name>"""
        domain_name = arg.strip()
        if not domain_name:
            print("Usage: register <domain_name>")
            return

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print(f"Invalid domain name format: {domain_name}")
            print("Domain names must follow standard format (e.g., example.com)")
            return

        # Check if domain already exists in cache or on blockchain
        if domain_name in self.cached_domains:
            print(f"Domain {domain_name} already exists in your local cache.")
            print(f"If you believe this is an error, use 'clear_cache' and try again.")
            return

        # Check if domain already exists on the blockchain
        if self._check_domain_exists(domain_name):
            print(f"Domain {domain_name} is already registered on the blockchain.")
            self._suggest_similar_domains(domain_name)
            return

        # Get client's IP address from the request
        try:
            # First try to get the IP from the request
            response = requests.get("https://api.ipify.org?format=json", timeout=5)
            if response.status_code == 200:
                ip_address = response.json()["ip"]
                print(f"Detected your IP address: {ip_address}")
            else:
                print("Warning: Could not automatically detect your IP address")
                return
        except requests.exceptions.RequestException as e:
            print(f"Error detecting IP address: {e}")
            return

        # Validate IP address
        if not self._validate_ip_address(ip_address):
            print(f"Invalid IP address detected: {ip_address}")
            return

        # Verify IP is in the expected network range
        if not self._is_ip_in_valid_range(ip_address):
            print(
                f"Warning: Your IP address {ip_address} may not be in the expected network range."
            )
            print(
                "This could happen if you're not connected to the same network as the blockchain nodes."
            )
            print("The domain may not be properly resolvable on the network.")
            confirm = input("Do you want to continue anyway? (y/n): ")
            if confirm.lower() not in ["y", "yes"]:
                return

        # Send registration request to a random node
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.post(
                f"{node}/dns/register",
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

                print(
                    f"Domain {domain_name} registered successfully with IP {ip_address}"
                )

                # Display blockchain information
                self._print_blockchain_info(json_response)

                # Cache the result
                self._update_cache(domain_name, ip_address)
            elif response.status_code == 400:
                # Check specific error cases
                message = response.json().get("message", "")
                if "already registered" in message.lower():
                    print(
                        f"Domain {domain_name} is already registered on the blockchain."
                    )
                else:
                    print(f"Failed to register domain: {message}")
            else:
                print(
                    f"Failed to register domain: {response.json().get('message', 'Unknown error')}"
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

        # First check if domain exists
        if not self._check_domain_exists(domain_name):
            print(
                f"Domain {domain_name} does not exist. Cannot transfer non-existent domain."
            )
            return

        # Check if domain belongs to this client
        if not self._check_domain_ownership(domain_name):
            print(
                f"You don't own the domain {domain_name}. Only the owner can transfer it."
            )
            return

        # Validate new owner ID format (simple check)
        if not new_owner or len(new_owner) < 3:
            print(f"Invalid new owner ID: {new_owner}")
            print("Owner ID should be at least 3 characters long.")
            return

        # Check for special cases
        if new_owner == self.client_id:
            print("You are already the owner of this domain. Transfer cancelled.")
            return

        # Double-check with important warning
        print("\n⚠️ IMPORTANT: Domain transfers are permanent and cannot be reversed!")
        print(f"You are about to transfer '{domain_name}' to user '{new_owner}'.")
        print("After transfer, you will no longer have control over this domain.")

        # Confirm transfer with additional verification
        confirm = input(f"Type the domain name '{domain_name}' to confirm transfer: ")
        if confirm != domain_name:
            print("Transfer cancelled: Domain name does not match.")
            return

        # Send transfer request to a random node
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

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
                json_response = response.json()
                self.last_transaction = json_response.get("transaction")

                print(f"\n✅ Domain {domain_name} transferred to {new_owner}")

                # Display blockchain information
                self._print_blockchain_info(json_response)

                # Explain what happens next
                print(f"\nThe transfer will be processed in the next block.")
                print(
                    f"The new owner ({new_owner}) now has full control of this domain."
                )

                # Remove from local cache
                if domain_name in self.cached_domains:
                    del self.cached_domains[domain_name]
                    if domain_name in self.cache_expiry:
                        del self.cache_expiry[domain_name]
            else:
                print(
                    f"Failed to transfer domain: {response.json().get('message', 'Unknown error')}"
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
        """Resolve a domain name to an IP address: resolve <domain_name>"""
        domain_name = arg.strip()
        if not domain_name:
            print("Usage: resolve <domain_name>")
            return

        # Validate domain name format
        if not self._validate_domain_name(domain_name):
            print(f"Invalid domain name format: {domain_name}")
            return

        # Check local cache first
        if domain_name in self.cached_domains and time.time() < self.cache_expiry.get(
            domain_name, 0
        ):
            print(
                f"Domain {domain_name} resolved to {self.cached_domains[domain_name]} (from cache)"
            )
            print(f"Cache expires: {time.ctime(self.cache_expiry.get(domain_name, 0))}")
            return

        # If not in cache or expired, query the blockchain
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/dns/resolve/{domain_name}", timeout=10)

            if response.status_code == 200:
                json_response = response.json()
                ip_address = json_response.get("ip_address")

                print(f"\n📋 Domain Information:")
                print(f"Domain: {domain_name}")
                print(f"IP Address: {ip_address}")

                # Display detailed blockchain information
                print(f"\n🔗 Blockchain Record Details:")
                if "owner" in json_response:
                    print(f"Owner: {json_response.get('owner')}")
                if "registered_at" in json_response:
                    print(
                        f"Registered: {time.ctime(json_response.get('registered_at'))}"
                    )
                if "expires_at" in json_response:
                    expires_at = json_response.get("expires_at")
                    remaining_days = max(0, int((expires_at - time.time()) / 86400))
                    print(
                        f"Expires: {time.ctime(expires_at)} ({remaining_days} days remaining)"
                    )
                if "last_update" in json_response:
                    print(
                        f"Last updated: {time.ctime(json_response.get('last_update'))}"
                    )
                if "block_number" in json_response:
                    print(f"Stored in block: #{json_response.get('block_number')}")
                if "last_transaction_id" in json_response:
                    tx_id = json_response.get("last_transaction_id")
                    print(f"Last transaction: {tx_id}")
                    print(
                        f"Tip: Use 'transaction_info {tx_id}' to view transaction details"
                    )

                # Cache the result for 1 hour
                self._update_cache(domain_name, ip_address)
            elif response.status_code == 404:
                print(f"Domain {domain_name} not found or expired.")
                # Suggest similar domains if available
                self._suggest_similar_domains(domain_name)
            else:
                print(
                    f"Failed to resolve domain: {response.json().get('message', 'Unknown error')}"
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

    def do_list_records(self, arg):
        """List all DNS records in the blockchain"""
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/dns/records")

            if response.status_code == 200:
                records = response.json().get("dns_records", {})
                blockchain_info = response.json().get("blockchain_info", {})

                if not records:
                    print("No DNS records found.")
                    return

                # Format the records for display
                table_data = []
                headers = [
                    "Domain",
                    "IP Address",
                    "Owner",
                    "Block #",
                    "TX ID",
                    "Expires",
                ]

                for domain, record in records.items():
                    expires_at = time.ctime(record.get("expires_at", 0))
                    remaining_days = max(
                        0, int((record.get("expires_at", 0) - time.time()) / 86400)
                    )
                    tx_id = record.get("last_transaction_id", "N/A")
                    # Truncate transaction ID for better display
                    if len(tx_id) > 12:
                        tx_id = tx_id[:8] + "..."

                    table_data.append(
                        [
                            domain,
                            record.get("ip_address", "N/A"),
                            record.get("owner", "N/A"),
                            record.get("block_number", "N/A"),
                            tx_id,
                            f"{remaining_days}d left",
                        ]
                    )

                print(tabulate(table_data, headers=headers, tablefmt="grid"))

                # Display blockchain information if available
                if blockchain_info:
                    print("\n🔗 Blockchain Information:")
                    print(
                        f"Current Block: #{blockchain_info.get('current_block', 'N/A')}"
                    )
                    print(
                        f"Chain Length: {blockchain_info.get('chain_length', 'N/A')} blocks"
                    )
                    print(
                        f"Last Update: {time.ctime(blockchain_info.get('last_update', time.time()))}"
                    )

                # Display information about your domains
                own_domains = [
                    domain
                    for domain, record in records.items()
                    if record.get("owner") == self.client_id
                ]
                if own_domains:
                    print(
                        f"\nYou own {len(own_domains)} domain(s): {', '.join(own_domains)}"
                    )

                # Show soon-to-expire domains
                soon_expire = []
                for domain, record in records.items():
                    days_left = max(
                        0, int((record.get("expires_at", 0) - time.time()) / 86400)
                    )
                    if days_left < 30 and record.get("owner") == self.client_id:
                        soon_expire.append((domain, days_left))

                if soon_expire:
                    print("\n⚠️ Domains expiring soon:")
                    for domain, days in sorted(soon_expire, key=lambda x: x[1]):
                        print(f"  • {domain}: {days} days left")
            else:
                print(
                    f"Failed to retrieve DNS records: {response.json().get('message')}"
                )

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

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
        self.cache_expiry = {}
        print("Local DNS cache cleared.")

    def do_show_cache(self, arg):
        """Show the contents of the local DNS cache"""
        if not self.cached_domains:
            print("Local DNS cache is empty.")
            return

        print("Local DNS cache:")
        table_data = []
        headers = ["Domain", "IP Address", "Expires At", "Status"]

        current_time = time.time()
        for domain, ip in self.cached_domains.items():
            expires_at = self.cache_expiry.get(domain, 0)
            status = "Valid" if current_time < expires_at else "Expired"
            expires_at_str = time.ctime(expires_at)

            table_data.append([domain, ip, expires_at_str, status])

        print(tabulate(table_data, headers=headers, tablefmt="grid"))

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
        """List all domains associated with your client ID"""
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/dns/records", timeout=10)

            if response.status_code == 200:
                records = response.json().get("dns_records", {})

                own_domains = {
                    domain: record
                    for domain, record in records.items()
                    if record.get("owner") == self.client_id
                }

                if not own_domains:
                    print("You don't own any domains.")
                    return

                # Display domains in a table
                print(f"\nYou own {len(own_domains)} domains:")

                table_data = []
                headers = ["Domain", "IP Address", "Registered", "Expires", "Block #"]

                for domain, record in own_domains.items():
                    registered = time.ctime(record.get("registered_at", 0))
                    expires = time.ctime(record.get("expires_at", 0))
                    remaining = max(
                        0, int((record.get("expires_at", 0) - time.time()) / 86400)
                    )

                    table_data.append(
                        [
                            domain,
                            record.get("ip_address", "N/A"),
                            registered,
                            f"{expires} ({remaining} days left)",
                            record.get("block_number", "N/A"),
                        ]
                    )

                print(tabulate(table_data, headers=headers, tablefmt="grid"))

                # Show expiring domains
                expiring_soon = [
                    (domain, record.get("expires_at", 0))
                    for domain, record in own_domains.items()
                    if record.get("expires_at", 0) - time.time() < 30 * 86400  # 30 days
                ]

                if expiring_soon:
                    print("\n⚠️ Domains expiring soon:")
                    for domain, expires_at in sorted(expiring_soon, key=lambda x: x[1]):
                        days_left = max(0, int((expires_at - time.time()) / 86400))
                        print(
                            f"  • {domain}: {days_left} days left (expires {time.ctime(expires_at)})"
                        )
                        print(f"    To renew: renew {domain}")
            else:
                print(
                    f"Failed to retrieve DNS records: {response.json().get('message', 'Unknown error')}"
                )

        except requests.exceptions.ConnectionError:
            print(f"Connection error: Could not reach blockchain node at {node}")
        except requests.exceptions.Timeout:
            print(f"Connection timed out while reaching {node}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

    def do_lookup_ip(self, arg):
        """Find domains associated with an IP address: lookup_ip [ip_address]
        If no IP is provided, it will look up domains for your current IP address."""
        ip_address = arg.strip()

        # If no IP provided, get the client's current IP
        if not ip_address:
            try:
                response = requests.get("https://api.ipify.org?format=json", timeout=5)
                if response.status_code == 200:
                    ip_address = response.json()["ip"]
                    print(f"Looking up domains for your IP address: {ip_address}")
                else:
                    print(
                        "Could not detect your IP address. Please provide an IP address."
                    )
                    return
            except requests.exceptions.RequestException as e:
                print(f"Error detecting IP address: {e}")
                return

        # Validate IP address
        if not self._validate_ip_address(ip_address):
            print(f"Invalid IP address format: {ip_address}")
            return

        # Query the blockchain for domains with this IP
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/dns/records", timeout=10)

            if response.status_code == 200:
                records = response.json().get("dns_records", {})

                matching_domains = {
                    domain: record
                    for domain, record in records.items()
                    if record.get("ip_address") == ip_address
                }

                if not matching_domains:
                    print(f"No domains found with IP address {ip_address}")
                    return

                # Display the domains in a table
                print(
                    f"\n🔍 Found {len(matching_domains)} domains with IP {ip_address}:"
                )

                table_data = []
                headers = ["Domain", "Owner", "Registered", "Block #"]

                for domain, record in matching_domains.items():
                    registered = time.ctime(record.get("registered_at", 0))
                    is_yours = record.get("owner") == self.client_id
                    owner = record.get("owner", "Unknown")
                    if is_yours:
                        owner = f"{owner} (You)"

                    table_data.append(
                        [domain, owner, registered, record.get("block_number", "N/A")]
                    )

                print(tabulate(table_data, headers=headers, tablefmt="grid"))

                # If any domains are owned by the current client, highlight them
                own_domains = [
                    domain
                    for domain, record in matching_domains.items()
                    if record.get("owner") == self.client_id
                ]

                if own_domains:
                    print(
                        f"\nYou own {len(own_domains)} of these domains: {', '.join(own_domains)}"
                    )

            else:
                print(
                    f"Failed to retrieve DNS records: {response.json().get('message', 'Unknown error')}"
                )

        except requests.exceptions.ConnectionError:
            print(f"Connection error: Could not reach blockchain node at {node}")
        except requests.exceptions.Timeout:
            print(f"Connection timed out while reaching {node}")
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

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
        """Get a random blockchain node from the connected nodes"""
        if not self.blockchain_nodes:
            return None

        # Try nodes in random order until we find one that responds
        available_nodes = list(self.blockchain_nodes)
        random.shuffle(available_nodes)

        for node in available_nodes:
            if self._get_node_status(node, timeout=2):
                return node

        print("Warning: No responsive blockchain nodes found!")
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

    def _check_domain_exists(self, domain_name):
        """Check if a domain exists in the blockchain with improved error handling"""
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return False

        try:
            # Try to get the domain from the blockchain's DNS records endpoint first
            # This is more efficient as it avoids potential timeouts with resolve endpoint
            records_response = requests.get(f"{node}/dns/records", timeout=5)

            if records_response.status_code == 200:
                records = records_response.json().get("dns_records", {})
                if domain_name in records:
                    # Check if the domain is expired
                    record = records[domain_name]
                    if record.get("expires_at", 0) > time.time():
                        return True
                    else:
                        # Domain exists but is expired
                        return False
                else:
                    # Domain not found in records
                    return False

            # Fallback to the direct resolve endpoint if records approach fails
            response = requests.get(f"{node}/dns/resolve/{domain_name}", timeout=5)
            return response.status_code == 200

        except requests.exceptions.Timeout:
            print(f"Timeout checking domain existence: {domain_name}")
            return False
        except requests.exceptions.ConnectionError:
            print(f"Connection error checking domain: {domain_name}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Error checking domain existence: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error checking domain: {e}")
            return False

    def _check_domain_ownership(self, domain_name):
        """Check if the current client owns a domain with improved error handling"""
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return False

        try:
            # First try the direct resolve endpoint which is faster
            resolve_response = requests.get(
                f"{node}/dns/resolve/{domain_name}", timeout=5
            )

            if resolve_response.status_code == 200:
                record = resolve_response.json()
                if record.get("owner") == self.client_id:
                    # Also check if the domain is expired
                    if record.get("expires_at", 0) > time.time():
                        return True
                    else:
                        print(
                            f"Domain {domain_name} has expired. Please renew it first."
                        )
                        return False
                return False
            elif resolve_response.status_code == 404:
                # Domain doesn't exist
                return False

            # Fallback to checking all records if direct resolve fails
            records_response = requests.get(f"{node}/dns/records", timeout=5)

            if records_response.status_code == 200:
                records = records_response.json().get("dns_records", {})
                if domain_name in records:
                    record = records[domain_name]
                    # Check both ownership and expiration
                    is_owner = record.get("owner") == self.client_id
                    is_expired = record.get("expires_at", 0) <= time.time()

                    if is_owner and is_expired:
                        print(
                            f"Domain {domain_name} has expired. Please renew it first."
                        )

                    return is_owner and not is_expired
                return False
            else:
                print(
                    f"Unexpected response checking domain ownership: {records_response.status_code}"
                )
                return False

        except requests.exceptions.Timeout:
            print(f"Timeout checking domain ownership: {domain_name}")
            return False
        except requests.exceptions.ConnectionError:
            print(f"Connection error checking ownership: {domain_name}")
            return False
        except requests.exceptions.RequestException as e:
            print(f"Error checking domain ownership: {e}")
            return False
        except Exception as e:
            print(f"Unexpected error checking ownership: {e}")
            return False

    def _update_cache(self, domain_name, ip_address):
        """Update the local DNS cache with a domain resolution"""
        self.cached_domains[domain_name] = ip_address
        self.cache_expiry[domain_name] = time.time() + 3600  # Cache for 1 hour

    def _refresh_cache_expiry(self, domain_name):
        """Refresh the expiry time for a cached domain"""
        if domain_name in self.cache_expiry:
            self.cache_expiry[domain_name] = time.time() + 3600  # Extend by 1 hour

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
        parts = domain_name.split(".")
        if len(parts) != 2:
            return

        base_name, tld = parts

        node = self._get_random_node()
        if not node:
            return

        try:
            response = requests.get(f"{node}/dns/records", timeout=5)
            if response.status_code == 200:
                records = response.json().get("dns_records", {})

                # Look for similar domains
                similar_domains = []
                for existing_domain in records.keys():
                    try:
                        existing_parts = existing_domain.split(".")
                        if len(existing_parts) != 2:
                            continue

                        existing_base, existing_tld = existing_parts

                        # Check for similarity
                        if existing_tld == tld and (
                            existing_base.startswith(base_name[:3])
                            or base_name.startswith(existing_base[:3])
                            or self._levenshtein_distance(base_name, existing_base) <= 2
                        ):
                            similar_domains.append(existing_domain)
                    except Exception as e:
                        print(f"Error processing domain {existing_domain}: {e}")
                        continue

                # Display similar domains
                if similar_domains:
                    print("\nSimilar domains that exist:")
                    for i, domain in enumerate(similar_domains[:5], 1):
                        try:
                            print(
                                f"  {i}. {domain} -> {records[domain].get('ip_address', 'N/A')}"
                            )
                        except Exception as e:
                            print(f"Error displaying domain {domain}: {e}")
            else:
                print(f"Error fetching records: {response.status_code}")
        except requests.exceptions.Timeout:
            print("Timeout while fetching records for suggestions")
        except requests.exceptions.ConnectionError:
            print("Connection error while fetching records")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching records for suggestions: {e}")
        except Exception as e:
            print(f"Unexpected error suggesting similar domains: {e}")

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
