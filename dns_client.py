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
from tabulate import tabulate


class DNSClientShell(cmd.Cmd):
    intro = (
        "Welcome to the Decentralized DNS Client. Type help or ? to list commands.\n"
    )
    prompt = "dns> "

    def __init__(self, blockchain_nodes=None, client_id=None):
        super(DNSClientShell, self).__init__()
        self.blockchain_nodes = blockchain_nodes or []
        self.client_id = client_id or f"client_{random.randint(1000, 9999)}"
        self.cached_domains = {}  # Local DNS cache
        self.cache_expiry = {}  # Expiry times for cached domains

        # Initialize the client
        print(f"Initialized DNS client with ID: {self.client_id}")
        print(f"Connected to blockchain nodes: {', '.join(self.blockchain_nodes)}")

    def do_register(self, arg):
        """Register a new domain name: register <domain_name> <ip_address>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: register <domain_name> <ip_address>")
            return

        domain_name, ip_address = args

        # Validate IP address
        try:
            socket.inet_aton(ip_address)
        except socket.error:
            print(f"Invalid IP address: {ip_address}")
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
            )

            if response.status_code == 201:
                print(
                    f"Domain {domain_name} registered successfully with IP {ip_address}"
                )
                print(f"Transaction created: {response.json().get('transaction')}")
            else:
                print(f"Failed to register domain: {response.json().get('message')}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_update(self, arg):
        """Update an existing domain's IP address: update <domain_name> <new_ip_address>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: update <domain_name> <new_ip_address>")
            return

        domain_name, ip_address = args

        # Validate IP address
        try:
            socket.inet_aton(ip_address)
        except socket.error:
            print(f"Invalid IP address: {ip_address}")
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
            )

            if response.status_code == 201:
                print(f"Domain {domain_name} updated with new IP {ip_address}")
                print(f"Transaction created: {response.json().get('transaction')}")

                # Update local cache
                if domain_name in self.cached_domains:
                    self.cached_domains[domain_name] = ip_address
            else:
                print(f"Failed to update domain: {response.json().get('message')}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_transfer(self, arg):
        """Transfer domain ownership: transfer <domain_name> <new_owner_id>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: transfer <domain_name> <new_owner_id>")
            return

        domain_name, new_owner = args

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
            )

            if response.status_code == 201:
                print(f"Domain {domain_name} transferred to {new_owner}")
                print(f"Transaction created: {response.json().get('transaction')}")

                # Remove from local cache
                if domain_name in self.cached_domains:
                    del self.cached_domains[domain_name]
                    del self.cache_expiry[domain_name]
            else:
                print(f"Failed to transfer domain: {response.json().get('message')}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

    def do_renew(self, arg):
        """Renew a domain's registration: renew <domain_name>"""
        domain_name = arg.strip()
        if not domain_name:
            print("Usage: renew <domain_name>")
            return

        # Send renew request to a random node
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.post(
                f"{node}/dns/renew",
                json={"sender": self.client_id, "domain_name": domain_name},
            )

            if response.status_code == 201:
                print(f"Domain {domain_name} renewed successfully")
                print(f"Transaction created: {response.json().get('transaction')}")
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

        # Check local cache first
        if domain_name in self.cached_domains and time.time() < self.cache_expiry.get(
            domain_name, 0
        ):
            print(
                f"Domain {domain_name} resolved to {self.cached_domains[domain_name]} (from cache)"
            )
            return

        # If not in cache or expired, query the blockchain
        node = self._get_random_node()
        if not node:
            print("No blockchain nodes available.")
            return

        try:
            response = requests.get(f"{node}/dns/resolve/{domain_name}")

            if response.status_code == 200:
                ip_address = response.json().get("ip_address")
                print(f"Domain {domain_name} resolved to {ip_address}")

                # Cache the result for 1 hour
                self.cached_domains[domain_name] = ip_address
                self.cache_expiry[domain_name] = time.time() + 3600
            else:
                print(f"Failed to resolve domain: {response.json().get('message')}")

        except requests.exceptions.RequestException as e:
            print(f"Error connecting to blockchain node: {e}")

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

                if not records:
                    print("No DNS records found.")
                    return

                # Format the records for display
                table_data = []
                headers = ["Domain", "IP Address", "Owner", "Expires At"]

                for domain, record in records.items():
                    expires_at = time.ctime(record.get("expires_at", 0))
                    table_data.append(
                        [
                            domain,
                            record.get("ip_address", "N/A"),
                            record.get("owner", "N/A"),
                            expires_at,
                        ]
                    )

                print(tabulate(table_data, headers=headers, tablefmt="grid"))
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

                print("Blockchain Node Status:")
                print(f"Node ID: {status.get('node_id')}")
                print(f"Is Validator: {status.get('is_validator')}")
                print(f"Connected Peers: {status.get('peers_count')}")
                print(f"Chain Length: {status.get('chain_length')}")
                print(f"Pending Transactions: {status.get('pending_transactions')}")
                print(f"DNS Records Count: {status.get('dns_records_count')}")
            else:
                print(
                    f"Failed to retrieve node status: {response.json().get('message')}"
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

        # Check if already connected
        if node_url in self.blockchain_nodes:
            print(f"Already connected to {node_url}")
            return

        # Try to connect to the node
        try:
            response = requests.get(f"{node_url}/node/status")

            if response.status_code == 200:
                self.blockchain_nodes.append(node_url)
                print(f"Successfully connected to blockchain node at {node_url}")
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
            print(f"{i}. {node}")

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
        headers = ["Domain", "IP Address", "Expires At"]

        current_time = time.time()
        for domain, ip in self.cached_domains.items():
            expires_at = self.cache_expiry.get(domain, 0)
            status = "Valid" if current_time < expires_at else "Expired"
            expires_at_str = time.ctime(expires_at)

            table_data.append([domain, ip, f"{expires_at_str} ({status})"])

        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    def _get_random_node(self):
        """Get a random blockchain node from the connected nodes"""
        if not self.blockchain_nodes:
            return None
        return random.choice(self.blockchain_nodes)


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
