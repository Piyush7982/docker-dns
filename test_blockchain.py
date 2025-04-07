#!/usr/bin/env python3
import argparse
import requests
import time
import random
import json


def register_domain(node_url, client_id, domain, ip_address=None):
    """Register a domain on the blockchain"""
    try:
        # IP address is now optional as server detects it automatically
        # If provided, it will be ignored by the server
        transaction = {"sender": client_id, "domain_name": domain}

        # Include IP in message for backwards compatibility
        # but it will be ignored by the updated server
        if ip_address:
            print(
                f"Note: IP address {ip_address} provided but will be ignored as server auto-detects client IP"
            )
            transaction["ip_address"] = (
                ip_address  # For backwards compatibility with older servers
            )

        response = requests.post(
            f"{node_url}/dns/register",
            json=transaction,
        )

        if response.status_code == 201:
            transaction_data = response.json().get("transaction", {})
            detected_ip = transaction_data.get("ip_address")
            print(f"✅ Domain {domain} registered")
            if detected_ip:
                print(f"Server detected IP: {detected_ip}")
            print(f"Transaction ID: {transaction_data.get('transaction_id')}")
            return True
        else:
            print(f"❌ Failed to register domain: {response.json().get('message')}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to node: {e}")
        return False


def resolve_domain(node_url, domain):
    """Resolve a domain from the blockchain"""
    try:
        response = requests.get(f"{node_url}/dns/resolve/{domain}")

        if response.status_code == 200:
            result = response.json()
            print(f"✅ Domain {domain} resolved to {result.get('ip_address')}")
            print(f"Owner: {result.get('owner')}")
            if "block_number" in result:
                print(f"Block: {result.get('block_number')}")
            return result.get("ip_address")
        else:
            print(f"❌ Failed to resolve domain: {response.json().get('message')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to node: {e}")
        return None


def check_blockchain_status(node_url):
    """Check the status of the blockchain"""
    try:
        response = requests.get(f"{node_url}/node/status")

        if response.status_code == 200:
            status = response.json()
            print("\n📊 Blockchain Status:")
            print(f"Node ID: {status.get('node_id')}")
            print(f"Is Validator: {status.get('is_validator')}")
            print(f"Chain Length: {status.get('chain_length')} blocks")
            print(f"Connected Peers: {status.get('peers_count')}")
            print(f"Validators: {len(status.get('validators', []))}")
            print(f"DNS Records: {status.get('dns_records_count')}")
            return status
        else:
            print(
                f"❌ Failed to get blockchain status: {response.json().get('message')}"
            )
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to node: {e}")
        return None


def test_blockchain(node_url, num_domains=3):
    """Run a simple test of the blockchain with DNS operations"""
    print(f"Testing blockchain at {node_url}")

    # Check blockchain status
    status = check_blockchain_status(node_url)
    if not status:
        print("Failed to get blockchain status. Aborting test.")
        return

    # Generate a client ID
    client_id = f"test_client_{random.randint(1000, 9999)}"
    print(f"Using client ID: {client_id}")

    # Register some domains
    domains = []
    for i in range(num_domains):
        domain = f"test{i}.com"
        # No need to provide IP address as server will detect it
        if register_domain(node_url, client_id, domain):
            domains.append(domain)

    if not domains:
        print("Failed to register any domains. Aborting test.")
        return

    # Wait for mining to occur
    print("\nWaiting for mining (15 seconds)...")
    time.sleep(15)

    # Resolve the domains
    for domain in domains:
        resolve_domain(node_url, domain)

    # Check blockchain status again
    check_blockchain_status(node_url)

    print("\n✅ Blockchain test completed successfully!")


def get_blockchain_info(node_url):
    """Get detailed information about the blockchain"""
    try:
        # Get chain data
        chain_response = requests.get(f"{node_url}/chain")

        if chain_response.status_code == 200:
            chain_data = chain_response.json()
            chain = chain_data.get("chain", [])

            print(f"\n🔗 Blockchain Information:")
            print(f"Chain Length: {len(chain)} blocks")

            # Print information about the last few blocks
            last_blocks = chain[-3:] if len(chain) >= 3 else chain
            print(f"\nLast {len(last_blocks)} blocks:")

            for block in last_blocks:
                print(f"\nBlock #{block.get('index')}:")
                print(f"  Hash: {block.get('hash')[:16]}...")
                print(f"  Validator: {block.get('validator')}")
                print(f"  Timestamp: {time.ctime(block.get('timestamp'))}")
                print(f"  Transactions: {len(block.get('transactions', []))}")

            # Count the number of transactions by type
            tx_types = {}
            for block in chain:
                for tx in block.get("transactions", []):
                    action = tx.get("action")
                    tx_types[action] = tx_types.get(action, 0) + 1

            if tx_types:
                print("\nTransaction Types:")
                for action, count in tx_types.items():
                    print(f"  {action}: {count}")

            return chain_data
        else:
            print(
                f"❌ Failed to get chain data: {chain_response.json().get('message')}"
            )
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to node: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Test the blockchain network")
    parser.add_argument(
        "--node",
        type=str,
        default="http://localhost:5001",
        help="URL of the blockchain node to test",
    )
    parser.add_argument(
        "--domains",
        type=int,
        default=3,
        help="Number of domains to register for the test",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Get detailed information about the blockchain",
    )

    args = parser.parse_args()

    # Ensure node URL has proper format
    node_url = args.node
    if not node_url.startswith("http://"):
        node_url = f"http://{node_url}"

    if args.info:
        get_blockchain_info(node_url)
    else:
        test_blockchain(node_url, args.domains)


if __name__ == "__main__":
    main()
