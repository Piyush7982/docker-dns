#!/usr/bin/env python3
import argparse
import requests
import os
import json
import sys


def read_public_key(validator_id):
    """Read the public key for a validator from the keys directory"""
    key_path = os.path.join("keys", f"{validator_id}.pub")
    if not os.path.exists(key_path):
        print(f"Error: Public key not found for validator {validator_id}")
        return None

    with open(key_path, "rb") as f:
        return f.read()


def register_validator(node_url, validator_id):
    """Register a validator with its public key on the specified node"""
    public_key = read_public_key(validator_id)
    if not public_key:
        return False

    try:
        response = requests.post(
            f"{node_url}/validators/register",
            json={
                "validator_id": validator_id,
                "public_key": public_key.decode("utf-8"),
            },
        )

        if response.status_code in (200, 201):
            print(f"Successfully registered validator {validator_id} on {node_url}")
            print(f"Response: {response.json().get('message')}")
            return True
        else:
            print(f"Failed to register validator: {response.json().get('message')}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to node {node_url}: {e}")
        return False


def register_peer(node_url, peer_url):
    """Register a peer node with the specified node"""
    try:
        response = requests.post(f"{node_url}/peers/register", json={"peer": peer_url})

        if response.status_code in (200, 201):
            print(f"Successfully registered peer {peer_url} on {node_url}")
            print(f"Response: {response.json().get('message')}")
            return True
        else:
            print(f"Failed to register peer: {response.json().get('message')}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to node {node_url}: {e}")
        return False


def setup_network(nodes, validators):
    """Set up the entire network by connecting nodes and registering validators"""
    # Connect all nodes to each other
    for node in nodes:
        for peer in nodes:
            if node != peer:
                print(f"Connecting {node} to {peer}...")
                register_peer(node, peer)

    # Register all validators on all nodes
    for validator_id in validators:
        for node in nodes:
            print(f"Registering validator {validator_id} on {node}...")
            register_validator(node, validator_id)

    print("\nNetwork setup complete.")


def main():
    parser = argparse.ArgumentParser(
        description="Set up a blockchain validator network"
    )
    parser.add_argument(
        "--nodes", nargs="+", required=True, help="URLs of all blockchain nodes"
    )
    parser.add_argument(
        "--validators", nargs="+", required=True, help="IDs of all validator nodes"
    )

    args = parser.parse_args()

    # Ensure node URLs have proper format
    nodes = []
    for node in args.nodes:
        if not node.startswith("http://"):
            node = f"http://{node}"
        nodes.append(node)

    setup_network(nodes, args.validators)


if __name__ == "__main__":
    main()
