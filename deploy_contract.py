#!/usr/bin/env python3
import json
import argparse
import sys
import os
from web3 import Web3
from web3.middleware import geth_poa_middleware
from solcx import compile_source, install_solc


def compile_contract(contract_source_file):
    """Compile the contract source file"""
    print(f"Compiling smart contract from {contract_source_file}")
    with open(contract_source_file, "r") as f:
        contract_source_code = f.read()

    # Install specific solc version and compile
    install_solc("0.8.0")
    compiled_sol = compile_source(contract_source_code, output_values=["abi", "bin"])

    # Return the contract interface
    contract_id, contract_interface = compiled_sol.popitem()
    return contract_interface


def deploy_contract(w3, contract_interface, account_address):
    """Deploy the compiled contract"""
    # Get contract binary
    contract_binary = contract_interface["bin"]

    # Create contract instance
    Contract = w3.eth.contract(abi=contract_interface["abi"], bytecode=contract_binary)

    # Get transaction count (nonce)
    nonce = w3.eth.get_transaction_count(account_address)

    # Build transaction
    txn = Contract.constructor().build_transaction(
        {
            "from": account_address,
            "nonce": nonce,
            "gas": 1500000,
            "gasPrice": w3.to_wei("50", "gwei"),
        }
    )

    # Sign transaction
    private_key = input("Enter your private key: ")
    signed_txn = w3.eth.account.sign_transaction(txn, private_key)

    # Send transaction
    txn_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    print(f"Transaction hash: {txn_hash.hex()}")

    # Wait for transaction receipt
    txn_receipt = w3.eth.wait_for_transaction_receipt(txn_hash)
    contract_address = txn_receipt.contractAddress

    print(f"Contract deployed at address: {contract_address}")
    return contract_address, contract_interface["abi"]


def save_contract_details(contract_address, contract_abi, output_dir):
    """Save contract details to file"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Save contract address
    with open(f"{output_dir}/contract_address.txt", "w") as f:
        f.write(contract_address)

    # Save contract ABI
    with open(f"{output_dir}/contract_abi.json", "w") as f:
        json.dump(contract_abi, f, indent=2)

    print(f"Contract details saved to {output_dir}/")


def main():
    parser = argparse.ArgumentParser(description="Deploy DNS Smart Contract")
    parser.add_argument(
        "--contract",
        type=str,
        default="dns_contract.sol",
        help="Path to the smart contract file (default: dns_contract.sol)",
    )
    parser.add_argument(
        "--provider",
        type=str,
        default="http://localhost:8545",
        help="Ethereum provider URL (default: http://localhost:8545)",
    )
    parser.add_argument(
        "--address",
        type=str,
        required=True,
        help="Ethereum account address to deploy from",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./contract",
        help="Output directory for contract details (default: ./contract)",
    )
    args = parser.parse_args()

    # Connect to Ethereum node
    print(f"Connecting to Ethereum node at {args.provider}")
    w3 = Web3(Web3.HTTPProvider(args.provider))

    # Add middleware for PoA chains
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Check connection
    if not w3.is_connected():
        print("Error: Could not connect to Ethereum node")
        sys.exit(1)

    print("Connected to Ethereum node")
    print(f"Chain ID: {w3.eth.chain_id}")

    # Validate account address
    if not w3.is_address(args.address):
        print("Error: Invalid Ethereum address")
        sys.exit(1)

    # Check account balance
    balance = w3.eth.get_balance(args.address)
    balance_eth = w3.from_wei(balance, "ether")
    print(f"Account balance: {balance_eth} ETH")

    if balance_eth < 0.1:
        print("Warning: Account balance is low, may not have enough ETH to deploy")

    # Compile contract
    contract_interface = compile_contract(args.contract)

    # Deploy contract
    contract_address, contract_abi = deploy_contract(
        w3, contract_interface, args.address
    )

    # Save contract details
    save_contract_details(contract_address, contract_abi, args.output)

    print("Contract deployment completed successfully!")


if __name__ == "__main__":
    main()
