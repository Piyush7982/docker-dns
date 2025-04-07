#!/usr/bin/env python3
import os
import sys
import base64
import json
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import requests


def create_new_key_pair(validator_id, keys_dir):
    """Generate new RSA key pair for the validator with proper formatting"""
    private_key_path = os.path.join(keys_dir, f"{validator_id}.pem")
    public_key_path = os.path.join(keys_dir, f"{validator_id}.pub")

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

    print(f"Generated new key pair for validator {validator_id}")
    return private_key, public_key


def sign_test_data(private_key):
    """Test signature generation with the new key"""
    test_data = "test_data"
    test_data_bytes = test_data.encode("utf-8")

    signature = private_key.sign(
        test_data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key, data, signature):
    """Verify a signature using a validator's public key"""
    try:
        # Decode the base64 signature
        signature_bytes = base64.b64decode(signature)

        # Convert data to bytes if it's not already
        if isinstance(data, str):
            data = data.encode("utf-8")

        # Load the public key
        public_key_obj = serialization.load_pem_public_key(public_key)

        # Verify the signature
        public_key_obj.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


def register_validator_with_nodes(validator_id, public_key, nodes):
    """Register the validator with all blockchain nodes using the new key"""
    success_count = 0
    fail_count = 0

    for node in nodes:
        try:
            response = requests.post(
                f"{node}/validators/register",
                json={
                    "validator_id": validator_id,
                    "public_key": public_key.decode("utf-8"),
                },
                timeout=5,
            )

            if response.status_code in (200, 201):
                print(
                    f"✅ Successfully registered validator {validator_id} with {node}"
                )
                success_count += 1
            else:
                print(
                    f"❌ Failed to register validator with {node}: {response.json().get('message')}"
                )
                fail_count += 1
        except Exception as e:
            print(f"❌ Error registering validator with {node}: {e}")
            fail_count += 1

    return success_count, fail_count


def main():
    parser = argparse.ArgumentParser(
        description="Fix validator signatures for blockchain nodes"
    )
    parser.add_argument("--validator", required=True, help="Validator ID to fix")
    parser.add_argument(
        "--keys-dir", default="keys", help="Directory containing validator keys"
    )
    parser.add_argument(
        "--nodes", nargs="+", help="Blockchain node URLs to register with"
    )

    args = parser.parse_args()

    validator_id = args.validator
    keys_dir = args.keys_dir
    nodes = args.nodes or []

    # Ensure nodes have proper format
    nodes = [node if node.startswith("http://") else f"http://{node}" for node in nodes]

    # Ensure keys directory exists
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print(f"Created keys directory: {keys_dir}")

    # Check if keys already exist
    private_key_path = os.path.join(keys_dir, f"{validator_id}.pem")
    public_key_path = os.path.join(keys_dir, f"{validator_id}.pub")

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print(f"Existing keys found for validator {validator_id}")

        # Backup existing keys
        backup_dir = os.path.join(keys_dir, "backup")
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        import time

        timestamp = int(time.time())
        os.rename(
            private_key_path,
            os.path.join(backup_dir, f"{validator_id}_{timestamp}.pem"),
        )
        os.rename(
            public_key_path, os.path.join(backup_dir, f"{validator_id}_{timestamp}.pub")
        )
        print(f"Backed up existing keys to {backup_dir}")

    # Create new keys
    private_key, public_key = create_new_key_pair(validator_id, keys_dir)

    # Test signature
    signature = sign_test_data(private_key)
    verification_result = verify_signature(public_key, "test_data", signature)

    if verification_result:
        print("✅ Signature verification successful")
    else:
        print("❌ Signature verification failed")
        sys.exit(1)

    # Register with nodes if provided
    if nodes:
        print(f"\nRegistering validator {validator_id} with {len(nodes)} nodes...")
        success_count, fail_count = register_validator_with_nodes(
            validator_id, public_key, nodes
        )
        print(
            f"\nRegistration complete: {success_count} successful, {fail_count} failed"
        )

    print("\nValidator signature fix completed successfully!")
    print(f"New keys saved to {os.path.abspath(keys_dir)}")
    print("\nPlease restart your validator node for the changes to take effect.")


if __name__ == "__main__":
    main()
