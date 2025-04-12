import argparse
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from seel.utils import save_key_pem, generate_did_key

def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 key pair and DID Key for Seel.")
    parser.add_argument("--key-dir", default="keys", help="Directory to save the generated keys (default: keys)")
    parser.add_argument("--name", default="prover", help="Base name for the key files (e.g., prover.pem, prover.pub.pem) (default: prover)")
    args = parser.parse_args()

    # Ensure key directory exists
    os.makedirs(args.key_dir, exist_ok=True)

    # Generate keys
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Define file paths
    private_key_path = os.path.join(args.key_dir, f"{args.name}.pem")
    public_key_path = os.path.join(args.key_dir, f"{args.name}.pub.pem")

    # Save keys
    save_key_pem(private_key, private_key_path, is_private=True)
    save_key_pem(public_key, public_key_path, is_private=False)

    # Generate and print DID Key
    did_key = generate_did_key(public_key)

    print(f"🔑 Generated Ed25519 key pair with base name: {args.name}")
    print(f"   Private Key: {private_key_path}")
    print(f"   Public Key:  {public_key_path}")
    print(f"🆔 DID Key:     {did_key}")
    print("\n✨ Store this DID Key safely, it identifies the prover.")

if __name__ == "__main__":
    main() 