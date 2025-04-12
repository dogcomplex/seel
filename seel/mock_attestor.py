import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding
from seel.utils import hash_string, load_private_key_pem, load_public_key_pem
import logging

logger = logging.getLogger(__name__)

def create_attestation_payload(model_hash: str, constraint_hash: str, prompt_hash: str, output_hash: str) -> str:
    """
    Creates a reproducible JSON string payload representing the items to be attested.
    Order is important for reproducibility.
    """
    payload = {
        "model_hash": model_hash,
        "constraint_hash": constraint_hash,
        "prompt_hash": prompt_hash,
        "output_hash": output_hash
        # Add other relevant metadata if needed, e.g., timestamp
    }
    # Use sort_keys=True for deterministic serialization
    return json.dumps(payload, sort_keys=True)

def generate_mock_attestation(payload_str: str, private_key: ed25519.Ed25519PrivateKey) -> tuple[str, str]:
    """
    Hashes the payload string and signs the hash with the private key.

    Args:
        payload_str: The JSON string payload created by create_attestation_payload.
        private_key: The prover's Ed25519 private key object.

    Returns:
        A tuple containing: (payload_hash: str, signature_hex: str)
        Returns (None, None) if signing fails.
    """
    try:
        # Hash the payload string (using SHA256 consistent with other hashes)
        payload_hash = hash_string(payload_str, 'sha256')
        logger.info(f"Generated attestation payload hash: {payload_hash}")

        # Sign the hash
        # Ed25519 does not use padding or hash contexts like RSA/ECDSA, it signs the message directly
        signature = private_key.sign(payload_hash.encode('utf-8'))

        signature_hex = signature.hex()
        logger.info(f"Generated signature for payload hash (length: {len(signature_hex)})")
        return payload_hash, signature_hex

    except Exception as e:
        logger.error(f"Failed to generate mock attestation: {e}", exc_info=True)
        return None, None

def verify_mock_attestation(payload_str: str, signature_hex: str, public_key: ed25519.Ed25519PublicKey) -> bool:
    """
    Verifies the signature against the payload hash and public key.

    Args:
        payload_str: The original JSON string payload.
        signature_hex: The signature (hex encoded) to verify.
        public_key: The prover's Ed25519 public key object.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        payload_hash = hash_string(payload_str, 'sha256')
        signature_bytes = bytes.fromhex(signature_hex)

        # Ed25519 verification raises an exception on failure
        public_key.verify(signature_bytes, payload_hash.encode('utf-8'))
        logger.info("Mock attestation signature verified successfully.")
        return True
    except Exception as e:
        # Includes InvalidSignature
        logger.error(f"Mock attestation signature verification failed: {e}", exc_info=False) # Keep log clean
        return False

# Example Usage
if __name__ == '__main__':
    from seel.utils import generate_did_key, load_public_key_pem # Added load_public_key_pem
    import os

    # --- Prerequisites: Run keygen first --- 
    # python -m seel.keygen --key-dir keys_test --name test_prover
    key_dir = "keys_test"
    priv_key_path = os.path.join(key_dir, "test_prover.pem")
    pub_key_path = os.path.join(key_dir, "test_prover.pub.pem")

    if not (os.path.exists(priv_key_path) and os.path.exists(pub_key_path)):
        print(f"Error: Key files not found in '{key_dir}'. Run keygen first:")
        print(f"python -m seel.keygen --key-dir {key_dir} --name test_prover")
    else:
        print("\n--- Mock Attestation Test ---")
        # Load keys
        private_key = load_private_key_pem(priv_key_path)
        public_key = load_public_key_pem(pub_key_path) # Correctly load public key

        # Example data (replace with actual hashes in real flow)
        model_h = "abc_model_hash_123"
        constraints_h = hash_string(json.dumps({"max_length": 100}, sort_keys=True))
        prompt_h = hash_string("My prompt")
        output_h = hash_string("The model output")

        # Create payload
        payload = create_attestation_payload(model_h, constraints_h, prompt_h, output_h)
        print(f"Attestation Payload: {payload}")

        # Generate attestation
        payload_hash, signature = generate_mock_attestation(payload, private_key)
        print(f"Payload Hash: {payload_hash}")
        print(f"Signature: {signature[:30]}...{signature[-30:]}")

        # Verify attestation (using re-derived public key)
        is_valid = verify_mock_attestation(payload, signature, public_key)
        print(f"Verification Result (Correct Key): {is_valid}")

        # Test verification failure (tamper with payload)
        tampered_payload = payload.replace("100", "200")
        is_valid_tampered = verify_mock_attestation(tampered_payload, signature, public_key)
        print(f"Verification Result (Tampered Payload): {is_valid_tampered}")

        # Test verification failure (wrong key)
        wrong_private_key = ed25519.Ed25519PrivateKey.generate()
        wrong_public_key = wrong_private_key.public_key()
        is_valid_wrong_key = verify_mock_attestation(payload, signature, wrong_public_key)
        print(f"Verification Result (Wrong Key): {is_valid_wrong_key}")
        print("-----------------------------") 