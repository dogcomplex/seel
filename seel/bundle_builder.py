import os
import json
import shutil
import datetime
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from seel.utils import hash_string, load_private_key_pem, generate_did_key

logger = logging.getLogger(__name__)

DEFAULT_BUNDLE_DIR = "output_bundles"

def create_bundle(output_dir_base: str,
                  model_hash: str,
                  constraint_file_path: str,
                  constraint_hash: str,
                  prompt: str,
                  output_text: str | None,
                  attestation_payload: str, # The JSON string payload
                  attestation_payload_hash: str,
                  attestation_signature: str,
                  private_key_path: str,
                  include_output_file: bool = True
                  ) -> str | None:
    """
    Assembles the final output bundle directory.

    Args:
        output_dir_base: The base directory where the bundle subdirectory will be created.
        model_hash: The hash of the model used.
        constraint_file_path: Path to the original constraint file used.
        constraint_hash: Hash of the canonical constraint definition used.
        prompt: The original input prompt.
        output_text: The generated output text (or None if not saving).
        attestation_payload: The JSON string payload that was signed for the mock attestation.
        attestation_payload_hash: The hash of the attestation payload.
        attestation_signature: The signature of the attestation payload hash.
        private_key_path: Path to the prover's private key PEM file for signing meta.json.
        include_output_file: Whether to save the output_text to output.txt.

    Returns:
        The path to the created bundle directory, or None on failure.
    """
    try:
        # 1. Create unique bundle directory
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        bundle_name = f"seel_bundle_{timestamp}"
        bundle_path = os.path.join(output_dir_base, bundle_name)
        os.makedirs(bundle_path, exist_ok=True)
        logger.info(f"Creating bundle directory: {bundle_path}")

        # 2. Load Prover's Key and get DID
        private_key = load_private_key_pem(private_key_path)
        public_key = private_key.public_key()
        prover_did = generate_did_key(public_key)

        # 3. Prepare content hashes
        prompt_hash = hash_string(prompt)
        output_hash = hash_string(output_text) if output_text is not None else None

        # 4. Create Mock Proof File (containing payload and signature)
        mock_proof_content = {
            "payload": json.loads(attestation_payload), # Store payload as object
            "payload_hash": attestation_payload_hash,
            "signature": attestation_signature
        }
        mock_proof_path = os.path.join(bundle_path, "mock_proof.json")
        with open(mock_proof_path, 'w') as f:
            json.dump(mock_proof_content, f, indent=2)
        logger.info(f"Created mock proof file: {mock_proof_path}")

        # 5. Create Metadata Dictionary
        metadata = {
            "bundle_version": "1.0-mvp",
            "timestamp_utc": timestamp,
            "prover_did": prover_did,
            "model_hash": model_hash,
            "constraint_file": os.path.basename(constraint_file_path),
            "constraint_hash": constraint_hash,
            "prompt_hash": prompt_hash,
            "output_hash": output_hash, # May be None
            "attestation_reference": "mock_proof.json",
            "attestation_payload_hash": attestation_payload_hash,
            # Add other useful info: model name, inference params?
        }

        # 6. Create meta.json
        meta_path = os.path.join(bundle_path, "meta.json")
        with open(meta_path, 'w') as f:
            # Use sort_keys for deterministic output before signing
            json.dump(metadata, f, indent=2, sort_keys=True)
        logger.info(f"Created metadata file: {meta_path}")

        # 7. Sign meta.json -> meta.sig
        with open(meta_path, 'rb') as f:
            meta_bytes = f.read()
        # Hash the canonical meta.json bytes before signing
        # Note: Signing the hash is more common with RSA/ECDSA.
        # Ed25519 typically signs the message directly. We sign the raw meta.json bytes.
        meta_signature = private_key.sign(meta_bytes)
        meta_sig_path = os.path.join(bundle_path, "meta.sig")
        with open(meta_sig_path, 'wb') as f:
            f.write(meta_signature)
        logger.info(f"Created signature file: {meta_sig_path}")

        # 8. Copy/Create other bundle files
        # constraint.json (copy original)
        shutil.copy2(constraint_file_path, os.path.join(bundle_path, "constraint.json"))
        # model_hash.txt
        with open(os.path.join(bundle_path, "model_hash.txt"), 'w') as f:
            f.write(model_hash)
        # output.txt (optional)
        if include_output_file and output_text is not None:
            with open(os.path.join(bundle_path, "output.txt"), 'w', encoding='utf-8') as f:
                f.write(output_text)
            logger.info("Included output.txt in bundle.")
        else:
             logger.info("Skipping output.txt in bundle.")

        logger.info(f"Bundle creation successful: {bundle_path}")
        return bundle_path

    except Exception as e:
        logger.error(f"Failed to create bundle: {e}", exc_info=True)
        # Clean up potentially partially created bundle directory?
        # if 'bundle_path' in locals() and os.path.exists(bundle_path):
        #     shutil.rmtree(bundle_path)
        return None

# Example Usage (requires outputs from previous steps)
if __name__ == '__main__':
    # --- Prerequisites --- 
    # 1. Run keygen: python -m seel.keygen --key-dir keys_test --name test_prover_bundle
    # 2. Have a constraint file: e.g., seel/constraints/default.json
    # 3. Need outputs from mock_attestor (payload, hash, sig) and model_loader (hash)

    print("\n--- Bundle Builder Test ---")
    key_dir = "keys_test"
    prover_name = "test_prover_bundle"
    priv_key_path = os.path.join(key_dir, f"{prover_name}.pem")
    constraint_path = os.path.join("seel", "constraints", "default.json")

    if not os.path.exists(priv_key_path):
        print(f"Error: Private key not found: {priv_key_path}")
        print(f"Run: python -m seel.keygen --key-dir {key_dir} --name {prover_name}")
    elif not os.path.exists(constraint_path):
         print(f"Error: Constraint file not found: {constraint_path}")
    else:
        # Mock data representing outputs of previous steps
        mock_model_hash = "mock_model_12345"
        mock_constraints = json.dumps({"max_length": 100}, sort_keys=True)
        mock_constraint_hash = hash_string(mock_constraints)
        mock_prompt = "This was the prompt."
        mock_output = "This was the output generated by the model."

        # Simulate mock attestation generation
        from seel.mock_attestor import create_attestation_payload, generate_mock_attestation
        att_payload_str = create_attestation_payload(
            model_hash=mock_model_hash,
            constraint_hash=mock_constraint_hash,
            prompt_hash=hash_string(mock_prompt),
            output_hash=hash_string(mock_output)
        )
        temp_priv_key = load_private_key_pem(priv_key_path)
        att_payload_hash, att_sig = generate_mock_attestation(att_payload_str, temp_priv_key)

        if att_payload_hash and att_sig:
            print("Generated mock attestation data for test.")
            # Create the bundle
            bundle_output_path = create_bundle(
                output_dir_base=DEFAULT_BUNDLE_DIR,
                model_hash=mock_model_hash,
                constraint_file_path=constraint_path,
                constraint_hash=mock_constraint_hash,
                prompt=mock_prompt,
                output_text=mock_output,
                attestation_payload=att_payload_str,
                attestation_payload_hash=att_payload_hash,
                attestation_signature=att_sig,
                private_key_path=priv_key_path,
                include_output_file=True
            )

            if bundle_output_path:
                print(f"Bundle created successfully at: {bundle_output_path}")
                print("Bundle contents:")
                for item in os.listdir(bundle_output_path):
                    print(f"  - {item}")
            else:
                print("Bundle creation failed.")
        else:
            print("Failed to generate mock attestation data for test.")

        print("---------------------------") 