import argparse
import os
import json
import logging
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("verify_cli")

from seel.utils import (
    hash_string, hash_directory, parse_did_key, public_key_from_bytes,
    load_public_key_pem # Might need this if comparing against a known key file
)
from seel.mock_attestor import verify_mock_attestation, create_attestation_payload

def verify_bundle(bundle_path: str) -> bool:
    """
    Verifies the integrity and consistency of a Seel bundle directory.

    Args:
        bundle_path: Path to the bundle directory.

    Returns:
        True if the bundle is valid, False otherwise.
    """
    logger.info(f"Starting verification for bundle: {bundle_path}")
    results = {"checks": [], "overall_valid": False}

    def add_check(name: str, success: bool, message: str = ""):
        results["checks"].append({"name": name, "success": success, "message": message})
        if not success:
            logger.error(f"Verification Check Failed: {name} - {message}")
        else:
            logger.info(f"Verification Check Passed: {name}")

    # --- Check 1: Bundle Structure and File Existence --- 
    required_files = ["meta.json", "meta.sig", "mock_proof.json", "constraint.json", "model_hash.txt"]
    optional_files = ["output.txt"]
    found_files = os.listdir(bundle_path)

    missing_required = [f for f in required_files if f not in found_files]
    if missing_required:
        add_check("File Existence (Required)", False, f"Missing required files: {missing_required}")
        return False # Cannot proceed without metadata
    else:
        add_check("File Existence (Required)", True)

    has_output_file = "output.txt" in found_files
    add_check("File Existence (Optional Output)", True, f"output.txt found: {has_output_file}")

    # Define file paths
    meta_path = os.path.join(bundle_path, "meta.json")
    meta_sig_path = os.path.join(bundle_path, "meta.sig")
    mock_proof_path = os.path.join(bundle_path, "mock_proof.json")
    constraint_path = os.path.join(bundle_path, "constraint.json")
    model_hash_path = os.path.join(bundle_path, "model_hash.txt")
    output_path = os.path.join(bundle_path, "output.txt") if has_output_file else None

    # --- Check 2: Load Metadata (meta.json) --- 
    try:
        with open(meta_path, 'r') as f:
            metadata = json.load(f)
        add_check("Load meta.json", True)
    except Exception as e:
        add_check("Load meta.json", False, f"Failed to load or parse meta.json: {e}")
        return False # Cannot proceed without metadata

    # Extract key fields from metadata
    prover_did = metadata.get("prover_did")
    meta_model_hash = metadata.get("model_hash")
    meta_constraint_hash = metadata.get("constraint_hash")
    meta_prompt_hash = metadata.get("prompt_hash")
    meta_output_hash = metadata.get("output_hash") # Can be None
    meta_attestation_ref = metadata.get("attestation_reference")
    meta_attestation_payload_hash = metadata.get("attestation_payload_hash")

    required_meta_fields = [
        prover_did, meta_model_hash, meta_constraint_hash,
        meta_prompt_hash, meta_attestation_ref, meta_attestation_payload_hash
        # meta_output_hash is optional depending on whether output.txt is included
    ]
    if not all(required_meta_fields):
         add_check("Metadata Content Check", False, "meta.json is missing one or more required fields.")
         return False
    else:
        add_check("Metadata Content Check", True)

    # --- Check 3: Parse Prover DID and Get Public Key --- 
    if not prover_did:
        add_check("Parse Prover DID", False, "Prover DID missing in metadata.")
        return False
    
    prover_pub_key_bytes = parse_did_key(prover_did)
    if not prover_pub_key_bytes:
        add_check("Parse Prover DID", False, f"Could not parse prover DID: {prover_did}")
        return False
    
    prover_public_key = public_key_from_bytes(prover_pub_key_bytes)
    if not prover_public_key:
        add_check("Parse Prover DID", False, f"Could not construct public key from DID: {prover_did}")
        return False
    else:
         add_check("Parse Prover DID", True, f"Successfully obtained public key for {prover_did}")

    # --- Check 4: Verify meta.sig --- 
    try:
        with open(meta_path, 'rb') as f_meta:
            meta_bytes = f_meta.read()
        with open(meta_sig_path, 'rb') as f_sig:
            meta_signature = f_sig.read()
        
        # Ed25519 verify raises exception on failure
        prover_public_key.verify(meta_signature, meta_bytes)
        add_check("Verify meta.sig", True, "Signature matches meta.json content and prover DID key.")
    except Exception as e:
        add_check("Verify meta.sig", False, f"meta.sig verification failed: {e}")
        return False # Bundle integrity compromised

    # --- Check 5: Load Mock Proof File --- 
    if meta_attestation_ref != "mock_proof.json":
        add_check("Load Mock Proof", False, f"Metadata attestation reference points to unexpected file: {meta_attestation_ref}")
        return False
    try:
        with open(mock_proof_path, 'r') as f:
            mock_proof_content = json.load(f)
        attestation_payload_obj = mock_proof_content.get("payload")
        attestation_payload_hash_in_proof = mock_proof_content.get("payload_hash")
        attestation_signature = mock_proof_content.get("signature")
        if not all([isinstance(attestation_payload_obj, dict), attestation_payload_hash_in_proof, attestation_signature]):
            raise ValueError("mock_proof.json is missing payload, payload_hash, or signature")
        add_check("Load Mock Proof", True)
    except Exception as e:
        add_check("Load Mock Proof", False, f"Failed to load or parse mock_proof.json: {e}")
        return False

    # --- Check 6: Verify Internal Mock Attestation Signature --- 
    # Recreate the canonical payload string from the object in the proof file
    attestation_payload_str = json.dumps(attestation_payload_obj, sort_keys=True)
    # Verify the signature within mock_proof.json using the public key derived from meta.json
    is_attestation_valid = verify_mock_attestation(
        payload_str=attestation_payload_str,
        signature_hex=attestation_signature,
        public_key=prover_public_key
    )
    add_check("Verify Mock Attestation Signature", is_attestation_valid, "Internal signature in mock_proof.json is valid.")
    if not is_attestation_valid:
        return False
        
    # --- Check 7: Consistency - Attestation Payload Hash --- 
    # Verify the hash stored *in* the proof file matches the hash stored *in* meta.json
    if attestation_payload_hash_in_proof != meta_attestation_payload_hash:
         add_check("Consistency: Attestation Payload Hash", False, 
                   f"Hash in meta.json ({meta_attestation_payload_hash}) != hash in proof file ({attestation_payload_hash_in_proof})")
         return False
    else:
         add_check("Consistency: Attestation Payload Hash", True)
         
    # --- Check 8: Consistency - Payload Content vs Metadata Hashes --- 
    # Verify that the hashes *inside* the attestation payload match the hashes in meta.json
    payload_model_hash = attestation_payload_obj.get("model_hash")
    payload_constraint_hash = attestation_payload_obj.get("constraint_hash")
    payload_prompt_hash = attestation_payload_obj.get("prompt_hash")
    payload_output_hash = attestation_payload_obj.get("output_hash") # Can be None
    
    consistency_checks = []
    if payload_model_hash != meta_model_hash:
        consistency_checks.append(f"Model Hash (payload {payload_model_hash} != meta {meta_model_hash})")
    if payload_constraint_hash != meta_constraint_hash:
        consistency_checks.append(f"Constraint Hash (payload {payload_constraint_hash} != meta {meta_constraint_hash})")
    if payload_prompt_hash != meta_prompt_hash:
        consistency_checks.append(f"Prompt Hash (payload {payload_prompt_hash} != meta {meta_prompt_hash})")
    if payload_output_hash != meta_output_hash: # Checks None == None correctly
        consistency_checks.append(f"Output Hash (payload {payload_output_hash} != meta {meta_output_hash})")
        
    if consistency_checks:
        add_check("Consistency: Payload Hashes vs Metadata Hashes", False, f"Mismatches found: {'; '.join(consistency_checks)}")
        return False
    else:
        add_check("Consistency: Payload Hashes vs Metadata Hashes", True)
        
    # --- Check 9: Consistency - Files vs Hashes --- 
    # Verify hashes of actual files match hashes in metadata
    files_consistent = True
    file_check_messages = []
    
    # a) Model Hash
    try:
        with open(model_hash_path, 'r') as f:
            file_model_hash = f.read().strip()
        if file_model_hash != meta_model_hash:
            files_consistent = False
            file_check_messages.append(f"model_hash.txt content ({file_model_hash}) != meta {meta_model_hash}")
    except Exception as e:
         files_consistent = False
         file_check_messages.append(f"Could not read or compare model_hash.txt: {e}")
         
    # b) Constraint Hash
    try:
        with open(constraint_path, 'r') as f:
            constraint_content = json.load(f)
        file_constraint_hash = hash_string(json.dumps(constraint_content, sort_keys=True))
        if file_constraint_hash != meta_constraint_hash:
            files_consistent = False
            file_check_messages.append(f"constraint.json hash ({file_constraint_hash}) != meta {meta_constraint_hash}")
    except Exception as e:
        files_consistent = False
        file_check_messages.append(f"Could not read/hash/compare constraint.json: {e}")

    # c) Output Hash (if output.txt exists)
    if has_output_file and output_path:
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                output_content = f.read()
            file_output_hash = hash_string(output_content)
            if file_output_hash != meta_output_hash:
                files_consistent = False
                file_check_messages.append(f"output.txt hash ({file_output_hash}) != meta {meta_output_hash}")
        except Exception as e:
            files_consistent = False
            file_check_messages.append(f"Could not read/hash/compare output.txt: {e}")
    elif not has_output_file and meta_output_hash is not None:
        # If output.txt doesn't exist, meta_output_hash should be None
        files_consistent = False
        file_check_messages.append(f"output.txt missing but meta.json has output_hash ({meta_output_hash})")
        
    add_check("Consistency: Files vs Hashes", files_consistent, '; '.join(file_check_messages) if file_check_messages else "File hashes match metadata.")
    if not files_consistent:
        return False

    # --- All Checks Passed --- 
    results["overall_valid"] = True
    logger.info("✅ Bundle verification successful. All checks passed.")
    return True

def main():
    parser = argparse.ArgumentParser(description="Verify a Seel proof bundle.")
    parser.add_argument("bundle_dir", help="Path to the Seel bundle directory to verify.")
    args = parser.parse_args()

    if not os.path.isdir(args.bundle_dir):
        logger.error(f"Error: Bundle directory not found: {args.bundle_dir}")
        sys.exit(1)

    is_valid = verify_bundle(args.bundle_dir)

    if is_valid:
        print("\n----------------------------")
        print("✅ Verification Result: VALID")
        print("----------------------------")
        sys.exit(0)
    else:
        print("\n------------------------------")
        print("❌ Verification Result: INVALID")
        print("------------------------------")
        sys.exit(1)

if __name__ == "__main__":
    main() 