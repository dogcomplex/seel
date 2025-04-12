import argparse
import os
import json
import logging
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
import pickle # For deserializing Receipt

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("verify_cli")

from seel.utils import (
    hash_string, hash_directory, parse_did_key, public_key_from_bytes,
    load_public_key_pem # Might need this if comparing against a known key file
)
from seel.mock_attestor import verify_mock_attestation
from seel.risc0_attestor import verify_attestation as verify_risc0_attestation, RISC0_INSTALLED, Receipt

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
    attestation_type = metadata.get("attestation_type")
    attestation_reference = metadata.get("attestation_reference")

    if not attestation_type or attestation_type not in ["mock", "risc0"]:
        add_check("Metadata Content Check (Attestation Type)", False, f"Missing or invalid attestation_type: {attestation_type}")
        return False
    else:
        add_check("Metadata Content Check (Attestation Type)", True)

    # Check other required fields based on type
    required_base = [prover_did, meta_model_hash, meta_constraint_hash, meta_prompt_hash, attestation_reference]
    required_mock = [metadata.get("mock_payload_hash")] if attestation_type == "mock" else []
    required_risc0 = [metadata.get("risc0_image_id")] if attestation_type == "risc0" else []

    if not all(required_base + required_mock + required_risc0):
        add_check("Metadata Content Check (Required Fields)", False, "meta.json is missing one or more required fields for its type.")
        return False
    else:
        add_check("Metadata Content Check (Required Fields)", True)

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

    # --- Check 5: Load and Verify Attestation Artifact --- 
    attestation_path = os.path.join(bundle_path, attestation_reference)
    if not os.path.exists(attestation_path):
        add_check(f"Attestation File Existence ({attestation_reference})", False, f"Attestation file missing: {attestation_path}")
        return False
    else:
        add_check(f"Attestation File Existence ({attestation_reference})", True)
        
    is_attestation_valid = False
    journal_bytes_list = [] # For risc0 journal check later
    
    if attestation_type == "mock":
        meta_payload_hash = metadata.get("mock_payload_hash")
        try:
            with open(attestation_path, 'r') as f:
                mock_proof_content = json.load(f)
            payload_hash_in_proof = mock_proof_content.get("payload_hash")
            signature = mock_proof_content.get("signature")
            if not payload_hash_in_proof or not signature:
                raise ValueError("mock_proof.json missing payload_hash or signature")
            
            # Consistency check: Hash in meta vs hash in proof file
            if payload_hash_in_proof != meta_payload_hash:
                add_check("Consistency: Mock Payload Hash", False, f"Hash in meta.json ({meta_payload_hash}) != hash in proof file ({payload_hash_in_proof})")
                return False
            else:
                add_check("Consistency: Mock Payload Hash", True)
                
            # Verify signature (we need to reconstruct the payload string)
            # This requires knowing the exact inputs that created the hash.
            # We stored hashes in meta.json, let's recreate the payload from those.
            payload_str = json.dumps({
                "model_hash": meta_model_hash,
                "constraint_hash": meta_constraint_hash,
                "prompt_hash": meta_prompt_hash,
                "output_hash": meta_output_hash
            }, sort_keys=True)
            
            # Verify the signature from the proof file against the reconstructed payload hash
            is_attestation_valid = verify_mock_attestation(payload_str, signature, prover_public_key)
            add_check("Verify Mock Attestation Signature", is_attestation_valid)
            
        except Exception as e:
            add_check("Load/Verify Mock Proof", False, f"Error processing mock_proof.json: {e}")
            return False
            
    elif attestation_type == "risc0":
        meta_image_id = metadata.get("risc0_image_id")
        if not RISC0_INSTALLED:
            add_check("Verify Risc0 Attestation", False, "risc0-zkvm library not installed, cannot verify.")
            return False
        try:
            with open(attestation_path, 'rb') as f:
                receipt = pickle.load(f)
            if not isinstance(receipt, Receipt):
                raise TypeError("Deserialized object is not a Risc0 Receipt")
            
            # Verify receipt against image ID from meta.json
            is_attestation_valid = verify_risc0_attestation(receipt, meta_image_id)
            add_check("Verify Risc0 Receipt", is_attestation_valid)
            
            if is_attestation_valid:
                # Extract journal for later checks
                journal_bytes_list = receipt.get_journal()
                logger.info(f"Risc0 Journal contains {len(journal_bytes_list)} entries.")
                
        except (pickle.UnpicklingError, TypeError, FileNotFoundError) as e:
            add_check("Load/Verify Risc0 Receipt", False, f"Error processing receipt.bin: {e}")
            return False
        except Exception as e:
            # Catch verification errors from verify_risc0_attestation
            add_check("Verify Risc0 Receipt", False, f"Receipt verification failed: {e}")
            is_attestation_valid = False # Ensure flag is false

    if not is_attestation_valid:
        logger.error("Core attestation verification failed.")
        return False # Stop if the core proof/sig is invalid

    # --- Check 6: Consistency - Attestation Content vs Metadata --- 
    content_consistent = False
    if attestation_type == "mock":
        # For mock, we already verified the payload hash matches meta hash
        # and verified the signature against a reconstructed payload based on meta hashes.
        # So, if we passed Check 6, content is considered consistent.
        content_consistent = True 
        add_check("Consistency: Attestation Content vs Metadata", content_consistent, "Mock payload hash verified against metadata.")
    elif attestation_type == "risc0":
        # For risc0, check if journal contents match metadata hashes
        try:
            if len(journal_bytes_list) == 4:
                journal_model_hash = journal_bytes_list[0].decode('utf-8')
                journal_constraint_hash = journal_bytes_list[1].decode('utf-8')
                journal_prompt_hash = journal_bytes_list[2].decode('utf-8')
                journal_output_hash = journal_bytes_list[3].decode('utf-8')
                
                checks = []
                if journal_model_hash != meta_model_hash: checks.append("model_hash")
                if journal_constraint_hash != meta_constraint_hash: checks.append("constraint_hash")
                if journal_prompt_hash != meta_prompt_hash: checks.append("prompt_hash")
                # Handle potential None in meta_output_hash
                meta_output_hash_str = meta_output_hash if meta_output_hash is not None else ""
                if journal_output_hash != meta_output_hash_str and not (meta_output_hash is None and journal_output_hash == hash_string("")):
                    # Allow empty string hash if meta was None, otherwise compare
                    # Need to be careful here depending on how None output was handled in guest/hashing
                    # Assuming guest always gets *some* string (even empty) for output hash if output is None
                    # Let's refine this: If meta_output_hash is None, journal_output_hash should correspond to hash_string(None)? No, guest receives a hash.
                    # Host side (seel_cli) calculates output_hash = hash_string(output_text) if output_text is not None else hash_string("") - ASSUMPTION NEEDED?
                    # Let's assume seel_cli passes hash_string("") if output is None.
                    expected_output_hash = meta_output_hash if meta_output_hash is not None else hash_string("")
                    if journal_output_hash != expected_output_hash:
                        checks.append(f"output_hash (journal: {journal_output_hash}, expected: {expected_output_hash})")
                    
                if not checks:
                    content_consistent = True
                    add_check("Consistency: Risc0 Journal vs Metadata", True, "Journal hashes match metadata.")
                else:
                    add_check("Consistency: Risc0 Journal vs Metadata", False, f"Mismatches found: {checks}")
            else:
                add_check("Consistency: Risc0 Journal vs Metadata", False, f"Expected 4 journal entries, found {len(journal_bytes_list)}")
        except Exception as e:
            add_check("Consistency: Risc0 Journal vs Metadata", False, f"Error decoding or comparing journal: {e}")
            
    if not content_consistent:
        return False

    # --- Check 7: Consistency - Files vs Hashes --- 
    # Renumbered from Check 9
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