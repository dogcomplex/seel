# seel/risc0_attestor.py
import logging
import os
from typing import List, Tuple

# Check if the risc0-zkvm library is installed
try:
    from risc0.zkvm.host import ProverOpts, Prover
    from risc0.zkvm.receipt import Receipt
    RISC0_INSTALLED = True
except ImportError:
    ProverOpts = None
    Prover = None
    Receipt = None
    RISC0_INSTALLED = False

logger = logging.getLogger(__name__)

# --- Configuration --- #
# Path to the guest ELF binary (compiled inside WSL filesystem)
# Assumes the Python script can access this path directly.
# If running Python outside WSL, this path needs adjustment or file copying.
# We determined this path from the `cargo risczero build` output.
# Use os.path.expanduser to resolve the ~
GUEST_ELF_PATH = os.path.expanduser("~/risc0-guest/target/riscv32im-risc0-zkvm-elf/docker/risc0-guest.bin")

# Image ID of the compiled guest program (from `cargo risczero build` output)
GUEST_IMAGE_ID = "3d224244111b207aca4b86d7170a2b422b91f4cceda3a2cb86a37e9bff6bc785"

class Risc0Error(Exception):
    "Custom exception for risc0 related errors."
    pass

def check_dependencies():
    "Checks if risc0 is installed and the guest ELF exists."
    if not RISC0_INSTALLED:
        logger.error("risc0-zkvm Python library not found. Please install via requirements.txt")
        raise Risc0Error("risc0-zkvm library not installed")
    if not os.path.exists(GUEST_ELF_PATH):
        logger.error(f"Risc0 guest ELF not found at: {GUEST_ELF_PATH}")
        logger.error("Please build the guest using 'cargo risczero build' inside the 'risc0-guest' directory within the WSL filesystem (~).")
        raise Risc0Error("Guest ELF not found")
    logger.info("Risc0 dependencies check passed.")

def generate_attestation(model_hash: str, constraint_hash: str, prompt_hash: str, output_hash: str) -> dict:
    """
    Generates a Risc0 attestation (Receipt) by running the guest program.
    Returns a dictionary containing attestation details.

    Args:
        model_hash: Hash of the model.
        constraint_hash: Hash of the constraints.
        prompt_hash: Hash of the prompt.
        output_hash: Hash of the output.

    Returns:
        A dictionary: {
            "type": "risc0",
            "image_id": image_id_string | None, # None on failure
            "payload_hash": None, # Not applicable to risc0
            "proof_data": receipt_object | None # None on failure
        }
        Raises Risc0Error on setup/dependency failure.
    """
    check_dependencies() # Ensure setup is correct
    logger.info("Starting Risc0 proof generation...")
    result = {
        "type": "risc0",
        "image_id": None,
        "payload_hash": None,
        "proof_data": None
    }

    try:
        # Create a prover instance
        # ProverOpts can be used to configure hashfn etc., default is SHA-256
        opts = ProverOpts()
        prover = Prover.create(GUEST_ELF_PATH, GUEST_IMAGE_ID, opts)
        logger.info(f"Prover created for ELF: {GUEST_ELF_PATH}")

        # Add inputs to the prover. Must match the order in guest main.rs!
        # Need to encode strings to bytes.
        prover.add_input_u8_slice(model_hash.encode('utf-8'))
        prover.add_input_u8_slice(constraint_hash.encode('utf-8'))
        prover.add_input_u8_slice(prompt_hash.encode('utf-8'))
        prover.add_input_u8_slice(output_hash.encode('utf-8'))
        logger.info("Inputs added to the prover.")

        # Run the prover
        logger.info("Running the prover... (This can take some time)")
        receipt = prover.run()
        logger.info("Prover run completed successfully.")
        
        result["image_id"] = GUEST_IMAGE_ID
        result["proof_data"] = receipt
        return result

    except Exception as e:
        logger.error(f"Risc0 proof generation failed: {e}", exc_info=True)
        # Don't raise here, return dict with None proof_data
        return result

def verify_attestation(receipt: Receipt, image_id: str) -> bool:
    """
    Verifies a Risc0 Receipt against its Image ID.
    Also implicitly verifies the integrity of the journal within the receipt.

    Args:
        receipt: The Risc0 Receipt object.
        image_id: The expected Image ID (hex string) of the guest program.

    Returns:
        True if verification succeeds, False otherwise.
    """
    if not RISC0_INSTALLED:
        logger.error("risc0-zkvm library not available for verification.")
        return False
    if not isinstance(receipt, Receipt):
         logger.error(f"Invalid receipt object provided for verification: {type(receipt)}")
         return False
    if not image_id or not isinstance(image_id, str):
        logger.error(f"Invalid Image ID provided for verification: {image_id}")
        return False

    logger.info(f"Verifying Risc0 receipt against Image ID: {image_id}")
    try:
        # The verify method raises an exception on failure
        receipt.verify(image_id)
        logger.info("Receipt verification successful.")
        return True
    except Exception as e:
        logger.error(f"Receipt verification failed: {e}", exc_info=True)
        return False

# Example Usage / Test (requires guest built and dependencies installed)
if __name__ == '__main__':
    print("--- Risc0 Attestor Test --- (Requires guest ELF built)")
    logging.basicConfig(level=logging.INFO)

    # Check if dependencies are met before proceeding
    try:
        check_dependencies()
    except Risc0Error as e:
        print(f"Dependency Error: {e}")
        exit(1)

    # Mock data
    mh = "test_model_hash"
    ch = "test_constraint_hash"
    ph = "test_prompt_hash"
    oh = "test_output_hash"

    print("\nGenerating proof...")
    attestation_result = None
    try:
        attestation_result = generate_attestation(mh, ch, ph, oh)
        image_id = attestation_result["image_id"]
        receipt = attestation_result["proof_data"]

        if image_id and receipt:
            print(f"Proof generated successfully. Image ID: {image_id}")
            print(f"Journal Hash: {receipt.get_journal_hash()}")
            print(f"Journal Contents (decoded): {[bytes(entry).decode('utf-8') for entry in receipt.get_journal()]}")
        else:
            print("Proof generation failed (returned None receipt). Check logs.")
            exit(1)

    except Risc0Error as e:
        print(f"Proof generation dependency/setup error: {e}")
        exit(1)

    if attestation_result and attestation_result["proof_data"]:
        receipt = attestation_result["proof_data"]
        image_id = attestation_result["image_id"]
        print("\nVerifying proof...")
        is_valid = verify_attestation(receipt, image_id)
        print(f"Verification result (correct image ID): {is_valid}")

        print("\nVerifying proof with incorrect image ID...")
        wrong_image_id = "0000000000000000000000000000000000000000000000000000000000000000"
        # Use the same receipt, but wrong ID
        is_invalid_check = verify_attestation(receipt, wrong_image_id)
        print(f"Verification result (wrong image ID): {is_invalid_check}") # Should be False

    print("---------------------------") 