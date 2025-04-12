import argparse
import os
import json
import logging
import sys

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("seel_cli")

# Add project root to path to allow sibling imports
# This assumes the script is run with `python -m seel.seel_cli`
# Or that the project root is in PYTHONPATH
# For direct execution `python seel/seel_cli.py`, adjust as needed
# (Might need `sys.path.append(os.path.dirname(os.path.dirname(__file__)))`)

from seel.model_loader import load_model_and_tokenizer
from seel.constraint_checker import load_constraints, check_constraints
from seel.inference_runner import run_inference
from seel.mock_attestor import create_attestation_payload, generate_mock_attestation
from seel.bundle_builder import create_bundle, DEFAULT_BUNDLE_DIR
from seel.utils import hash_string, load_private_key_pem

def main():
    parser = argparse.ArgumentParser(description="Generate a Seel proof bundle for AI inference.")
    parser.add_argument("-m", "--model", required=True, help="Model name (Hugging Face ID) or local path.")
    parser.add_argument("-p", "--prompt-file", required=True, help="Path to the input prompt text file.")
    parser.add_argument("-c", "--constraint-file", default="seel/constraints/default.json", help="Path to the constraint JSON file.")
    parser.add_argument("-k", "--key-file", required=True, help="Path to the prover's private key PEM file.")
    parser.add_argument("-o", "--output-dir", default=DEFAULT_BUNDLE_DIR, help=f"Base directory to save the output bundle (default: {DEFAULT_BUNDLE_DIR})")
    parser.add_argument("--max-new-tokens", type=int, default=100, help="Maximum number of new tokens for the model to generate.")
    parser.add_argument("--skip-output-file", action="store_true", help="Do not include the generated output.txt in the bundle.")

    args = parser.parse_args()

    logger.info("Starting Seel bundle generation process...")

    # --- 1. Load Prover Key --- 
    logger.info(f"Loading private key from: {args.key_file}")
    try:
        private_key = load_private_key_pem(args.key_file)
    except Exception as e:
        logger.error(f"Failed to load private key: {e}", exc_info=True)
        sys.exit(1)
    logger.info("Private key loaded successfully.")

    # --- 2. Load Constraints --- 
    logger.info(f"Loading constraints from: {args.constraint_file}")
    constraints = load_constraints(args.constraint_file)
    if constraints is None:
        logger.error("Failed to load constraints.")
        sys.exit(1)
    # Create canonical hash of constraints for payload
    constraint_json_str_canonical = json.dumps(constraints, sort_keys=True)
    constraint_hash = hash_string(constraint_json_str_canonical)
    logger.info(f"Constraints loaded. Hash: {constraint_hash}")

    # --- 3. Load Prompt --- 
    logger.info(f"Loading prompt from: {args.prompt_file}")
    try:
        with open(args.prompt_file, 'r', encoding='utf-8') as f:
            prompt_text = f.read()
    except Exception as e:
        logger.error(f"Failed to read prompt file: {e}", exc_info=True)
        sys.exit(1)
    logger.info(f"Prompt loaded ({len(prompt_text)} characters).")

    # --- 4. Check Prompt Constraints --- 
    logger.info("Checking prompt against constraints...")
    prompt_compliant, prompt_violations = check_constraints(prompt_text, constraints)
    if not prompt_compliant:
        logger.error(f"Prompt does not comply with constraints: {prompt_violations}")
        sys.exit(1)
    logger.info("Prompt is compliant.")

    # --- 5. Load Model & Tokenizer --- 
    logger.info(f"Loading model: {args.model}. This may take time...")
    model, tokenizer, model_dir, model_hash = load_model_and_tokenizer(args.model)
    if not model or not tokenizer:
        logger.error("Failed to load model or tokenizer.")
        sys.exit(1)
    logger.info(f"Model loaded successfully. Directory: {model_dir}, Hash: {model_hash}")

    # --- 6. Run Inference --- 
    logger.info(f"Running inference (max_new_tokens={args.max_new_tokens})...")
    output_text = run_inference(model, tokenizer, prompt_text, max_new_tokens=args.max_new_tokens)
    if output_text is None:
        logger.error("Inference failed.")
        sys.exit(1)
    logger.info(f"Inference successful ({len(output_text)} characters output).")
    # For constraint checking, maybe only check the *newly generated* part?
    # Let's check the full output for now as per requirement simplicity.
    generated_part = output_text[len(prompt_text):] # Crude way, assumes prompt is prefix
    logger.info(f"Newly generated text part ({len(generated_part)} characters)." )

    # --- 7. Check Output Constraints --- 
    logger.info("Checking model output against constraints...")
    output_compliant, output_violations = check_constraints(output_text, constraints)
    if not output_compliant:
        # Decide policy: fail or just warn and proceed? MVP Req F2 implies final bundle requires compliance.
        logger.error(f"Model output does not comply with constraints: {output_violations}")
        logger.error("Bundle generation aborted due to output constraint violation.")
        sys.exit(1)
    logger.info("Model output is compliant.")

    # --- 8. Generate Mock Attestation --- 
    logger.info("Generating mock attestation...")
    prompt_hash = hash_string(prompt_text)
    output_hash = hash_string(output_text)
    attestation_payload_str = create_attestation_payload(
        model_hash=model_hash,
        constraint_hash=constraint_hash,
        prompt_hash=prompt_hash,
        output_hash=output_hash
    )
    attestation_payload_hash, attestation_signature = generate_mock_attestation(
        payload_str=attestation_payload_str,
        private_key=private_key
    )
    if not attestation_signature:
        logger.error("Failed to generate mock attestation signature.")
        sys.exit(1)
    logger.info("Mock attestation generated successfully.")

    # --- 9. Build Bundle --- 
    logger.info(f"Building final bundle in directory: {args.output_dir}")
    bundle_path = create_bundle(
        output_dir_base=args.output_dir,
        model_hash=model_hash,
        constraint_file_path=args.constraint_file,
        constraint_hash=constraint_hash,
        prompt=prompt_text,
        output_text=output_text,
        attestation_payload=attestation_payload_str,
        attestation_payload_hash=attestation_payload_hash,
        attestation_signature=attestation_signature,
        private_key_path=args.key_file,
        include_output_file=not args.skip_output_file
    )

    if not bundle_path:
        logger.error("Failed to create the final bundle.")
        sys.exit(1)

    logger.info(f"✅ Seel bundle generation complete! Bundle saved to: {bundle_path}")

if __name__ == "__main__":
    main() 