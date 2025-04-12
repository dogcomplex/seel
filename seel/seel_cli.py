import argparse
import os
import json
import logging
import sys
import torch # Import torch for ONNX export
import tempfile # For temporary directory
import shutil # For removing temp directory

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
from seel.mock_attestor import (
    create_attestation_payload as create_mock_payload,
    generate_mock_attestation
)
from seel.risc0_attestor import (
    generate_attestation as generate_risc0_attestation,
    Risc0Error
)
from seel.bundle_builder import create_bundle, DEFAULT_BUNDLE_DIR
from seel.utils import hash_string, load_private_key_pem
from seel.ezkl_attestor import generate_ezkl_attestation, EzklError

# Try importing optimum exporter
try:
    from optimum.exporters.onnx import main_export
    OPTIMUM_AVAILABLE = True
except ImportError:
    OPTIMUM_AVAILABLE = False
    logger.warning("Hugging Face Optimum library not found. ONNX export for ezkl will fail.")
    logger.warning("Install it with: pip install optimum onnxruntime")
    # Define a dummy function if import fails to avoid NameError later
    def main_export(*args, **kwargs):
        raise ImportError("Optimum library not found, cannot export ONNX model.")

def main():
    parser = argparse.ArgumentParser(description="Generate a Seel proof bundle for AI inference.")
    parser.add_argument("-m", "--model", required=True, help="Model name (Hugging Face ID) or local path.")
    parser.add_argument("-p", "--prompt-file", required=True, help="Path to the input prompt text file.")
    parser.add_argument("-c", "--constraint-file", default="seel/constraints/default.json", help="Path to the constraint JSON file.")
    parser.add_argument("-k", "--key-file", required=True, help="Path to the prover's private key PEM file.")
    parser.add_argument("-o", "--output-dir", default=DEFAULT_BUNDLE_DIR, help=f"Base directory to save the output bundle (default: {DEFAULT_BUNDLE_DIR})")
    parser.add_argument("--max-new-tokens", type=int, default=100, help="Maximum number of new tokens for the model to generate.")
    parser.add_argument("--attestor", choices=["mock", "risc0", "ezkl"], default="mock", help="Attestation method to use (default: mock)")
    parser.add_argument("--skip-output-file", action="store_true", help="Do not include the generated output.txt in the bundle.")

    args = parser.parse_args()

    logger.info(f"Starting Seel bundle generation process (Attestor: {args.attestor})...")

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

    # --- 8. Generate Attestation (Mock or Risc0 or ezkl) --- 
    logger.info(f"Generating {args.attestor} attestation...")
    prompt_hash = hash_string(prompt_text)
    output_hash = hash_string(output_text)
    attestation_result = None
    onnx_export_temp_dir = None # Keep track of temp dir for cleanup
    input_data_path = None # Keep track of input file path

    if args.attestor == "mock":
        mock_payload_str = create_mock_payload(
            model_hash=model_hash,
            constraint_hash=constraint_hash,
            prompt_hash=prompt_hash,
            output_hash=output_hash
        )
        attestation_result = generate_mock_attestation(
            payload_str=mock_payload_str,
            private_key=private_key
        )
    elif args.attestor == "risc0":
        try:
            attestation_result = generate_risc0_attestation(
                model_hash=model_hash,
                constraint_hash=constraint_hash,
                prompt_hash=prompt_hash,
                output_hash=output_hash
            )
        except Risc0Error as e:
            logger.error(f"Risc0 Attestor Error: {e}")
            logger.error("(Currently, the required Python package 'risc0-zkvm' is unavailable on PyPI)")
            sys.exit(1)
    elif args.attestor == "ezkl":
        logger.info("Preparing for ezkl attestation using Optimum ONNX export...")
        if not OPTIMUM_AVAILABLE:
             logger.error("Optimum library is required for ezkl ONNX export but not installed.")
             sys.exit(1)

        try:
            # Create a temporary directory for ONNX export artifacts
            onnx_export_temp_dir = tempfile.mkdtemp(prefix="seel_onnx_export_")
            logger.info(f"Created temporary directory for ONNX export: {onnx_export_temp_dir}")
            # Expected path for the exported model within the temp dir
            onnx_model_path = os.path.join(onnx_export_temp_dir, "model.onnx") 

            # 1. Export Model using Optimum
            logger.info(f"Exporting model '{args.model}' to ONNX using Optimum -> {onnx_export_temp_dir}")
            # Determine task. For GPT2, text-generation-with-past is common for ONNX Runtime
            # Use --task auto? or specific? Try specific first.
            onnx_export_config = main_export(
                model_name_or_path=args.model, # Use original model name/path
                output=onnx_export_temp_dir,
                task="text-generation-with-past", # Specify task for GPT-like models
                opset=14, # Try forcing opset 14
                no_post_process=False # Let optimum do post-processing
                # Remove dynamic_axes to export with fixed shapes
                # dynamic_axes=dynamic_axes 
            )
            # Check if model.onnx was created
            if not os.path.exists(onnx_model_path):
                 logger.error(f"Optimum export finished, but expected file {onnx_model_path} not found.")
                 # List files in temp dir for debugging
                 try: 
                     files = os.listdir(onnx_export_temp_dir)
                     logger.error(f"Files found in {onnx_export_temp_dir}: {files}")
                 except Exception as list_e:
                     logger.error(f"Could not list files in temp dir: {list_e}")
                 raise FileNotFoundError(f"ONNX export failed to produce {onnx_model_path}")
            logger.info("Model successfully exported to ONNX using Optimum.")

            # 2. Create ezkl Input JSON (using original tokenizer)
            input_data_path = os.path.join(onnx_export_temp_dir, "input.json") # Place in temp dir too
            logger.info(f"Creating ezkl input data file: {input_data_path}")
            pad_token_id = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id
            if pad_token_id is None: pad_token_id = 0
            dummy_seq_len = 16 # Match dummy length potentially used by Optimum or ezkl needs
            dummy_input_ids = torch.LongTensor([[pad_token_id] * dummy_seq_len])
            # Optimum exported models might only need input_ids, need to check
            input_data_list = [dummy_input_ids.cpu().numpy().tolist()] 
            ezkl_input_data = {"input_data": input_data_list}
            with open(input_data_path, 'w') as f:
                json.dump(ezkl_input_data, f)
            logger.info("ezkl input data file created.")
            
            # 3. Call the ezkl attestor (still a placeholder)
            logger.info("Calling ezkl attestation generation function...")
            attestation_result = generate_ezkl_attestation(
                onnx_model_path=onnx_model_path, 
                input_data_path=input_data_path,
                output_dir=args.output_dir # Bundle dir, not temp dir 
            )

            if attestation_result and not attestation_result.get("error"):
                 logger.info("ezkl attestation generation call succeeded (but is not implemented).")
            else:
                 logger.error(f"ezkl attestation generation failed: {attestation_result.get('error', 'Not implemented')}")
                 sys.exit(1)
                 
        except ImportError as e:
             logger.error(f"Missing library for ONNX export or ezkl. Ensure torch, onnx, onnxruntime, optimum, ezkl are installed: {e}")
             sys.exit(1)
        except FileNotFoundError as e: 
             logger.error(f"File not found during ezkl ONNX export or attestation preparation: {e}")
             sys.exit(1)
        except EzklError as e:
            logger.error(f"ezkl Attestor Error: {e}")
            logger.error("Ensure ezkl library is installed correctly (`pip install ezkl`).")
            sys.exit(1)
        except NotImplementedError:
            logger.error("ezkl attestation is not yet implemented in ezkl_attestor.py.")
            sys.exit(1) # Exit as ezkl attestation cannot be completed
        except Exception as e:
            logger.error(f"Unexpected error during ezkl Optimum export or attestation preparation: {e}", exc_info=True)
            sys.exit(1)
        finally:
            # Clean up temporary directory
            if onnx_export_temp_dir:
                 logger.info(f"Cleaning up temporary ONNX export directory: {onnx_export_temp_dir}")
                 try:
                     shutil.rmtree(onnx_export_temp_dir)
                 except Exception as e_clean:
                      logger.warning(f"Failed to remove temporary directory {onnx_export_temp_dir}: {e_clean}")
            
    else:
        # Should not happen due to argparse choices
        logger.error(f"Invalid attestor type specified: {args.attestor}")
        sys.exit(1)

    # Check if attestation succeeded (common check for mock/risc0, ezkl currently fails)
    # We modify this check because ezkl currently fails intentionally
    if args.attestor in ["mock", "risc0"] and (not attestation_result or attestation_result.get("proof_data") is None):
        logger.error(f"Failed to generate {args.attestor} attestation proof/signature.")
        sys.exit(1)
    elif args.attestor == "ezkl":
        # ezkl attestation currently exits earlier if it fails or is not implemented
        pass 

    logger.info(f"{args.attestor.capitalize()} attestation generated successfully (or placeholder called)." ) # Adjusted message

    # --- 9. Build Bundle --- 
    logger.info(f"Building final bundle in directory: {args.output_dir}")
    bundle_path = create_bundle(
        output_dir_base=args.output_dir,
        model_hash=model_hash,
        constraint_file_path=args.constraint_file,
        constraint_hash=constraint_hash,
        prompt=prompt_text,
        output_text=output_text,
        attestation_result=attestation_result, # Pass the whole dict
        private_key_path=args.key_file,
        include_output_file=not args.skip_output_file
    )

    if not bundle_path:
        logger.error("Failed to create the final bundle.")
        sys.exit(1)

    logger.info(f"✅ Seel bundle generation complete! Bundle saved to: {bundle_path}")

if __name__ == "__main__":
    main() 