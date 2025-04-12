import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, GenerationConfig
import logging

logger = logging.getLogger(__name__)

def run_inference(model: AutoModelForCausalLM, tokenizer: AutoTokenizer, prompt: str, max_new_tokens: int = 100, device: str = "auto") -> str | None:
    """
    Runs inference using the provided model, tokenizer, and prompt.

    Args:
        model: The loaded Hugging Face Causal LM model.
        tokenizer: The loaded Hugging Face tokenizer.
        prompt: The input text prompt.
        max_new_tokens: The maximum number of new tokens to generate.
        device: The device to use for inference.

    Returns:
        The generated text string (including the prompt if not skipped).
        Returns None if inference fails.
    """
    logger.info(f"Running inference with prompt: '{prompt[:50]}...' ({len(prompt)} chars)")

    # Determine device (CPU or CUDA)
    # Force CPU for now to avoid compatibility issues in WSL/different environments
    resolved_device = "cpu" # 'cuda' if torch.cuda.is_available() and device == "auto" else "cpu"
    logger.info(f"Using device: {resolved_device}")

    # Prepare inputs
    try:
        inputs = tokenizer(prompt, return_tensors="pt").to(resolved_device)
    except Exception as e:
        logger.error(f"Error tokenizing prompt: {e}")
        return None

    # Set generation config
    # Using a simple config, can be expanded
    generation_config = GenerationConfig(
        max_new_tokens=max_new_tokens,
        pad_token_id=tokenizer.eos_token_id, # Use EOS token ID for padding
        eos_token_id=tokenizer.eos_token_id,
        do_sample=False, # Using greedy decoding for simplicity
        # Add other parameters like temperature, top_k, top_p if needed for sampling
    )

    # Move model to device if not already there (though load_model usually handles this)
    if model.device.type != resolved_device:
        try:
            model.to(resolved_device)
        except Exception as e:
            logger.error(f"Error moving model to device {resolved_device}: {e}")
            return None

    # Run generation
    try:
        # Ensure model is in evaluation mode
        model.eval()
        with torch.no_grad(): # Disable gradient calculation for inference
            outputs = model.generate(
                **inputs,
                generation_config=generation_config
            )

        # Decode output
        # outputs[0] contains the full sequence (prompt + generation)
        # We need to decode only the newly generated part.
        input_length = inputs.input_ids.shape[1]
        generated_ids = outputs[0][input_length:]
        output_text = tokenizer.decode(generated_ids, skip_special_tokens=True)
        logger.info(f"Inference completed. Generated {len(generated_ids)} tokens.")
        return output_text.strip() # Strip leading/trailing whitespace

    except Exception as e:
        logger.error(f"Error during inference: {e}", exc_info=True)
        return None

# Example Usage
if __name__ == '__main__':
    from seel.model_loader import load_model_and_tokenizer
    import time

    model_id = "distilgpt2"
    print(f"\n--- Inference Runner Test ({model_id}) ---")
    print("Loading model (this might take time)...")
    start_load = time.time()
    model, tokenizer, _, _ = load_model_and_tokenizer(model_id)
    load_time = time.time() - start_load
    print(f"Model loaded in {load_time:.2f} seconds.")

    if model and tokenizer:
        test_prompt = "Once upon a time,"
        print(f"Running inference for prompt: '{test_prompt}'")
        start_infer = time.time()
        generated_output = run_inference(model, tokenizer, test_prompt, max_new_tokens=30)
        infer_time = time.time() - start_infer

        if generated_output:
            print(f"\nGenerated Text (took {infer_time:.2f}s):")
            print(generated_output)
        else:
            print("Inference failed.")
        print("---------------------------------")
    else:
        print(f"Could not load model {model_id} for inference test.") 