import os
from transformers import AutoModelForCausalLM, AutoTokenizer
# HfFolder was moved to huggingface_hub
from huggingface_hub.constants import HF_HUB_CACHE 
from seel.utils import hash_directory
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def load_model_and_tokenizer(model_name_or_path: str) -> tuple:
    """
    Loads a Hugging Face model and tokenizer from a local path or downloads it.
    Calculates the hash of the model directory.

    Args:
        model_name_or_path: The name (on Hugging Face Hub) or local path to the model.

    Returns:
        A tuple containing: (model, tokenizer, model_directory, model_hash)
        Returns (None, None, None, None) if loading fails.
    """
    try:
        logger.info(f"Attempting to load model and tokenizer: {model_name_or_path}")
        # Try loading from local path first, if it exists
        if os.path.isdir(model_name_or_path):
            model_dir = model_name_or_path
            logger.info(f"Found local directory: {model_dir}")
        else:
            # If not a local path, treat as model ID and download/cache
            logger.info(f"Model not found locally. Attempting download/cache for: {model_name_or_path}")
            # Use huggingface_hub constant for the cache directory
            cache_dir = HF_HUB_CACHE
            logger.info(f"Default Hugging Face cache directory: {cache_dir}")
            # This is a bit heuristic; models usually end up in snapshots/ dir
            # We rely on the fact that loading the model below will ensure it's cached.
            # A more robust approach might involve snapshot_download first.
            # However, letting AutoModel handle it simplifies things.
            pass # Defer identifying exact dir until after loading

        # Load model and tokenizer - this handles download if necessary
        model = AutoModelForCausalLM.from_pretrained(model_name_or_path)
        tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)

        # Determine the actual directory after loading (works for cache and local path)
        # The `pretrained_model_name_or_path` attribute points to the resolved location
        model_dir = model.config._name_or_path if hasattr(model.config, '_name_or_path') else model_name_or_path
        # If it was downloaded, it might be a symlink, resolve it
        if not os.path.isdir(model_dir):
             # Fallback if _name_or_path isn't helpful (e.g. not set)
             # We need a better way to find the actual cached model dir.
             # For now, we'll try a common pattern. This is NOT robust.
             # A better way: use huggingface_hub.snapshot_download explicitly first.
             # Using HF_HUB_CACHE here
             possible_cache_path = os.path.join(HF_HUB_CACHE, f"models--{model_name_or_path.replace('/', '--')}", "snapshots")
             if os.path.isdir(possible_cache_path):
                 # Assume the latest snapshot dir is the one
                 snapshots = sorted([d for d in os.listdir(possible_cache_path) if os.path.isdir(os.path.join(possible_cache_path, d))], reverse=True)
                 if snapshots:
                     model_dir = os.path.join(possible_cache_path, snapshots[0])
                 else:
                     raise FileNotFoundError(f"Could not locate cached model directory snapshot for {model_name_or_path}")
             else:
                  raise FileNotFoundError(f"Could not resolve model directory for hashing: {model_name_or_path}")

        logger.info(f"Resolved model directory for hashing: {model_dir}")

        # Calculate hash of the model directory
        model_hash = hash_directory(model_dir)
        logger.info(f"Calculated model hash: {model_hash}")

        return model, tokenizer, model_dir, model_hash

    except Exception as e:
        logger.error(f"Failed to load model {model_name_or_path}: {e}", exc_info=True)
        return None, None, None, None

# Example Usage (can be run directly for testing)
if __name__ == '__main__':
    # Test with a small model ID (will download if not cached)
    model_id = "distilgpt2"
    result = load_model_and_tokenizer(model_id)

    if result[0]:
        model, tokenizer, model_dir, model_hash = result
        print(f"\n--- Model Loading Test ({model_id}) ---")
        print(f"Model loaded: {isinstance(model, AutoModelForCausalLM)}")
        print(f"Tokenizer loaded: {isinstance(tokenizer, AutoTokenizer)}")
        print(f"Model directory: {model_dir}")
        print(f"Model hash: {model_hash}")
        print("---------------------------------------")
    else:
        print(f"Failed to load model: {model_id}")

    # Test with a potentially non-existent local path
    local_path = "./non_existent_model"
    result_local = load_model_and_tokenizer(local_path)
    if not result_local[0]:
        print(f"\nCorrectly failed to load non-existent local model: {local_path}")
    else:
        print(f"\nIncorrectly loaded something for path: {local_path}") 