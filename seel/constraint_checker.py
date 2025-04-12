import json
import re
import logging
import os

logger = logging.getLogger(__name__)

def load_constraints(filepath: str) -> dict:
    """Loads constraints from a JSON file."""
    try:
        with open(filepath, 'r') as f:
            constraints = json.load(f)
        logger.info(f"Loaded constraints from: {filepath}")
        # Basic validation (can be expanded)
        if not isinstance(constraints.get("prohibited_keywords"), list):
            logger.warning(f"'prohibited_keywords' missing or not a list in {filepath}")
            constraints["prohibited_keywords"] = []
        if not isinstance(constraints.get("max_length"), int):
            logger.warning(f"'max_length' missing or not an integer in {filepath}")
            constraints["max_length"] = None # Or a default large value
        return constraints
    except FileNotFoundError:
        logger.error(f"Constraint file not found: {filepath}")
        return None
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from constraint file: {filepath}")
        return None
    except Exception as e:
        logger.error(f"Error loading constraints from {filepath}: {e}", exc_info=True)
        return None

def check_constraints(text: str, constraints: dict) -> tuple[bool, list[str]]:
    """
    Checks if the given text complies with the loaded constraints.

    Args:
        text: The text to check (e.g., prompt or model output).
        constraints: The dictionary of constraints loaded from JSON.

    Returns:
        A tuple: (is_compliant: bool, violations: list[str])
    """
    if not constraints:
        logger.warning("No constraints provided, assuming compliant.")
        return True, []

    violations = []

    # Check max length
    max_len = constraints.get("max_length")
    if max_len is not None and len(text) > max_len:
        violations.append(f"Exceeds max length ({len(text)} > {max_len})")

    # Check prohibited keywords (case-insensitive)
    prohibited = constraints.get("prohibited_keywords", [])
    if prohibited:
        # Use regex for word boundaries to avoid partial matches (e.g., "assess" matching "ass")
        # Compile a single pattern for efficiency
        # We make it case-insensitive with re.IGNORECASE
        pattern = r'\b(' + '|'.join(re.escape(word) for word in prohibited) + r')\b'
        found_keywords = re.findall(pattern, text, re.IGNORECASE)
        if found_keywords:
            violations.append(f"Contains prohibited keywords: {list(set(kw.lower() for kw in found_keywords))}")

    # Placeholder for future safe classifiers check
    # safe_classifiers = constraints.get("safe_classifiers", [])
    # if safe_classifiers:
    #    logger.warning("Safe classifier checks are not implemented in MVP.")
    #    # Add mock check or actual implementation here later

    is_compliant = not bool(violations)
    if not is_compliant:
        logger.warning(f"Constraint violations found: {violations}")
    else:
        logger.info("Text complies with constraints.")

    return is_compliant, violations

# Example Usage
if __name__ == '__main__':
    constraints_path = os.path.join(os.path.dirname(__file__), 'constraints', 'default.json')
    if not os.path.exists(constraints_path):
        print(f"Error: Default constraints file not found at {constraints_path}. Run from project root or adjust path.")
    else:
        loaded_constraints = load_constraints(constraints_path)

        if loaded_constraints:
            print("\n--- Constraint Checking Test ---")
            test_text_good = "This is a short and safe message."
            compliant, violations = check_constraints(test_text_good, loaded_constraints)
            print(f"Text: '{test_text_good}'")
            print(f"Compliant: {compliant}, Violations: {violations}")

            test_text_bad_len = "This text is definitely way too long" * 50 # Make it exceed 512
            compliant, violations = check_constraints(test_text_bad_len, loaded_constraints)
            print(f"\nText: '{test_text_bad_len[:50]}...'")
            print(f"Compliant: {compliant}, Violations: {violations}")

            test_text_bad_keyword = "This message contains a secret keyword."
            compliant, violations = check_constraints(test_text_bad_keyword, loaded_constraints)
            print(f"\nText: '{test_text_bad_keyword}'")
            print(f"Compliant: {compliant}, Violations: {violations}")

            test_text_bad_both = "This SECRET message is also way too long" * 50
            compliant, violations = check_constraints(test_text_bad_both, loaded_constraints)
            print(f"\nText: '{test_text_bad_both[:50]}...'")
            print(f"Compliant: {compliant}, Violations: {violations}")
            print("-------------------------------") 