# 🪶 Seel Project

This repository contains the Minimal Viable Prototype (MVP) for Seel, a system for Zero-Knowledge AI Inference Certification.

Refer to `REQUIREMENTS.md` for the high-level goals and `implementation_plan.md` for the development strategy.

## Setup

1.  Clone the repository.
2.  Create a virtual environment: `python -m venv .venv`
3.  Activate the environment:
    *   Windows CMD/PowerShell: `.venv\Scripts\activate`
    *   Linux/macOS/WSL/Git Bash: `source .venv/bin/activate`
4.  Install dependencies: `pip install -r requirements.txt`
    *   *Note:* `torch` installation might vary depending on your system and CUDA availability. The version in `requirements.txt` is a generic CPU/CUDA version. Refer to the [PyTorch website](https://pytorch.org/get-started/locally/) for specific installation commands if needed.

## Usage

1.  **Generate Prover Keys:**
    ```bash
    python -m seel.keygen --key-dir keys --name my_prover
    ```
    This creates `keys/my_prover.pem` (private) and `keys/my_prover.pub.pem` (public) and prints the corresponding `did:key`. Keep the private key safe!

2.  **Create an Input Prompt File:**
    Create a simple text file, e.g., `prompt.txt`, with your desired input prompt:
    ```text:prompt.txt
    Explain the concept of zero-knowledge proofs in simple terms.
    ```

3.  **Generate a Seel Bundle:**
    Run the main CLI, providing the model, prompt, and your private key.
    ```bash
    python -m seel.seel_cli --model distilgpt2 --prompt-file prompt.txt --key-file keys/my_prover.pem
    ```
    *   Optional arguments:
        *   `--constraint-file path/to/constraints.json`: Use custom constraints.
        *   `--output-dir path/to/output`: Specify where to save bundles.
        *   `--max-new-tokens N`: Set max generated tokens.
        *   `--skip-output-file`: Don't save `output.txt` in the bundle.
    *   This will:
        *   Load the model (downloading if needed).
        *   Check prompt & generated output against constraints (`seel/constraints/default.json` by default).
        *   Generate a mock attestation.
        *   Create a timestamped bundle directory inside `output_bundles/` (by default).

4.  **Verify a Seel Bundle:**
    Point the verification tool to the generated bundle directory:
    ```bash
    # Replace <timestamp> with the actual timestamp from the generated bundle directory name
    python -m seel.verify_cli output_bundles/seel_bundle_<timestamp>
    ```
    The tool will perform all necessary checks (signatures, hashes, consistency) and output ✅ VALID or ❌ INVALID.

## Project Structure

(Refer to `implementation_plan.md` for details on modules)

*   `seel/`: Main package code.
*   `seel/constraints/`: Constraint definition files.
*   `keys/`: Default directory for generated keys (.gitignore'd).
*   `output_bundles/`: Default directory for generated bundles (.gitignore'd).
*   `tests/`: Placeholder for future tests.
*   `scripts/`: Placeholder for helper scripts.

## Next Steps & Future Extensions

*   Integrate real ZK proving systems (`ezkl`, `risc0`).
*   Add more sophisticated constraint types (e.g., semantic checks, external classifiers).
*   Implement robust model hashing/verification against known manifests.
*   Add unit and integration tests.
*   Develop a web UI or API interface. 