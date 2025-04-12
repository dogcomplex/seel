# Implementation Plan: Seel MVP

This document outlines the steps and refined approach for building the Seel MVP, based on `REQUIREMENTS.md`.

## 🎯 Core Objective

Create a command-line tool that can:
1. Run inference with a specified LLM.
2. Apply basic constraints to the input/output.
3. Generate a "proof bundle" containing metadata, hashes, (mock) proof, and signature.
4. Provide a separate CLI tool to verify the integrity and compliance of this bundle offline.

## 🧱 Refined Modules & Technology Choices

We'll stick to the modular structure proposed but refine the initial technology choices for speed of MVP development:

| Module | Function | Initial Tech Choice | Notes |
|---|---|---|---|
| `keygen.py` | Creates signer keypair + DID-format identity | `cryptography` (ed25519), basic `did:key` formatting | Simple key generation, store as PEM files. |
| `model_loader.py` | Loads model, calculates hash | `transformers`, `hashlib` (SHA256) | Start with `distilgpt2` for simplicity. Hash the model directory/files. |
| `inference_runner.py` | Runs inference with loaded model | `transformers` | Takes model object, prompt, returns output. |
| `constraint_checker.py` | Evaluates prompt + output against rule set | Python (regex, basic checks) | Implement keyword blacklist and max length. Safe classifiers mocked initially. |
| `mock_attestor.py` | **Simulates** ZK proof generation | `hashlib`, `cryptography` | Hashes inputs (model hash, constraints, prompt/output hashes), signs this aggregate hash with the prover key. This *replaces* the complex ZK setup for the MVP. |
| `bundle_builder.py` | Generates `.meta.json` + `.sig` package | `json`, `cryptography` | Creates the final bundle structure, including signing the `meta.json`. |
| `seel_cli.py` | Main CLI entry point (generation) | `argparse`, orchestrates other modules | User interface for generating a proof bundle. |
| `verify_cli.py` | Loads and verifies full bundle offline | `argparse`, `json`, `cryptography` | User interface for verifying a proof bundle. |

**Key Simplifications for MVP:**
- **No Real ZK:** The `mock_attestor.py` provides cryptographic linkage between inputs and the prover's key, simulating the *purpose* of the ZK proof (binding inputs to a compliant execution) without the overhead of setting up `ezkl` or `risc0`.
- **Simple DID:** Use `did:key` format based directly on the public key. No complex DID resolution needed for MVP verification.
- **Basic Constraints:** Focus on easily implemented constraints (keywords, length).

## 📂 Project Structure 

seel/
├── init.py
├── keygen.py
├── model_loader.py
├── inference_runner.py
├── constraint_checker.py
├── mock_attestor.py
├── bundle_builder.py
├── seel_cli.py
├── verify_cli.py
├── utils.py # Shared helper functions (e.g., hashing, key loading)
└── constraints/
└── default.json # Default sample constraints
tests/ # Unit/integration tests (Future)
scripts/ # Helper scripts (e.g., download model)
output_bundles/ # Default output location for generated bundles
keys/ # Default location for generated keys
README.md
requirements.txt
implementation_plan.md # This file


## ⚙️ Development Steps

1.  **Setup & Keygen:**
    - Create project structure and `requirements.txt` (`transformers`, `torch`, `cryptography`, `python-dotenv`).
    - Implement `keygen.py` to generate/save ed25519 keys and print `did:key`.
    - Implement basic key loading in `utils.py`.
2.  **Model Loading & Hashing:**
    - Implement `model_loader.py` to load a model (e.g., `distilgpt2`) using `transformers`.
    - Add function to hash the model's files/directory consistently.
3.  **Constraint Definition & Checking:**
    - Create `constraints/default.json`.
    - Implement `constraint_checker.py` to load rules and check text against them (keyword, length).
4.  **Inference:**
    - Implement `inference_runner.py` to run the loaded model.
5.  **Mock Attestation:**
    - Implement `mock_attestor.py` to create and sign the aggregate hash (model, constraints, prompt/output).
6.  **Bundle Building:**
    - Implement `bundle_builder.py` to assemble the output directory structure, `meta.json`, and `meta.sig`.
7.  **Generation CLI (`seel_cli.py`):**
    - Use `argparse` to take inputs: model path/ID, prompt file, constraint file, key file/path.
    - Orchestrate calls to the other modules to generate a bundle.
8.  **Verification CLI (`verify_cli.py`):**
    - Use `argparse` to take input: bundle directory path.
    - Load `meta.json`, verify `meta.sig` using the prover's public key (derived from `did:key` in metadata).
    - Verify the internal mock attestation signature.
    - Check hash consistency within the bundle.
    - Print ✅ or ❌.
9.  **Documentation & Refinement:**
    - Update `README.md` with usage instructions.
    - Add basic error handling.

## ✅ Acceptance Criteria (MVP)

- Can generate keys using `keygen.py`.
- Can run `seel_cli.py` with a model, prompt, and key to produce a structured output bundle.
- The bundle contains `output.txt` (optional), `model_hash.txt`, `constraint.json`, `mock_proof.json` (containing the aggregate hash and signature), `meta.json`, and `meta.sig`.
- `meta.json` includes the model hash, constraint reference, prompt/output hashes (or placeholders), prover `did:key`, and reference to the mock proof.
- `meta.sig` is a valid signature of `meta.json` using the prover's private key.
- Can run `verify_cli.py` on the generated bundle.
- `verify_cli.py` successfully validates the `meta.sig`, the internal mock proof signature, and hash consistency.
- `verify_cli.py` rejects tampered bundles (e.g., modified metadata, inconsistent hashes).

