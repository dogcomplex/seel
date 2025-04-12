# 🪶 Seel

This repository contains the Minimal Viable Prototype (MVP) for Seel, a system for Zero-Knowledge AI Inference Certification.

Refer to `REQUIREMENTS.md` for the high-level goals and `implementation_plan.md` for the development strategy.

## Setup and Installation

**IMPORTANT:** This project currently requires **Windows Subsystem for Linux (WSL)** for building the Risc0 guest code and running the full attestation process due to Risc0 build dependencies and filesystem requirements. All commands below should be run within your WSL distribution (e.g., Ubuntu) unless otherwise specified.

**Prerequisites:**

1.  **WSL:** Ensure you have WSL installed and configured. Ubuntu is recommended.
2.  **Rust:** Install Rust using `rustup`:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env" # Or restart your terminal
    ```
3.  **Python:** Ensure you have Python 3.10+ installed in your WSL environment.
    ```bash
    sudo apt update && sudo apt install python3 python3-pip python3-venv -y # Example for Ubuntu
    ```
4.  **Git:** Ensure Git is installed (`sudo apt install git -y`).

**Installation Steps (within WSL):**

1.  **Clone the Repository:** Clone this repository into your WSL filesystem (e.g., your home directory). Cloning onto the Windows filesystem (`/mnt/c/...`) may cause issues later.
    ```bash
    cd ~ # Navigate to your home directory or desired location
    git clone <repository_url> seel # Replace <repository_url>
    cd seel
    ```

2.  **Install Risc0 Toolchain:** Install `rzup` (the Risc0 toolchain manager) and the necessary components.
    ```bash
    # Install rzup
    curl -L https://risczero.com/install | bash
    source "$HOME/.cargo/env" # Or restart your terminal

    # Install Risc0 components (Rust toolchain, prover, etc.)
    rzup install
    ```
    *Note: `rzup install` should handle setting up the necessary Rust toolchain and Risc0 components.*

3.  **Set up Python Virtual Environment:**
    *   **Important:** Create the virtual environment in your WSL home directory (`~`) to avoid potential filesystem issues when working on mounted Windows drives (`/mnt/...`).
    ```bash
    # Create the venv in your WSL home directory (e.g., ~/.venv/seel-venv)
    python3 -m venv ~/.venv/seel-venv
    # Activate the venv using the absolute path
    source ~/.venv/seel-venv/bin/activate
    ```
    *You should see `(seel-venv)` at the beginning of your terminal prompt. You can now run subsequent commands from your project directory (`/mnt/g/...` or wherever you cloned it).*

4.  **Install Python Dependencies (within activated venv):**
    *   Navigate back to your project directory if you aren't there:
        ```bash
        cd /path/to/your/seel/project # e.g., cd /mnt/g/loki/locus/seel
        ```
    *   First, upgrade pip:
        ```bash
        pip install --upgrade pip
        ```
    *   Modify `requirements.txt` to comment out `risc0-zkvm`:
        *   Open `requirements.txt` in a text editor (e.g., `nano requirements.txt`).
        *   Find the line `risc0-zkvm>=1.0,<2.0 ...` and ensure it is commented out (starts with `#`).
        *   Save the file (Ctrl+X, then Y, then Enter in nano).
    *   Install the requirements:
        ```bash
        # Installs transformers, torch, ezkl, optimum, etc.
        pip install -r requirements.txt 
        ```

5.  **ZK Attestor Python Package Status:**
    *   **Risc0 (`risc0-zkvm`): UNAVAILABLE**
        *   **Blocker:** As of April 2025, the `risc0-zkvm` Python package is **not available** on the standard PyPI repository or common mirrors (e.g., Tsinghua). `pip install risc0-zkvm` fails. The Risc0 toolchain (`rzup`) also does not reliably install the necessary Python components in a detectable way for standard Python environments.
        *   **Result:** Risc0 attestation cannot be used in this project currently.
    *   **ezkl (`ezkl`): INSTALLED BUT BLOCKED**
        *   **Blocker:** While the `ezkl` Python package installs successfully via pip, integrating it with the `distilgpt2` model is blocked during the setup phase. Specifically, `ezkl.gen_settings` fails with a `RuntimeError: Failed to generate settings: [graph] [tract] Undetermined symbol in expression: <Sym1>`. This occurs even when using `optimum` for ONNX export with fixed shapes and different opsets. It indicates `ezkl`/`tract` cannot statically analyze the complexity of the exported ONNX graph for this transformer model with current settings.
        *   **Result:** ezkl attestation cannot be used in this project currently without further investigation and potentially significant changes to the model export or `ezkl` configuration.

**Building the Risc0 Guest Code (Optional - Cannot be used by Host):**

*   If the Risc0 toolchain (`rzup`) was installed successfully, you can optionally still build the guest code to explore it independently. However, the resulting ELF/Image ID **cannot** be used by the Python host code in this project due to the missing `risc0-zkvm` Python library.

1.  **Navigate to Guest Directory:**
    ```bash
    cd risc0-guest
    ```
2.  **Build:**
    ```bash
    cargo risczero build
    ```

**~~Configure the Python Host Code:~~ (Not Applicable for Risc0/ezkl)**

*   Since the `risc0-zkvm` Python library cannot be installed, the Risc0 attestor code (`seel/risc0_attestor.py`) cannot function, and configuring it is unnecessary.

## Usage (within WSL)

Ensure your Python virtual environment is activated (`source ~/.venv/seel-venv/bin/activate`) and you are in the project's root directory (e.g., `/mnt/g/loki/locus/seel`).

1.  **Generate Keys (if needed):**
    ```bash
    mkdir keys # If the directory doesn't exist
    python -m seel.key_utils generate keys/my_prover
    ```

2.  **Create Input Files:**
    *   `prompt.txt`: Create a file with your desired LLM prompt.
    *   `seel/constraints/default.json`: (Optional) Modify constraints if needed.

3.  **Generate a Seel Bundle:**
    *   **Only Mock Attestation (`--attestor mock`) is currently functional:**
        ```bash
        python -m seel.seel_cli --model <model_name> --prompt-file prompt.txt --key-file keys/my_prover.pem --attestor mock
        ```
        *Replace `<model_name>` (e.g., `distilgpt2`).*
    *   **Risc0 Attestation (`--attestor risc0`):** Unavailable (Python package missing).
    *   **ezkl Attestation (`--attestor ezkl`):** Blocked (Setup fails on model graph analysis).

4.  **Verify a Seel Bundle:**
    *   Verification currently only works for bundles created with the mock attestor.
    ```bash
    python -m seel.verify_cli output_bundles/seel_bundle_<timestamp>
    ```
    *Replace `<timestamp>` with the actual timestamp of the bundle you want to verify.*

## Future Steps / Known Issues

*   **Risc0 Integration:**
    *   **Issue:** `risc0-zkvm` Python package unavailable via pip.
    *   **Possible Next Steps:**
        *   Monitor the Risc0 project for official alternative installation methods (e.g., Conda packages, updated `rzup` installers, direct source build instructions).
        *   If Risc0 updates its Python packaging, revisit integration, potentially requiring updates to both the guest (Rust) and host (Python) code to match newer Risc0 versions.
*   **ezkl Integration:**
    *   **Issue:** `ezkl.gen_settings` fails with `Undetermined symbol in expression` for the exported `distilgpt2` ONNX model.
    *   **Possible Next Steps:**
        *   Consult `ezkl` documentation and community resources (GitHub issues, Discord) for specific guidance on handling transformer models (like GPT-2/distilgpt2).
        *   Investigate required parameters for `ezkl.gen_settings` (e.g., `scale`, `logrows`, `input_visibility`, `output_visibility`) or specific ONNX export settings needed by `ezkl` to resolve the graph analysis error.
        *   Experiment with simpler ONNX models to isolate the issue.
        *   Consider alternative models known to be more compatible with `ezkl`.
*   **ONNX Export Warnings:** The `optimum` ONNX export shows warnings about numerical differences. While potentially acceptable, this could impact ZK proof generation/verification if high precision is required by the ZK scheme.
*   **Constraint System:** The current constraint checker is basic. Future work could involve more sophisticated constraint types and enforcement mechanisms.

## Resuming in WSL / Troubleshooting

If your WSL terminal crashes or you open a new one, follow these steps to reactivate your environment and resume working on the project:

1.  **Open WSL Terminal.**
2.  **Navigate to Project Directory:**
    ```bash
    cd /mnt/g/loki/locus/seel # Or your project path
    ```
3.  **Ensure Rust is in PATH:**
    ```bash
    source "$HOME/.cargo/env"
    ```
4.  **Activate Python venv:**
    ```bash
    # Activate using the absolute path to where you created it
    source ~/.venv/seel-venv/bin/activate
    ```

Now you can run `pip`, `cargo`, `python -m seel...` commands.

**If `cargo risczero build` (inside `risc0-guest` dir) fails:**

*   Ensure you have run `rzup install` successfully.
*   Ensure you have run `rustup target add --toolchain nightly riscv32im-risc0-zkvm-elf` successfully.
*   Ensure you have installed `build-essential` in WSL (`sudo apt install build-essential`).
*   Try cleaning the guest build artifacts: `cd risc0-guest && cargo clean && cargo risczero build`

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