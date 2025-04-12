**Title:** 🪶 Seel — zkAICP MVP Spec: Minimal Viable Prototype for Zero-Knowledge AI Inference Certification

**Overview:**
This MVP defines the minimal working system to validate an AI model inference under a constraint set, produce a verifiable zk-proof, and package the result as a certifiable bundle that can be validated by any compliant peer — without leaking prompt, output, or model internals.

---

## 🎯 Goals

- ✅ Prove model identity from hash + signed manifest
- ✅ Enforce constraint logic on prompt/output
- ✅ Emit zk-proof of compliant inference
- ✅ Sign and bundle the full result
- ✅ Allow offline verification of the entire output bundle

---

## 🧱 Modules

| Module | Function |
|--------|----------|
| `model_runner.py` | Loads model, runs inference, checks constraints |
| `constraint_checker.py` | Evaluates prompt + output against rule set |
| `zk_attest.py` | Generates zk-proof of safe execution (mock/real) |
| `bundle_builder.py` | Generates `.meta.json` + `.sig` package |
| `verifier_cli.py` | Loads and verifies full bundle offline |
| `keygen.py` | Creates signer keypair + DID-format identity |

---

## 📦 Output Bundle Structure

```
zk_bundle/
├── output.txt             # (optional) Generated text
├── model_hash.txt         # SHA256 hash of model weights
├── constraint.json        # Human-readable constraints
├── proof.zkp              # zk-proof file
├── meta.json              # Metadata, hashes, constraint ref
└── meta.sig               # Signature from prover DID
```

---

## 🔧 Functional Requirements

| ID | Requirement |
|----|-------------|
| F1 | Must hash model weights and validate against known signed fingerprint |
| F2 | Must evaluate a constraint set against prompt/output before finalizing bundle |
| F3 | Must emit ZK proof (or mock proof) of valid constraint execution path |
| F4 | Must package metadata + proof + output into standard format |
| F5 | Must sign meta with `ed25519` key, verifiable as a DID |
| F6 | Must allow verification from another peer with no knowledge of prompt/output |

---

## 🧪 Sample Constraint File (`constraint.json`)
```json
{
  "prohibited_keywords": ["AGI", "nuke", "virus"],
  "max_length": 1024,
  "safe_classifiers": ["openai/nsfw-detector-v2"]
}
```

---

## ⚙️ Tech Stack

- 🤖 Model: `GPT-J`, `Mistral-7B` (HF weights)
- 🔐 ZK Layer: `ezkl`, `risc0`, or mock circuit w/ metadata hash
- 🧩 Constraint Logic: Regex matching + safe-classifier pass
- ✍️ Signing: `ed25519` via `cryptography` or `did:key`
- 📦 Packaging: JSON with embedded hashes and references
- 🖥️ CLI Tools: Python 3, argparse, optional web UI later

---

## 🚀 User Flow

1. User selects model + prompt file
2. System loads model, hashes weights
3. Constraint runner checks prompt/output
4. zk-proof is generated that constraints were honored
5. Bundle is signed + saved
6. Verifier on another machine runs CLI tool:
    - Confirms hash matches
    - Confirms valid proof
    - Confirms signer ID
    - Returns: ✅ Compliant | ❌ Rejected

---

## 🕒 Timeline (Solo Dev w/ AI Support)

| Task | Days |
|------|------|
| Model hashing + manifest check | 1 |
| Constraint engine | 2 |
| Inference runner + CLI | 2 |
| zk-proof wrapper (mock to real) | 3–5 |
| Bundle builder | 1 |
| Verifier tool | 2 |

Total: ~10–14 days MVP

---

## 🔮 Future Extensions

- zk-Auditor AI integration
- Web-based UI for upload/verification
- Multisig validator cert bundles
- P2P distribution (.torrent + webseed auto-push)
- Full hardware attestation integration (SGX/SEV)

---

**Status:** Ready for handoff to dev team (Cursor IDE, Gemini 2.5 Pro, or equivalent).

**Project Codename:** Seel 🪶 *(official)* / 🦭 *(unofficial, for mischief)* — The act of sealing trust into silence, and silence into proof.

