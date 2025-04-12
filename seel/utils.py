import os
import base58
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib
import logging

# Configure logger
logger = logging.getLogger(__name__)

# Ed25519 specific prefix for multicodec (0xed = ed25519-pub, 0x01 = varint length 1)
MULTICODEC_ED25519_PUB_PREFIX = b'\xed\x01'

def generate_did_key(public_key: ed25519.Ed25519PublicKey) -> str:
    """Generates a did:key string (RFC draft) from an Ed25519 public key."""
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    # Prepend the multicodec prefix for ed25519-pub
    multicodec_public_bytes = MULTICODEC_ED25519_PUB_PREFIX + public_bytes
    # Base58 encode the result (specifically base58btc, indicated by 'z')
    did_key_encoded = base58.b58encode(multicodec_public_bytes).decode('utf-8')
    return f"did:key:z{did_key_encoded}"

def save_key_pem(key: ed25519.Ed25519PrivateKey | ed25519.Ed25519PublicKey, filepath: str, is_private: bool):
    """Saves a key to a PEM file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    pem_encoding = serialization.Encoding.PEM
    pem_format = serialization.PrivateFormat.PKCS8 if is_private else serialization.PublicFormat.SubjectPublicKeyInfo
    encryption_algorithm = serialization.NoEncryption() if is_private else None # Public keys aren't encrypted

    pem_args = {
        "encoding": pem_encoding,
        "format": pem_format
    }
    if is_private:
        pem_args["encryption_algorithm"] = encryption_algorithm

    pem_bytes = key.private_bytes(**pem_args) if is_private else key.public_bytes(**pem_args)

    with open(filepath, "wb") as f:
        f.write(pem_bytes)
    logger.debug(f"Saved {'private' if is_private else 'public'} key to {filepath}")

def load_private_key_pem(filepath: str) -> ed25519.Ed25519PrivateKey:
    """Loads a private key from a PEM file."""
    logger.debug(f"Loading private key from {filepath}")
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None # Assuming no password for MVP
        )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise TypeError(f"Key loaded from {filepath} is not an Ed25519 private key")
    return private_key

def load_public_key_pem(filepath: str) -> ed25519.Ed25519PublicKey:
    """Loads a public key from a PEM file."""
    logger.debug(f"Loading public key from {filepath}")
    with open(filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise TypeError(f"Key loaded from {filepath} is not an Ed25519 public key")
    return public_key

def hash_directory(directory_path: str) -> str:
    """Calculates a SHA256 hash of the contents of a directory."""
    logger.debug(f"Calculating SHA256 hash for directory: {directory_path}")
    hasher = hashlib.sha256()
    if not os.path.isdir(directory_path):
        raise NotADirectoryError(f"Provided path is not a directory: {directory_path}")

    # Walk through the directory, hashing file contents in a deterministic order
    for root, dirs, files in os.walk(directory_path):
        # Sort directory and file names to ensure consistent hash order
        dirs.sort()
        files.sort()

        for filename in files:
            file_path = os.path.join(root, filename)
            try:
                with open(file_path, 'rb') as f:
                    while True:
                        # Read file in chunks to handle large files
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        hasher.update(chunk)
            except IOError as e:
                # Handle potential read errors (e.g., permission denied)
                logger.warning(f"Warning: Could not read file {file_path} for hashing: {e}")
                # Optionally, skip the file or raise an error depending on desired robustness
                # hasher.update(f"Error reading {filename}".encode())

    hex_digest = hasher.hexdigest()
    logger.debug(f"Directory hash calculated: {hex_digest}")
    return hex_digest

def hash_string(input_string: str, algorithm: str = 'sha256') -> str:
    """Hashes a string using the specified algorithm (default: sha256)."""
    hasher = hashlib.new(algorithm)
    hasher.update(input_string.encode('utf-8'))
    hex_digest = hasher.hexdigest()
    logger.debug(f"Hashed string ('{input_string[:20]}...') using {algorithm}: {hex_digest}")
    return hex_digest

def parse_did_key(did_key_str: str) -> bytes | None:
    """Parses a did:key string and returns the raw public key bytes if it's ed25519."""
    logger.debug(f"Parsing did:key: {did_key_str}")
    if not did_key_str.startswith("did:key:z"): # z indicates base58btc multicodec
        logger.warning(f"Invalid DID key format (must start with did:key:z): {did_key_str}")
        return None

    encoded_part = did_key_str[len("did:key:z"):]
    try:
        decoded_bytes = base58.b58decode(encoded_part)
        # Check for the Ed25519 prefix (0xed01)
        if decoded_bytes.startswith(MULTICODEC_ED25519_PUB_PREFIX):
            # Return the key bytes *after* the prefix
            key_bytes = decoded_bytes[len(MULTICODEC_ED25519_PUB_PREFIX):]
            logger.debug(f"Extracted Ed25519 key bytes (length {len(key_bytes)}) from DID.")
            return key_bytes
        else:
            logger.warning(f"DID key does not have the expected Ed25519 prefix (0xed01): {did_key_str}")
            return None
    except Exception as e:
        logger.error(f"Error decoding base58 or parsing DID key {did_key_str}: {e}", exc_info=True)
        return None

def public_key_from_bytes(key_bytes: bytes) -> ed25519.Ed25519PublicKey | None:
    """Creates an Ed25519PublicKey object from raw key bytes."""
    logger.debug(f"Creating Ed25519PublicKey from {len(key_bytes)} bytes.")
    try:
        # Ed25519PublicKey.from_public_bytes expects 32 bytes
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
        logger.debug("Successfully created Ed25519PublicKey object.")
        return public_key
    except ValueError as e:
         # cryptography raises ValueError for incorrect length / format
        logger.error(f"Invalid public key length or format for Ed25519: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to create Ed25519PublicKey from bytes: {e}", exc_info=True)
        return None