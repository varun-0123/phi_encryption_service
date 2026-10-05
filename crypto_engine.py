# crypto_engine.py
import os
import hmac
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kms import kms_client

class PHICryptoEngine:
    """
    Cryptographic engine implementing:
    1. Authenticated field-level encryption with AES-256-GCM (12-byte IV + 16-byte Auth Tag).
    2. Format-preserving version headers (e.g., 'v1$<hex_iv>$<hex_ciphertext>').
    3. Searchable blind indices using HMAC-SHA256.
    """

    @classmethod
    def encrypt_field(cls, plaintext_val) -> str:
        """
        Encrypts an arbitrary field value (string, date string, or list/dict) using the active KMS key.
        Output format: <key_version>$<iv_hex>$<ciphertext_and_tag_hex>
        """
        if plaintext_val is None:
            return None

        # Normalize data into bytes via JSON stringification
        norm_str = json.dumps(plaintext_val) if isinstance(plaintext_val, (dict, list)) else str(plaintext_val)
        data_bytes = norm_str.encode("utf-8")

        # 1. Fetch active KMS key
        version, key = kms_client.get_active_dek()

        # 2. Generate a unique 96-bit (12-byte) IV for AES-GCM
        iv = os.urandom(12)
        aesgcm = AESGCM(key)

        # 3. Encrypt (AESGCM produces ciphertext + 16-byte authentication tag appended)
        ciphertext = aesgcm.encrypt(iv, data_bytes, associated_data=None)

        # 4. Pack into transport format
        return f"{version}${iv.hex()}${ciphertext.hex()}"

    @classmethod
    def decrypt_field(cls, packed_val: str):
        """
        Parses key version, fetches appropriate DEK from KMS, and decrypts AES-256-GCM ciphertext.
        """
        if not packed_val:
            return None

        parts = packed_val.split("$")
        if len(parts) != 3:
            raise ValueError("Malformed encrypted payload format. Expected <version>$<iv>$<ciphertext>")

        version, iv_hex, cipher_hex = parts
        key = kms_client.get_dek_by_version(version)

        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(cipher_hex)

        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, associated_data=None)
        raw_str = decrypted_bytes.decode("utf-8")

        # Attempt JSON decoding if the original payload was complex (like diagnosis codes list)
        try:
            return json.loads(raw_str)
        except Exception:
            return raw_str

    @classmethod
    def compute_blind_index(cls, raw_val) -> str:
        """
        Generates a deterministic, cryptographically secure hash digest (HMAC-SHA256)
        for exact-match lookups over encrypted fields.
        """
        if raw_val is None:
            return None

        # Exact match normalization: lowercase and strip whitespace
        normalized = str(raw_val).strip().lower().encode("utf-8")
        h = hmac.new(kms_client.get_blind_index_key(), normalized, hashlib.sha256)
        return h.hexdigest()

    @classmethod
    def needs_reencryption(cls, packed_val: str) -> bool:
        """Checks if a ciphertext was encrypted under an outdated key version."""
        if not packed_val or "$" not in packed_val:
            return False
        ver = packed_val.split("$")[0]
        return ver != kms_client.active_version