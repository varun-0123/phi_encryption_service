# kms.py
import os
import base64
from typing import Dict, Tuple

class MockKMSClient:
    """
    Simulates an enterprise KMS/HSM (e.g., AWS KMS, HashiCorp Vault Transit Engine, GCP KMS).
    Manages versioned 256-bit AES Data Encryption Keys (DEKs) and dedicated Blind Index Hash Keys.
    """
    def __init__(self):
        # Dictionary of key_version -> 32-byte binary key
        self._dek_keyring: Dict[str, bytes] = {}
        # Dedicated blind index HMAC key (separated from cipher keys for cryptosecurity)
        self._index_key: bytes = os.urandom(32)
        
        # Initialize primary Key Version 1 (v1)
        self.active_version = "v1"
        self._dek_keyring[self.active_version] = os.urandom(32)

    def get_active_dek(self) -> Tuple[str, bytes]:
        """Returns the current active key version and its 32-byte key."""
        return self.active_version, self._dek_keyring[self.active_version]

    def get_dek_by_version(self, version: str) -> bytes:
        """Retrieves an older or current DEK for decryption."""
        if version not in self._dek_keyring:
            raise KeyError(f"Key version '{version}' not found in KMS keyring.")
        return self._dek_keyring[version]

    def get_blind_index_key(self) -> bytes:
        """Returns the stable HMAC key used for deterministic searchable digests."""
        return self._index_key

    def rotate_key(self) -> str:
        """Rotates the primary DEK to the next version (e.g., v1 -> v2)."""
        curr_num = int(self.active_version.replace("v", ""))
        new_version = f"v{curr_num + 1}"
        self._dek_keyring[new_version] = os.urandom(32)
        self.active_version = new_version
        return self.active_version

# Global KMS instance
kms_client = MockKMSClient()