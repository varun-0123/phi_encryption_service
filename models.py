# models.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import TypeDecorator, String, Text
from crypto_engine import PHICryptoEngine
import datetime

db = SQLAlchemy()

class EncryptedString(TypeDecorator):
    """
    Transparently encrypts plaintext strings to AES-256-GCM ciphertext on write (bind)
    and decrypts back to plaintext on read (result).
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return PHICryptoEngine.encrypt_field(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return PHICryptoEngine.decrypt_field(value)


class EncryptedJSON(TypeDecorator):
    """
    Transparently encrypts list/dict payloads (e.g., diagnosis codes) to AES-256-GCM.
    """
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return PHICryptoEngine.encrypt_field(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return PHICryptoEngine.decrypt_field(value)


class PatientPHI(db.Model):
    __tablename__ = "patient_phi"

    id = db.Column(db.String(64), primary_key=True)
    patient_name = db.Column(db.String(120), nullable=False)

    # 1. SSN (Encrypted at rest + Searchable Blind Index)
    # The actual column holds the ciphertext
    ssn = db.Column(EncryptedString, nullable=False)
    # Deterministic HMAC hash index for O(1) WHERE lookups
    ssn_bidx = db.Column(db.String(64), index=True, nullable=False)

    # 2. Date of Birth (Encrypted at rest + Blind Index for exact DOB match)
    dob = db.Column(EncryptedString, nullable=False)
    dob_bidx = db.Column(db.String(64), index=True, nullable=False)

    # 3. Diagnosis Codes (Encrypted at rest complex list, e.g., ["E11.9", "I10"])
    diagnosis_codes = db.Column(EncryptedJSON, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def to_dict(self, mask_ssn: bool = False):
        """Returns decrypted patient data, with optional masking for export/UI."""
        raw_ssn = self.ssn
        display_ssn = f"***-**-{raw_ssn[-4:]}" if mask_ssn and raw_ssn else raw_ssn

        return {
            "id": self.id,
            "patient_name": self.patient_name,
            "ssn": display_ssn,
            "dob": self.dob,
            "diagnosis_codes": self.diagnosis_codes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }