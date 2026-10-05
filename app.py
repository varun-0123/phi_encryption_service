# app.py
from flask import Flask, request, jsonify
from models import db, PatientPHI
from kms import kms_client
from crypto_engine import PHICryptoEngine
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///phi_secure.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

# ----------------- PHI RECORD CREATION -----------------
@app.route("/api/v1/phi/patients", methods=["POST"])
def create_patient():
    data = request.get_json() or {}
    required = ["id", "patient_name", "ssn", "dob", "diagnosis_codes"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    if PatientPHI.query.filter_by(id=data["id"]).first():
        return jsonify({"error": "Patient already exists"}), 409

    # Generate blind index digests for searchable fields
    ssn_digest = PHICryptoEngine.compute_blind_index(data["ssn"])
    dob_digest = PHICryptoEngine.compute_blind_index(data["dob"])

    patient = PatientPHI(
        id=data["id"],
        patient_name=data["patient_name"],
        ssn=data["ssn"],            # EncryptedString handles AES-GCM
        ssn_bidx=ssn_digest,        # Stored HMAC digest for exact lookup
        dob=data["dob"],            # EncryptedString handles AES-GCM
        dob_bidx=dob_digest,
        diagnosis_codes=data["diagnosis_codes"] # EncryptedJSON handles AES-GCM
    )

    db.session.add(patient)
    db.session.commit()

    return jsonify({
        "status": "created",
        "patient": patient.to_dict(mask_ssn=True)
    }), 201


# ----------------- SEARCHABLE ENCRYPTION QUERY -----------------
@app.route("/api/v1/phi/search", methods=["POST"])
def search_by_ssn():
    """
    Demonstrates exact-match query over encrypted PHI:
    Computes HMAC of search input and performs an index lookup without decrypting table rows.
    """
    data = request.get_json() or {}
    target_ssn = data.get("ssn")
    if not target_ssn:
        return jsonify({"error": "Target ssn required for query"}), 400

    # 1. Compute blind index digest of search parameter
    target_bidx = PHICryptoEngine.compute_blind_index(target_ssn)

    # 2. Query against indexed column
    record = PatientPHI.query.filter_by(ssn_bidx=target_bidx).first()
    if not record:
        return jsonify({"message": "No record found"}), 404

    return jsonify({
        "status": "found",
        "patient": record.to_dict()
    }), 200


# ----------------- RAW STORAGE INSPECTION (PROOF OF ENCRYPTION) -----------------
@app.route("/api/v1/phi/raw/<patient_id>", methods=["GET"])
def get_raw_storage(patient_id):
    """
    Inspect raw stored database columns directly to demonstrate encryption-at-rest to TL.
    """
    with db.engine.connect() as conn:
        result = conn.execute(
            db.text("SELECT id, patient_name, ssn, ssn_bidx, dob, diagnosis_codes FROM patient_phi WHERE id = :pid"),
            {"pid": patient_id}
        ).fetchone()

    if not result:
        return jsonify({"error": "Not found"}), 404

    return jsonify({
        "raw_storage_view": {
            "id": result[0],
            "patient_name": result[1],
            "ssn_raw_ciphertext": result[2],
            "ssn_blind_index": result[3],
            "dob_raw_ciphertext": result[4],
            "diagnosis_codes_raw_ciphertext": result[5]
        }
    }), 200


# ----------------- KEY ROTATION & RE-ENCRYPTION -----------------
@app.route("/api/v1/kms/rotate", methods=["POST"])
def rotate_key():
    """Rotates active KMS key to next version."""
    new_version = kms_client.rotate_key()
    return jsonify({
        "status": "rotated",
        "active_version": new_version
    }), 200


@app.route("/api/v1/phi/reencrypt", methods=["POST"])
def reencrypt_records():
    """
    Zero-downtime maintenance: re-encrypts records created with older key versions
    to the latest KMS key version.
    """
    active_version, _ = kms_client.get_active_dek()
    reencrypted_count = 0

    records = PatientPHI.query.all()
    for rec in records:
        # Check raw column text version prefix
        raw_ssn = db.session.execute(
            db.text("SELECT ssn FROM patient_phi WHERE id = :id"), {"id": rec.id}
        ).scalar()

        if PHICryptoEngine.needs_reencryption(raw_ssn):
            # Touching the fields forces EncryptedString to re-encrypt with current active DEK
            rec.ssn = rec.ssn
            rec.dob = rec.dob
            rec.diagnosis_codes = rec.diagnosis_codes
            reencrypted_count += 1

    db.session.commit()

    return jsonify({
        "status": "reencryption_complete",
        "active_key_version": active_version,
        "records_migrated": reencrypted_count
    }), 200

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "service": "Field-Level PHI Encryption & Tokenization Service",
        "status": "online",
        "kms_active_key_version": kms_client.active_version,
        "endpoints": {
            "create_patient": "POST /api/v1/phi/patients",
            "search_by_ssn": "POST /api/v1/phi/search",
            "inspect_raw_db": "GET /api/v1/phi/raw/<patient_id>",
            "rotate_kms_key": "POST /api/v1/kms/rotate",
            "batch_reencrypt": "POST /api/v1/phi/reencrypt"
        }
    }), 200

if __name__ == "__main__":
    app.run(port=5001, debug=True)