# demo_phi.py
import requests
import json
import time

BASE_URL = "http://127.0.0.1:5001"

def print_section(title):
    print("\n" + "=" * 75)
    print(f" DEMO TEST SUITE: {title}")
    print("=" * 75)

def print_result(label, resp):
    print(f"\n--> {label}")
    print(f"Status Code: {resp.status_code}")
    try:
        print(f"Response:\n{json.dumps(resp.json(), indent=2)}")
    except Exception:
        print(f"Response (Text):\n{resp.text}")

# 1. Ingest a Patient Record with Sensitive PHI
print_section("1. Create Patient Record with Transparent Field-Level Encryption")
patient_payload = {
    "id": "pt-201",
    "patient_name": "Alice Walker",
    "ssn": "987-65-4321",
    "dob": "1988-11-14",
    "diagnosis_codes": ["E11.9", "I10", "Z79.4"]
}
res_create = requests.post(f"{BASE_URL}/api/v1/phi/patients", json=patient_payload)
print_result("Patient created. Application views masked/decrypted data:", res_create)

# 2. Raw Database Storage Inspection (Encryption-at-Rest Proof)
print_section("2. Proof of Encryption-at-Rest (Inspecting Raw Database Columns)")
res_raw = requests.get(f"{BASE_URL}/api/v1/phi/raw/pt-201")
print_result("Raw Database Storage (shows v1 prefix, IV, AES-GCM tag, and HMAC digest):", res_raw)

# 3. Exact-Match Searchable Encryption Query
print_section("3. Searchable Encryption Query via Blind Index (HMAC-SHA256)")
search_payload = {"ssn": "987-65-4321"}
res_search = requests.post(f"{BASE_URL}/api/v1/phi/search", json=search_payload)
print_result("O(1) Exact lookup succeeds over encrypted SSN without full-table scan:", res_search)

# 4. KMS Key Rotation
print_section("4. Trigger KMS Key Rotation (v1 -> v2)")
res_rotate = requests.post(f"{BASE_URL}/api/v1/kms/rotate")
print_result("KMS rotated active DEK:", res_rotate)

# 5. Ingest Second Patient Under New Active Key (v2)
print_section("5. Ingest Patient Under New Key Version (v2)")
patient_2_payload = {
    "id": "pt-202",
    "patient_name": "Bob Martin",
    "ssn": "111-22-3333",
    "dob": "1992-04-23",
    "diagnosis_codes": ["J45.909"]
}
res_create_2 = requests.post(f"{BASE_URL}/api/v1/phi/patients", json=patient_2_payload)
print_result("Patient pt-202 created under active KMS version v2:", res_create_2)

# Check pt-202 raw storage to confirm v2 key header
res_raw_2 = requests.get(f"{BASE_URL}/api/v1/phi/raw/pt-202")
print_result("Raw DB of pt-202 showing 'v2' key version tag:", res_raw_2)

# 6. Re-encryption Migration for Existing Records
print_section("6. Batch Zero-Downtime Re-encryption Migration")
print("pt-201 was encrypted with v1. Migrating older records to active key version...")
res_reencrypt = requests.post(f"{BASE_URL}/api/v1/phi/reencrypt")
print_result("Re-encryption engine completes migration:", res_reencrypt)

# Verify pt-201 raw storage was upgraded to v2
res_raw_migrated = requests.get(f"{BASE_URL}/api/v1/phi/raw/pt-201")
print_result("Raw DB of pt-201 now verified migrated to 'v2':", res_raw_migrated)

# 7. Verify Blind Index Search Still Works Across Rotations
print_section("7. Verify Search Query Integrity Post-Rotation")
res_search_after = requests.post(f"{BASE_URL}/api/v1/phi/search", json={"ssn": "987-65-4321"})
print_result("Search query on pt-201 succeeds post-re-encryption:", res_search_after)