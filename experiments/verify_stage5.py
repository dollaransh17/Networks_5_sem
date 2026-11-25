#!/usr/bin/env python3
"""
experiments/verify_stage5.py

Phase 5: Evidence Sealing & Audit Chain Verification
References: PRD (Section 5, Phase 5), PLAN.md, AGENTS.md, TESTING.md

Verifies:
  [TEST 1/4] Cryptographic Key Management: ECDSA P-256 & AES-256 key generation / persistence.
  [TEST 2/4] Incident Sealing: Canonical serialization, SHA-256 hash, ECDSA signature, AES-GCM encryption.
  [TEST 3/4] Multi-bundle Hash Chain: Sequential hash linking & unbroken chain verification.
  [TEST 4/4] Tamper Resilience: Automatic detection of corrupted ciphertext, forged hashes, or omitted links.
"""

import base64
import sys
import os
import shutil
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from audit.sealer.key_manager import KeyManager
from audit.sealer.sealer import EvidenceSealer, GENESIS_PREV_HASH
from audit.verifier.verifier import EvidenceVerifier


def run_tests():
    print("=" * 65)
    print("   STAGE 5: CRYPTOGRAPHIC EVIDENCE SEALING & AUDIT VERIFICATION")
    print("=" * 65)

    passed = 0
    total = 4

    temp_dir = tempfile.mkdtemp(prefix="stage5_verify_")
    key_dir = os.path.join(temp_dir, "keys")
    spool_dir = os.path.join(temp_dir, "spool", "sealed_bundles")
    db_path = os.path.join(temp_dir, "spool", "incident_store.db")

    try:
        # -------------------------------------------------------------
        # TEST 1: Key Management
        # -------------------------------------------------------------
        sys.stdout.write("[TEST 1/4] Checking cryptographic key generation & loading... ")
        sys.stdout.flush()

        km = KeyManager(key_dir=key_dir)
        priv_key, pub_key, aes_key = km.ensure_keys()

        if (
            priv_key is not None
            and pub_key is not None
            and len(aes_key) == 32
            and os.path.exists(km.ecdsa_priv_path)
            and os.path.exists(km.ecdsa_pub_path)
        ):
            print(f"PASS (ECDSA: {priv_key.curve.name}, AES: {len(aes_key)*8}-bit key, KeyID: {km.key_id})")
            passed += 1
        else:
            print("FAIL (Key generation or loading failed)")

        # -------------------------------------------------------------
        # TEST 2: Single Incident Sealing & Decryption
        # -------------------------------------------------------------
        sys.stdout.write("[TEST 2/4] Testing incident bundle sealing & decryption... ")
        sys.stdout.flush()

        sealer = EvidenceSealer(db_path=db_path, spool_dir=spool_dir, key_manager=km)
        verifier = EvidenceVerifier(key_manager=km)

        payload_1 = {
            "incident_id": "inc-stage5-001",
            "subject_ip": "192.0.2.10",
            "target_ip": "198.51.100.20",
            "event_type": "decision_created",
            "action_type": "temporary_drop",
            "rule_cookie": 4097,
            "evidence_refs": ["evt-stage5-001"],
        }

        bundle_1 = sealer.seal_incident("inc-stage5-001", payload_1)
        res_1 = verifier.verify_single_bundle(bundle_1, expected_prev_hash=GENESIS_PREV_HASH)

        if (
            res_1.is_valid is True
            and res_1.decrypted_payload == payload_1
            and res_1.hash_valid is True
            and res_1.signature_valid is True
        ):
            print(f"PASS (Bundle: {bundle_1.bundle_id}, Hash: {bundle_1.record_hash[:16]}..., Enc: AES-256-GCM)")
            passed += 1
        else:
            print(f"FAIL (Single bundle verify failed: {res_1.error_message})")

        # -------------------------------------------------------------
        # TEST 3: Multi-Bundle Hash Chain Continuity
        # -------------------------------------------------------------
        sys.stdout.write("[TEST 3/4] Testing sequential hash chain continuity... ")
        sys.stdout.flush()

        payload_2 = {
            "incident_id": "inc-stage5-001",
            "event_type": "rule_processed",
            "switch_id": "s1",
            "rule_cookie": 4097,
        }
        payload_3 = {
            "incident_id": "inc-stage5-001",
            "event_type": "effect_observed",
            "switch_id": "s1",
            "packet_drop_count": 142,
        }

        bundle_2 = sealer.seal_incident("inc-stage5-001", payload_2)
        bundle_3 = sealer.seal_incident("inc-stage5-001", payload_3)

        chain_res = verifier.verify_chain([bundle_1, bundle_2, bundle_3])

        if (
            chain_res.is_valid is True
            and chain_res.total_bundles == 3
            and bundle_2.prev_hash == bundle_1.record_hash
            and bundle_3.prev_hash == bundle_2.record_hash
        ):
            print(f"PASS (Chain length: 3, Genesis -> bnd-2 -> bnd-3 unbroken)")
            passed += 1
        else:
            print(f"FAIL (Chain verification failed: {chain_res.failure_reason})")

        # -------------------------------------------------------------
        # TEST 4: Tamper Resilience
        # -------------------------------------------------------------
        sys.stdout.write("[TEST 4/4] Verifying automatic tamper detection... ")
        sys.stdout.flush()

        # Change a ciphertext byte so Base64 padding cannot absorb the mutation.
        tampered_dict = bundle_2.to_dict()
        ciphertext = bytearray(base64.b64decode(tampered_dict["ciphertext_b64"]))
        ciphertext[0] ^= 1
        tampered_dict["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
        tampered_bundle_2 = type(bundle_2)(**tampered_dict)

        tamper_res = verifier.verify_single_bundle(tampered_bundle_2, expected_prev_hash=bundle_1.record_hash)

        # Simulate omission: skip bundle 2 in the chain
        omitted_chain_res = verifier.verify_chain([bundle_1, bundle_3])

        if (
            tamper_res.is_valid is False
            and tamper_res.aes_gcm_valid is False
            and omitted_chain_res.is_valid is False
            and "gap" in omitted_chain_res.failure_reason.lower()
        ):
            print("PASS (Tampered ciphertext caught by AES-GCM; Omitted bundle caught by sequence check)")
            passed += 1
        else:
            print(f"FAIL (Tamper detection failed: tamper_valid={tamper_res.is_valid}, omission_valid={omitted_chain_res.is_valid})")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("=" * 65)
    print(f"   SUMMARY: {passed} / {total} tests passed")
    print("=" * 65)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)

