"""
tests/test_audit_sealer.py

Phase 5: Unit Tests for Evidence Sealing and Cryptographic Verification
References: PRD (Section 5, Phase 5), DATABASE.md, AGENTS.md, TESTING.md

Verifies:
1. Canonical serialization determinism (key order, whitespace invariance).
2. ECDSA signature generation & verification.
3. AES-256-GCM authenticated encryption & decryption.
4. SHA-256 hash chaining across multiple incident bundles.
5. Detection of ciphertext tampering (AES-GCM tag mismatch).
6. Detection of hash forgery (ECDSA signature failure).
7. Detection of broken hash chain (omitted or swapped links).
"""

import base64
import sys
import os
import copy
import json
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from audit.sealer.key_manager import KeyManager
from audit.sealer.sealer import EvidenceSealer, canonical_serialize, GENESIS_PREV_HASH
from audit.verifier.verifier import EvidenceVerifier


@pytest.fixture
def temp_audit_env(tmp_path):
    """Provides an isolated KeyManager, EvidenceSealer, and EvidenceVerifier in a temp directory."""
    key_dir = str(tmp_path / "keys")
    spool_dir = str(tmp_path / "spool" / "sealed_bundles")
    db_path = str(tmp_path / "spool" / "incident_store.db")

    km = KeyManager(key_dir=key_dir)
    sealer = EvidenceSealer(db_path=db_path, spool_dir=spool_dir, key_manager=km)
    verifier = EvidenceVerifier(key_manager=km)

    return sealer, verifier, km


class TestCanonicalSerialization:
    def test_key_order_invariance(self):
        """Objects with identical keys in different order must yield identical canonical bytes."""
        d1 = {"zebra": 1, "apple": 2, "mango": {"c": 3, "a": 4}}
        d2 = {"apple": 2, "mango": {"a": 4, "c": 3}, "zebra": 1}

        b1 = canonical_serialize(d1)
        b2 = canonical_serialize(d2)

        assert b1 == b2, "Canonical serialization must be independent of key insertion order"
        assert b" " not in b1, "Canonical serialization must not contain whitespace"


class TestEvidenceSealerAndVerifier:
    def test_single_bundle_seal_and_verify(self, temp_audit_env):
        """A single incident bundle seals and verifies successfully."""
        sealer, verifier, _ = temp_audit_env

        payload = {
            "incident_id": "inc-test-001",
            "subject_ip": "192.0.2.10",
            "target_ip": "198.51.100.20",
            "action": "temporary_drop",
            "cookie": 4097,
            "rule_priority": 200,
        }

        bundle = sealer.seal_incident("inc-test-001", payload)

        assert bundle.sequence == 1
        assert bundle.prev_hash == GENESIS_PREV_HASH
        assert len(bundle.record_hash) == 64

        res = verifier.verify_single_bundle(bundle, expected_prev_hash=GENESIS_PREV_HASH)
        assert res.is_valid is True
        assert res.aes_gcm_valid is True
        assert res.hash_valid is True
        assert res.signature_valid is True
        assert res.decrypted_payload == payload

    def test_multi_bundle_chain_continuity(self, temp_audit_env):
        """Sequential incident bundles create a valid unbroken hash chain."""
        sealer, verifier, _ = temp_audit_env

        bundles = []
        for i in range(1, 4):
            payload = {
                "incident_id": f"inc-chain-{i:03d}",
                "event_type": "decision_created",
                "seq_num": i,
            }
            b = sealer.seal_incident(f"inc-chain-{i:03d}", payload)
            bundles.append(b)

        # Check chain link properties
        assert bundles[0].prev_hash == GENESIS_PREV_HASH
        assert bundles[1].prev_hash == bundles[0].record_hash
        assert bundles[2].prev_hash == bundles[1].record_hash

        # Verify full chain
        chain_res = verifier.verify_chain(bundles)
        assert chain_res.is_valid is True
        assert chain_res.total_bundles == 3
        assert chain_res.valid_bundles == 3
        assert chain_res.broken_at_sequence is None


class TestTamperDetection:
    def test_detect_ciphertext_tampering(self, temp_audit_env):
        """Altering one ciphertext byte must trigger AES-GCM authentication failure."""
        sealer, verifier, _ = temp_audit_env

        payload = {"secret_incident_data": "confidential_evidence"}
        bundle = sealer.seal_incident("inc-tamper-01", payload)

        tampered_dict = bundle.to_dict()
        ciphertext = bytearray(base64.b64decode(tampered_dict["ciphertext_b64"]))
        ciphertext[0] ^= 1
        tampered_dict["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
        tampered_bundle = type(bundle)(**tampered_dict)

        res = verifier.verify_single_bundle(tampered_bundle, expected_prev_hash=bundle.prev_hash)
        assert res.is_valid is False
        assert res.aes_gcm_valid is False
        assert "authentication failure" in res.error_message.lower()

    def test_detect_hash_forgery(self, temp_audit_env):
        """Modifying the record_hash without a valid private key must fail ECDSA verification."""
        sealer, verifier, _ = temp_audit_env

        payload = {"data": "authentic"}
        bundle = sealer.seal_incident("inc-forge-01", payload)

        # Forge the record_hash (e.g. attacker tries to change the hash)
        tampered_dict = bundle.to_dict()
        tampered_dict["record_hash"] = "f" * 64
        tampered_bundle = type(bundle)(**tampered_dict)

        res = verifier.verify_single_bundle(tampered_bundle, expected_prev_hash=bundle.prev_hash)
        assert res.is_valid is False
        # The hash check will fail because computed hash != forged hash
        assert res.hash_valid is False

    def test_detect_broken_chain_sequence_gap(self, temp_audit_env):
        """Omitting a bundle from the chain must trigger immediate verification failure."""
        sealer, verifier, _ = temp_audit_env

        bundles = []
        for i in range(1, 4):
            bundles.append(sealer.seal_incident(f"inc-gap-{i}", {"step": i}))

        # Intentionally omit bundle #2 (simulate an attacker dropping an incriminating log)
        broken_chain = [bundles[0], bundles[2]]

        chain_res = verifier.verify_chain(broken_chain)
        assert chain_res.is_valid is False
        assert chain_res.broken_at_sequence == 3
        assert "gap" in chain_res.failure_reason.lower()

    def test_detect_spliced_prev_hash(self, temp_audit_env):
        """Changing the prev_hash link between consecutive bundles is caught."""
        sealer, verifier, _ = temp_audit_env

        b1 = sealer.seal_incident("inc-splice-1", {"step": 1})
        b2 = sealer.seal_incident("inc-splice-2", {"step": 2})

        # Tamper b2's prev_hash to point to genesis instead of b1
        tampered_dict = b2.to_dict()
        tampered_dict["prev_hash"] = GENESIS_PREV_HASH
        tampered_b2 = type(b2)(**tampered_dict)

        res = verifier.verify_single_bundle(tampered_b2, expected_prev_hash=b1.record_hash)
        assert res.is_valid is False
        assert res.chain_link_valid is False
        assert "broken chain" in res.error_message.lower()

