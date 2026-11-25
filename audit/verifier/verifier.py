"""
audit/verifier/verifier.py

Phase 5: Evidence Chain Verifier
References: PRD (Section 5, Phase 5), DATABASE.md, AGENTS.md, TESTING.md

Verifies:
1. AES-256-GCM Decryption & Authentication Tag: detects payload tampering.
2. Canonical Hash Integrity: SHA-256(canonical_payload + prev_hash) == record_hash.
3. ECDSA Signature Verification: confirms the bundle was signed by the authorized private key.
4. Hash Chain Continuity: prev_hash == prior.record_hash (detects omitted, reordered, or spliced bundles).
5. Genesis Anchor Verification: bundle 1 must have prev_hash == "0" * 64.
"""

import os
import json
import base64
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidTag

from audit.sealer.sealer import SealedBundle, canonical_serialize, GENESIS_PREV_HASH
from audit.sealer.key_manager import KeyManager


@dataclass
class BundleVerificationResult:
    bundle_id: str
    sequence: int
    is_valid: bool
    aes_gcm_valid: bool
    hash_valid: bool
    signature_valid: bool
    chain_link_valid: bool
    error_message: Optional[str] = None
    decrypted_payload: Optional[Dict[str, Any]] = None


@dataclass
class ChainVerificationResult:
    is_valid: bool
    total_bundles: int
    valid_bundles: int
    broken_at_sequence: Optional[int] = None
    failure_reason: Optional[str] = None
    bundle_results: List[BundleVerificationResult] = None


class EvidenceVerifier:
    """
    Independent cryptographic auditor for sealed evidence bundles.
    """

    def __init__(self, key_manager: Optional[KeyManager] = None):
        self.km = key_manager or KeyManager()

    def verify_single_bundle(
        self,
        bundle: SealedBundle,
        expected_prev_hash: Optional[str] = None,
        pub_key: Optional[ec.EllipticCurvePublicKey] = None,
        aes_key: Optional[bytes] = None,
    ) -> BundleVerificationResult:
        """
        Performs full cryptographic validation of a single bundle:
        - AES-256-GCM auth tag verification & decryption.
        - Canonical SHA-256 recalculation.
        - ECDSA signature check.
        - Previous hash link check (if expected_prev_hash is provided).
        """
        public_key = pub_key or self.km.get_ecdsa_public_key()
        encryption_key = aes_key or self.km.get_or_create_aes_key()

        # 1. Chain link check
        chain_link_ok = True
        if expected_prev_hash is not None:
            if bundle.prev_hash != expected_prev_hash:
                chain_link_ok = False
                return BundleVerificationResult(
                    bundle_id=bundle.bundle_id,
                    sequence=bundle.sequence,
                    is_valid=False,
                    aes_gcm_valid=False,
                    hash_valid=False,
                    signature_valid=False,
                    chain_link_valid=False,
                    error_message=f"Broken chain: prev_hash {bundle.prev_hash[:16]}... does not match expected {expected_prev_hash[:16]}...",
                )

        # 2. AES-256-GCM Decryption and Tag Check
        aesgcm = AESGCM(encryption_key)
        try:
            nonce = base64.b64decode(bundle.nonce_b64)
            tag = base64.b64decode(bundle.tag_b64)
            ciphertext = base64.b64decode(bundle.ciphertext_b64)
            combined_ciphertext = ciphertext + tag

            decrypted_bytes = aesgcm.decrypt(nonce, combined_ciphertext, None)
            decrypted_payload = json.loads(decrypted_bytes.decode("utf-8"))
            aes_ok = True
        except (InvalidTag, Exception) as exc:
            return BundleVerificationResult(
                bundle_id=bundle.bundle_id,
                sequence=bundle.sequence,
                is_valid=False,
                aes_gcm_valid=False,
                hash_valid=False,
                signature_valid=False,
                chain_link_valid=chain_link_ok,
                error_message=f"AES-256-GCM authentication failure (payload tampered or wrong key): {exc}",
            )

        # 3. Canonical Hash Check
        canonical_bytes = canonical_serialize(decrypted_payload)
        hasher = hashlib.sha256()
        hasher.update(canonical_bytes)
        hasher.update(bundle.prev_hash.encode("ascii"))
        computed_hash = hasher.hexdigest()

        hash_ok = (computed_hash == bundle.record_hash)
        if not hash_ok:
            return BundleVerificationResult(
                bundle_id=bundle.bundle_id,
                sequence=bundle.sequence,
                is_valid=False,
                aes_gcm_valid=True,
                hash_valid=False,
                signature_valid=False,
                chain_link_valid=chain_link_ok,
                error_message=f"Hash mismatch: computed {computed_hash} != record_hash {bundle.record_hash}",
            )

        # 4. ECDSA Signature Verification
        try:
            sig_bytes = bytes.fromhex(bundle.signature_hex)
            public_key.verify(
                sig_bytes,
                bundle.record_hash.encode("ascii"),
                ec.ECDSA(hashes.SHA256())
            )
            sig_ok = True
        except (InvalidSignature, Exception) as exc:
            return BundleVerificationResult(
                bundle_id=bundle.bundle_id,
                sequence=bundle.sequence,
                is_valid=False,
                aes_gcm_valid=True,
                hash_valid=True,
                signature_valid=False,
                chain_link_valid=chain_link_ok,
                error_message=f"ECDSA signature verification failed (forged signature or tampered hash): {exc}",
            )

        return BundleVerificationResult(
            bundle_id=bundle.bundle_id,
            sequence=bundle.sequence,
            is_valid=True,
            aes_gcm_valid=True,
            hash_valid=True,
            signature_valid=True,
            chain_link_valid=True,
            decrypted_payload=decrypted_payload,
        )

    def verify_chain(self, bundles: List[SealedBundle]) -> ChainVerificationResult:
        """
        Verifies an ordered sequence of sealed bundles from genesis to head.
        Ensures unbroken continuity and cryptographic authenticity of every link.
        """
        if not bundles:
            return ChainVerificationResult(
                is_valid=True, total_bundles=0, valid_bundles=0, bundle_results=[]
            )

        # Sort bundles by sequence to check chronological chain
        sorted_bundles = sorted(bundles, key=lambda b: b.sequence)
        bundle_results: List[BundleVerificationResult] = []

        pub_key = self.km.get_ecdsa_public_key()
        aes_key = self.km.get_or_create_aes_key()

        expected_prev_hash = GENESIS_PREV_HASH

        for i, bundle in enumerate(sorted_bundles):
            # Check expected sequence numbering
            expected_seq = i + 1
            if bundle.sequence != expected_seq:
                return ChainVerificationResult(
                    is_valid=False,
                    total_bundles=len(bundles),
                    valid_bundles=len(bundle_results),
                    broken_at_sequence=bundle.sequence,
                    failure_reason=f"Sequence gap: expected {expected_seq}, found {bundle.sequence}",
                    bundle_results=bundle_results,
                )

            res = self.verify_single_bundle(
                bundle,
                expected_prev_hash=expected_prev_hash,
                pub_key=pub_key,
                aes_key=aes_key,
            )
            bundle_results.append(res)

            if not res.is_valid:
                return ChainVerificationResult(
                    is_valid=False,
                    total_bundles=len(bundles),
                    valid_bundles=len(bundle_results) - 1,
                    broken_at_sequence=bundle.sequence,
                    failure_reason=res.error_message,
                    bundle_results=bundle_results,
                )

            # Advance expected previous hash for next link
            expected_prev_hash = bundle.record_hash

        return ChainVerificationResult(
            is_valid=True,
            total_bundles=len(bundles),
            valid_bundles=len(bundles),
            bundle_results=bundle_results,
        )

    def load_and_verify_spool(self, spool_dir: str) -> ChainVerificationResult:
        """Reads all JSON bundle files from a directory and verifies the entire chain."""
        if not os.path.exists(spool_dir):
            return ChainVerificationResult(
                is_valid=False, total_bundles=0, valid_bundles=0, failure_reason="Spool dir not found"
            )

        bundle_files = [f for f in os.listdir(spool_dir) if f.startswith("bundle_") and f.endswith(".json")]
        bundles: List[SealedBundle] = []

        for fn in sorted(bundle_files):
            fp = os.path.join(spool_dir, fn)
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    bundles.append(SealedBundle.from_dict(json.load(f)))
            except Exception as e:
                return ChainVerificationResult(
                    is_valid=False, total_bundles=len(bundles), valid_bundles=0,
                    failure_reason=f"Corrupt bundle file {fn}: {e}"
                )

        return self.verify_chain(bundles)

