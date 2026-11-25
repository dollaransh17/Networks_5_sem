"""
audit/sealer/sealer.py

Phase 5: Evidence Bundle Sealer
References: PRD (Section 5, Phase 5), DATABASE.md, AGENTS.md, ARCHITECTURE.md

Key Rules (AGENTS.md & DATABASE.md):
1. Never rewrite an already sealed record; add a linked event.
2. Canonical Serialization: deterministic JSON (sorted keys, compact separators).
3. Hash Chaining: SHA-256(canonical_payload + prev_hash).
   Genesis bundle uses 64 zeros as prev_hash ("0" * 64).
4. Digital Signature: ECDSA NIST P-256 over record_hash.
5. Authenticated Encryption: AES-256-GCM with fresh 12-byte nonce per bundle.
6. Persistence: Saves sealed bundle JSON to local spool directory
   and records entry in SQLite table `sealed_bundles`.
"""

import os
import sys
import json
import time
import base64
import hashlib
import sqlite3
import uuid
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from audit.sealer.key_manager import KeyManager

GENESIS_PREV_HASH = "0" * 64
DEFAULT_SPOOL_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "spool", "sealed_bundles")
)
DEFAULT_DB_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "spool", "incident_store.db")
)


@dataclass
class SealedBundle:
    """Represents a cryptographically sealed evidence bundle."""
    bundle_id: str
    incident_id: str
    sequence: int
    prev_hash: str
    record_hash: str
    signature_hex: str
    signing_key_id: str
    enc_alg: str
    nonce_b64: str
    tag_b64: str
    ciphertext_b64: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SealedBundle":
        return cls(**data)


def canonical_serialize(obj: Any) -> bytes:
    """
    Serializes a Python object to canonical deterministic UTF-8 JSON bytes:
    - Keys sorted alphabetically
    - No unnecessary whitespace (separators=(',', ':'))
    - Strict UTF-8 encoding
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class EvidenceSealer:
    """
    Seals incident records into a tamper-evident, append-only cryptographic chain.
    """

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        spool_dir: str = DEFAULT_SPOOL_DIR,
        key_manager: Optional[KeyManager] = None,
    ):
        self.db_path = db_path
        self.spool_dir = spool_dir
        self.km = key_manager or KeyManager()

        os.makedirs(self.spool_dir, exist_ok=True)
        self._init_db_schema()

        # Cache last sealed bundle state for fast sequential sealing
        self._last_bundle: Optional[SealedBundle] = self._load_last_bundle_from_db()

    def _init_db_schema(self) -> None:
        """Ensures sealed_bundles and chain_checkpoints tables exist per DATABASE.md."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sealed_bundles (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                sequence INTEGER NOT NULL UNIQUE,
                record_hash CHAR(64) NOT NULL,
                prev_hash CHAR(64) NOT NULL,
                signature_alg TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                enc_alg TEXT NOT NULL,
                nonce TEXT NOT NULL,
                tag TEXT NOT NULL,
                key_ref TEXT NOT NULL,
                s3_bucket TEXT,
                s3_key TEXT,
                s3_version_id TEXT,
                created_at TEXT NOT NULL,
                verified_at TEXT,
                verification_result TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chain_checkpoints (
                id TEXT PRIMARY KEY,
                chain_id TEXT NOT NULL,
                head_hash CHAR(64) NOT NULL,
                sequence INTEGER NOT NULL,
                anchored_to TEXT,
                anchored_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _load_last_bundle_from_db(self) -> Optional[SealedBundle]:
        """Loads the most recent bundle from SQLite to resume chain continuity."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, incident_id, sequence, prev_hash, record_hash,
                   signature_alg, signing_key_id, enc_alg, nonce, tag, created_at
            FROM sealed_bundles
            ORDER BY sequence DESC LIMIT 1
        """)
        row = cur.fetchone()
        conn.close()
        if not row:
            return None

        # Look up ciphertext in spool file
        bundle_file = os.path.join(self.spool_dir, f"bundle_{row[2]:06d}_{row[0]}.json")
        ciphertext_b64 = ""
        sig_hex = ""
        if os.path.exists(bundle_file):
            try:
                with open(bundle_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    ciphertext_b64 = data.get("ciphertext_b64", "")
                    sig_hex = data.get("signature_hex", "")
            except Exception:
                pass

        return SealedBundle(
            bundle_id=row[0],
            incident_id=row[1],
            sequence=row[2],
            prev_hash=row[3],
            record_hash=row[4],
            signature_hex=sig_hex,
            signing_key_id=row[6],
            enc_alg=row[7],
            nonce_b64=row[8],
            tag_b64=row[9],
            ciphertext_b64=ciphertext_b64,
            created_at=row[10],
        )

    def seal_incident(
        self,
        incident_id: str,
        payload_data: Dict[str, Any],
    ) -> SealedBundle:
        """
        Seals an incident's evidence into a new cryptographically chained bundle.

        Steps:
        1. Canonical serialization of payload_data.
        2. Hash chaining: record_hash = SHA256(canonical_payload + prev_hash).
        3. ECDSA signature over record_hash.
        4. AES-256-GCM encryption with fresh 12-byte nonce.
        5. Atomic persistence to spool and SQLite.
        """
        priv_key, pub_key, aes_key = self.km.ensure_keys()

        # Step 1: Canonical payload
        canonical_bytes = canonical_serialize(payload_data)

        # Step 2: Determine sequence and previous hash
        if self._last_bundle is None:
            sequence = 1
            prev_hash = GENESIS_PREV_HASH
        else:
            sequence = self._last_bundle.sequence + 1
            prev_hash = self._last_bundle.record_hash

        # Hash: SHA-256(canonical_payload + prev_hash)
        hasher = hashlib.sha256()
        hasher.update(canonical_bytes)
        hasher.update(prev_hash.encode("ascii"))
        record_hash = hasher.hexdigest()

        # Step 3: ECDSA signature over record_hash bytes
        signature = priv_key.sign(
            record_hash.encode("ascii"),
            ec.ECDSA(hashes.SHA256())
        )
        sig_hex = signature.hex()

        # Step 4: AES-256-GCM encryption
        # Fresh 12-byte random nonce per bundle
        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        # Encrypt produces ciphertext + 16-byte authentication tag appended at the end
        encrypted_raw = aesgcm.encrypt(nonce, canonical_bytes, None)
        ciphertext = encrypted_raw[:-16]
        tag = encrypted_raw[-16:]

        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        tag_b64 = base64.b64encode(tag).decode("ascii")
        ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")

        bundle_id = f"bnd-{uuid.uuid4().hex[:12]}"
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        bundle = SealedBundle(
            bundle_id=bundle_id,
            incident_id=incident_id,
            sequence=sequence,
            prev_hash=prev_hash,
            record_hash=record_hash,
            signature_hex=sig_hex,
            signing_key_id=self.km.key_id,
            enc_alg="AES-256-GCM",
            nonce_b64=nonce_b64,
            tag_b64=tag_b64,
            ciphertext_b64=ciphertext_b64,
            created_at=now_iso,
        )

        # Step 5: Persist locally
        self._save_bundle(bundle)
        self._last_bundle = bundle

        return bundle

    def _save_bundle(self, bundle: SealedBundle) -> None:
        """Saves sealed bundle to local disk spool and updates SQLite."""
        # 1. Disk JSON spool
        spool_file = os.path.join(self.spool_dir, f"bundle_{bundle.sequence:06d}_{bundle.bundle_id}.json")
        with open(spool_file, "w", encoding="utf-8") as f:
            json.dump(bundle.to_dict(), f, indent=2)

        # 2. SQLite record
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO sealed_bundles (
                id, incident_id, sequence, record_hash, prev_hash,
                signature_alg, signing_key_id, enc_alg, nonce, tag,
                key_ref, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            bundle.bundle_id, bundle.incident_id, bundle.sequence,
            bundle.record_hash, bundle.prev_hash,
            "ECDSA-SHA256", bundle.signing_key_id, bundle.enc_alg,
            bundle.nonce_b64, bundle.tag_b64, self.km.key_id,
            bundle.created_at
        ))

        # Update checkpoint head
        cur.execute("""
            INSERT OR REPLACE INTO chain_checkpoints (
                id, chain_id, head_hash, sequence, anchored_to, anchored_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "head-checkpoint", "main-incident-chain",
            bundle.record_hash, bundle.sequence, "local-store", bundle.created_at
        ))

        conn.commit()
        conn.close()

    @property
    def chain_length(self) -> int:
        return self._last_bundle.sequence if self._last_bundle else 0

    @property
    def head_hash(self) -> str:
        return self._last_bundle.record_hash if self._last_bundle else GENESIS_PREV_HASH

