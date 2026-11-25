"""
audit/sealer/key_manager.py

Phase 5: Key Management for Cryptographic Evidence Sealing
References: PRD (Section 5, Phase 5), AGENTS.md, DATABASE.md

Constraints (AGENTS.md):
- Never hardcode secrets, keys, tokens, or credentials.
- Keys are loaded from a secure local directory (default: audit/keys/) or environment.
- Automatically generates secure random keys if none exist on startup.
- ECDSA: NIST P-256 (SECP256R1) with SHA-256.
- AES: 256-bit symmetric key for AES-GCM encryption.
"""

import os
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

DEFAULT_KEY_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "keys")
)


class KeyManager:
    """
    Manages ECDSA key pairs and AES-256 symmetric keys for evidence sealing.
    """

    def __init__(self, key_dir: str = DEFAULT_KEY_DIR):
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)
        self.ecdsa_priv_path = os.path.join(self.key_dir, "ecdsa_private.pem")
        self.ecdsa_pub_path = os.path.join(self.key_dir, "ecdsa_public.pem")
        self.aes_key_path = os.path.join(self.key_dir, "aes_256.key")

    def ensure_keys(self) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey, bytes]:
        """
        Loads existing keys from disk or generates fresh keys if not present.
        Returns: (private_key, public_key, aes_key_bytes)
        """
        priv_key = self.get_or_create_ecdsa_private_key()
        pub_key = priv_key.public_key()
        aes_key = self.get_or_create_aes_key()
        return priv_key, pub_key, aes_key

    def get_or_create_ecdsa_private_key(self) -> ec.EllipticCurvePrivateKey:
        """Loads ECDSA P-256 private key from PEM or generates and saves a new one."""
        if os.path.exists(self.ecdsa_priv_path):
            with open(self.ecdsa_priv_path, "rb") as f:
                return serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )

        # Generate fresh NIST P-256 curve key
        priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        pem_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.ecdsa_priv_path, "wb") as f:
            f.write(pem_bytes)
        # Restrict permissions on private key if OS supports it
        try:
            os.chmod(self.ecdsa_priv_path, 0o600)
        except Exception:
            pass

        # Save corresponding public key
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(self.ecdsa_pub_path, "wb") as f:
            f.write(pub_bytes)

        return priv_key

    def get_ecdsa_public_key(self) -> ec.EllipticCurvePublicKey:
        """Loads ECDSA public key from PEM."""
        if not os.path.exists(self.ecdsa_pub_path):
            # Generating private key will also create the public key
            self.get_or_create_ecdsa_private_key()

        with open(self.ecdsa_pub_path, "rb") as f:
            return serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    def get_or_create_aes_key(self) -> bytes:
        """Loads 256-bit (32 bytes) AES key or generates a fresh cryptographically secure key."""
        if os.path.exists(self.aes_key_path):
            with open(self.aes_key_path, "rb") as f:
                key = f.read()
                if len(key) == 32:
                    return key

        # Generate fresh 32 bytes (256 bits) from CSPRNG
        key = os.urandom(32)
        with open(self.aes_key_path, "wb") as f:
            f.write(key)
        try:
            os.chmod(self.aes_key_path, 0o600)
        except Exception:
            pass
        return key

    @property
    def key_id(self) -> str:
        """Returns key identifier for audit trail."""
        return "ecdsa-p256-local-01"

