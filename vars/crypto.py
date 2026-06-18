"""Symmetric encryption for variable values (encrypted at rest).

Values are encrypted with Fernet (AES-128-CBC + HMAC). Multiple keys are
supported via MultiFernet so the master key can be rotated: the first key is
used for new writes, all keys are tried for decryption.

The master key(s) come from ``settings.KEYMAKER_MASTER_KEYS`` and are NEVER
stored in the database.
"""
from cryptography.fernet import Fernet, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    keys = settings.KEYMAKER_MASTER_KEYS
    if not keys:
        raise ImproperlyConfigured(
            "KEYMAKER_MASTER_KEY is not set. Generate one with:\n"
            "  python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
    try:
        _fernet = MultiFernet([Fernet(k.encode()) for k in keys])
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(f"Invalid KEYMAKER_MASTER_KEY: {exc}") from exc
    return _fernet


def encrypt(plaintext: str) -> bytes:
    """Encrypt a string value, returning ciphertext bytes for DB storage."""
    return _get_fernet().encrypt((plaintext or "").encode("utf-8"))


def decrypt(token: bytes) -> str:
    """Decrypt stored ciphertext bytes back into the original string."""
    if not token:
        return ""
    if isinstance(token, memoryview):
        token = token.tobytes()
    return _get_fernet().decrypt(bytes(token)).decode("utf-8")
