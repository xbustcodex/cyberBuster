"""Secret-at-rest encryption for plugin credentials.

Fernet key derived from JWT_SECRET via HKDF-SHA256. No new env var required.
"""
from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _fernet() -> Fernet:
    seed = os.environ["JWT_SECRET"].encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"secmaster-plugin-v1", info=b"fernet-key")
    key = base64.urlsafe_b64encode(hkdf.derive(seed))
    return Fernet(key)


def encrypt(plain: str) -> str:
    if plain is None or plain == "":
        return ""
    return _fernet().encrypt(plain.encode("utf-8")).decode("utf-8")


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return ""


def mask(plain: str) -> str:
    if not plain:
        return ""
    if len(plain) <= 8:
        return "•" * len(plain)
    return f"{plain[:4]}{'•' * (len(plain) - 8)}{plain[-4:]}"
