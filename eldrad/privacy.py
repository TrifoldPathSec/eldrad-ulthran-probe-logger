"""MAC address anonymization: salted per-session tokens, raw values only on opt-in."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from .frames import is_locally_administered


class MacAnonymizer:
    """Maps a MAC to an HMAC-SHA256 token keyed by a salt.

    By default the salt is random and lives only in memory, so tokens let you
    count devices within one session but cannot be linked across sessions or
    reversed to the original address once the process exits.
    """

    def __init__(self, salt: bytes | None = None, keep_raw: bool = False):
        self.salt = salt or secrets.token_bytes(16)
        self.keep_raw = keep_raw

    def token(self, mac: str) -> str:
        return hmac.new(self.salt, mac.lower().encode(), hashlib.sha256).hexdigest()[:16]

    def raw(self, mac: str) -> str | None:
        return mac.lower() if self.keep_raw else None

    @staticmethod
    def oui(mac: str) -> str | None:
        """Vendor prefix for globally administered MACs; meaningless for randomized ones."""
        return None if is_locally_administered(mac) else mac.lower()[:8]


def load_or_create_salt(path: str | Path) -> bytes:
    """Persistent salt for opt-in cross-session linking. Stored 0600, never commit it."""
    path = Path(path)
    if path.exists():
        return bytes.fromhex(path.read_text().strip())
    salt = secrets.token_bytes(16)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(salt.hex() + "\n")
    return salt
