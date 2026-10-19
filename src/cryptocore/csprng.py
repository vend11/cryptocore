"""Криптостойкий источник случайных байтов (CSPRNG) для ключей и IV.

Использует os.urandom: системный источник энтропии (getrandom() /
/dev/urandom), пригоден для генерации ключей и IV.
"""

import os

from cryptocore import CryptoCoreError


def generate_random_bytes(num_bytes: int) -> bytes:
    """Возвращает num_bytes криптостойких случайных байтов."""
    if not isinstance(num_bytes, int) or num_bytes <= 0:
        raise ValueError("num_bytes must be a positive integer")
    try:
        return os.urandom(num_bytes)
    except (OSError, NotImplementedError) as exc:
        raise CryptoCoreError(
            f"cannot generate secure random bytes: {exc}") from exc