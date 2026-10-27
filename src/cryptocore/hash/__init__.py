"""Хеш-функции проекта и утилита потокового хеширования файлов."""
import sys

from .. import CryptoCoreError
from .sha256 import SHA256, sha256_hex
from .sha3_256 import SHA3_256, sha3_256_hex

ALGORITHMS = {"sha256": SHA256, "sha3-256": SHA3_256}
CHUNK_SIZE = 8192


def compute_file(path, algorithm, chunk_size=CHUNK_SIZE):
    """Считает дайджест файла чанками (константная память), '-' = stdin."""
    try:
        hasher = ALGORITHMS[algorithm]()
        if path == "-":
            while True:
                chunk = sys.stdin.buffer.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        else:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hasher.update(chunk)
        return hasher.hexdigest()
    except OSError as e:
        raise CryptoCoreError(f"cannot read input file: {e}")