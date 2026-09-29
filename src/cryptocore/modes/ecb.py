"""Режим ECB: каждый блок шифруется независимо, с паддингом PKCS#7."""

from Crypto.Cipher import AES

from cryptocore.padding import pad, unpad

BLOCK_SIZE = 16


def _split(data):
    """Разбивает данные на блоки по 16 байт."""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def encrypt(key, plaintext):
    """Шифрует: pad -> поблочное AES -> конкатенация блоков."""
    data = pad(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)
    return b"".join(cipher.encrypt(b) for b in _split(data))


def decrypt(key, ciphertext):
    """Расшифровывает и снимает паддинг."""
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ciphertext length must be a positive multiple of 16")
    cipher = AES.new(key, AES.MODE_ECB)
    plain = b"".join(cipher.decrypt(b) for b in _split(ciphertext))
    return unpad(plain)