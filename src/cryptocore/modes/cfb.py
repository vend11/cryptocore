"""Режим CFB (CFB128): потоковый шифр, обратная связь по шифртексту."""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _split(data):
    """Разбивает данные на блоки по 16 байт."""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _xor(a, b):
    """Побайтовый XOR; обрезает результат до длины меньшего операнда."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(key, iv, plaintext):
    """Шифрует без паддинга: C_i = P_i XOR E(register), register = C_{i-1}."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    out = []
    register = iv
    for block in _split(plaintext):
        ct = _xor(block, cipher.encrypt(register))
        out.append(ct)
        register = ct  # неполный последний блок дальше не используется
    return b"".join(out)


def decrypt(key, iv, ciphertext):
    """Расшифровывает без паддинга; в регистр идёт шифртекст."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if not ciphertext:
        return b""
    cipher = AES.new(key, AES.MODE_ECB)
    out = []
    register = iv
    for block in _split(ciphertext):
        out.append(_xor(block, cipher.encrypt(register)))
        register = block
    return b"".join(out)