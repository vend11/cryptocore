"""Режим OFB: потоковый шифр, гамма не зависит от открытого текста."""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _split(data):
    """Разбивает данные на блоки по 16 байт."""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _xor(a, b):
    """Побайтовый XOR двух блоков."""
    return bytes(x ^ y for x, y in zip(a, b))


def _crypt(key, iv, data):
    """Гамма: register = AES(register); шифрование совпадает с расшифрованием."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    out = []
    register = iv
    for block in _split(data):
        register = cipher.encrypt(register)
        out.append(_xor(block, register))
    return b"".join(out)


def encrypt(key, iv, plaintext):
    """Шифрует данные без паддинга."""
    return _crypt(key, iv, plaintext)


def decrypt(key, iv, ciphertext):
    """Расшифровывает данные без паддинга."""
    return _crypt(key, iv, ciphertext)