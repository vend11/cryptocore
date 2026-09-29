"""Режим CTR: потоковый шифр на основе 128-битного счётчика блоков."""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _split(data):
    """Разбивает данные на блоки по 16 байт."""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _xor(a, b):
    """Побайтовый XOR; обрезает результат до длины меньшего операнда."""
    return bytes(x ^ y for x, y in zip(a, b))


def _increment(block):
    """Увеличивает 128-битный счётчик на 1 (big-endian, с переполнением)."""
    return ((int.from_bytes(block, "big") + 1) % (1 << 128)).to_bytes(BLOCK_SIZE, "big")


def _crypt(key, iv, data):
    """Гамма: AES(IV), AES(IV+1), ...; шифрование совпадает с расшифрованием."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    out = []
    counter = iv
    for block in _split(data):
        out.append(_xor(block, cipher.encrypt(counter)))
        counter = _increment(counter)
    return b"".join(out)


def encrypt(key, iv, plaintext):
    """Шифрует данные без паддинга."""
    return _crypt(key, iv, plaintext)


def decrypt(key, iv, ciphertext):
    """Расшифровывает данные без паддинга."""
    return _crypt(key, iv, ciphertext)