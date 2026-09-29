"""Режим CBC: блок открытого текста XOR-ится с предыдущим шифртекстом."""

from Crypto.Cipher import AES

from cryptocore.padding import pad, unpad

BLOCK_SIZE = 16


def _split(data):
    """Разбивает данные на блоки по 16 байт."""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _xor(a, b):
    """Побайтовый XOR двух блоков."""
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(key, iv, plaintext):
    """Шифрует C_i = E(P_i XOR C_{i-1}); для первого блока C_{i-1} = IV."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    out = []
    prev = iv
    for block in _split(pad(plaintext)):
        prev = cipher.encrypt(_xor(block, prev))
        out.append(prev)
    return b"".join(out)


def decrypt(key, iv, ciphertext):
    """Расшифровывает P_i = D(C_i) XOR C_{i-1} и снимает паддинг."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ciphertext length must be a positive multiple of 16")
    cipher = AES.new(key, AES.MODE_ECB)
    out = []
    prev = iv
    for block in _split(ciphertext):
        out.append(_xor(cipher.decrypt(block), prev))
        prev = block
    return unpad(b"".join(out))