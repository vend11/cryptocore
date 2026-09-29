"""Дополнение PKCS#7 до кратности размеру блока AES."""


BLOCK_SIZE = 16


def pad(data):
    """Дополняет data до кратности 16 байтам; всегда добавляет 1..16 байт."""
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n


def unpad(data):
    """Проверяет и убирает PKCS#7-дополнение, при нарушении — ValueError."""
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("data length must be a positive multiple of the block size")
    n = data[-1]
    if not 1 <= n <= BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-n]