"""Чистая реализация SHA3-256 по NIST FIPS 202 (губка Keccak, Keccak-f[1600])."""

_MASK = (1 << 64) - 1
_RATE = 136  # 1088 бит, выход 256 бит

# Раундовые константы iota
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

# Смещения rho для лана (x, y)
_ROT = ((0, 36, 3, 41, 18),
        (1, 44, 10, 45, 2),
        (62, 6, 43, 15, 61),
        (28, 55, 25, 21, 56),
        (27, 20, 39, 8, 14))


def _rotl(x, n):
    """Циклический сдвиг 64-битного лана влево."""
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f(a):
    """24 раунда перестановки Keccak-f[1600]; лан i = (x, y), i = x + 5*y."""
    for rc in _RC:
        # theta
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        for x in range(5):
            t = c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                a[x + y] ^= t
        # rho и pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(a[x + 5 * y], _ROT[x][y])
        # chi
        for y in range(0, 25, 5):
            for x in range(5):
                a[x + y] = b[x + y] ^ ((~b[(x + 1) % 5 + y]) & b[(x + 2) % 5 + y])
        # iota
        a[0] ^= rc
    return a


def _pad(msg_len):
    """Паддинг pad10*1 с доменным байтом SHA-3 (0x06)."""
    q = _RATE - (msg_len % _RATE)
    if q == 1:
        return b"\x86"
    return b"\x06" + b"\x00" * (q - 2) + b"\x80"


class SHA3_256:
    """SHA3-256 с потоковым API: update() -> digest(), вход любой длины."""

    block_size = _RATE
    digest_size = 32

    def __init__(self):
        self._a = [0] * 25
        self._buf = bytearray()

    def absorb_block(self, block):
        """XOR-ит блок данных в состояние и применяет Keccak-f."""
        for i in range(_RATE // 8):
            self._a[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f(self._a)

    def update(self, message):
        """Принимает очередную порцию данных любого размера."""
        self._buf += bytes(message)
        while len(self._buf) >= _RATE:
            self.absorb_block(self._buf[:_RATE])
            del self._buf[:_RATE]

    def digest(self):
        """Возвращает 32-байтовый дайджест, не меняя состояние объекта."""
        a = list(self._a)
        tail = bytes(self._buf) + _pad(len(self._buf))
        for i in range(0, len(tail), _RATE):
            for j in range(_RATE // 8):
                a[j] ^= int.from_bytes(tail[i + j * 8:i + j * 8 + 8], "little")
            _keccak_f(a)
        return b"".join(a[i].to_bytes(8, "little") for i in range(4))

    def hexdigest(self):
        """Дайджест строкой в нижнем регистре hex."""
        return self.digest().hex()

    def hash(self, data):
        """Одноразовый хеш: возвращает hex-строку, состояние объекта не трогает."""
        hasher = SHA3_256()
        hasher.update(data)
        return hasher.hexdigest()


def sha3_256_hex(data):
    """Одноразовый SHA3-256 произвольных данных -> hex-строка."""
    return SHA3_256().hash(data)