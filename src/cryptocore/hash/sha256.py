"""Чистая реализация SHA-256 по NIST FIPS 180-4."""

_MASK = 0xFFFFFFFF
_BLOCK = 64

# Дробные части квадратных корней первых 8 простых чисел
_H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# Дробные части кубических корней первых 64 простых чисел
_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def _rotr(x, n):
    """Циклический сдвиг 32-битного слова вправо."""
    return ((x >> n) | (x << (32 - n))) & _MASK


class SHA256:
    """SHA-256 с потоковым API: update() -> digest(), вход любой длины."""

    block_size = _BLOCK
    digest_size = 32

    def __init__(self):
        self.h = list(_H0)
        self.k = list(_K)
        self._buf = bytearray()
        self._length = 0

    def padding(self, message):
        """Паддинг полного сообщения: бит '1', нули, 64-битная длина."""
        msg = bytes(message)
        return (msg + b"\x80"
                + b"\x00" * ((55 - len(msg)) % _BLOCK)
                + (len(msg) * 8).to_bytes(8, "big"))

    def process_block(self, block):
        """Сжимает один 512-битный блок в текущее состояние."""
        self._compress(self.h, block)

    def update(self, message):
        """Принимает очередную порцию данных любого размера."""
        data = bytes(message)
        self._length += len(data)
        self._buf += data
        while len(self._buf) >= _BLOCK:
            self._compress(self.h, self._buf[:_BLOCK])
            del self._buf[:_BLOCK]

    def digest(self):
        """Возвращает 32-байтовый дайджест, не меняя состояние объекта."""
        h = list(self.h)
        tail = bytes(self._buf)
        tail += b"\x80" + b"\x00" * ((55 - len(tail)) % _BLOCK)
        tail += (self._length * 8).to_bytes(8, "big")
        for i in range(0, len(tail), _BLOCK):
            self._compress(h, tail[i:i + _BLOCK])
        return b"".join(word.to_bytes(4, "big") for word in h)

    def hexdigest(self):
        """Дайджест строкой в нижнем регистре hex."""
        return self.digest().hex()

    def hash(self, data):
        """Одноразовый хеш: возвращает hex-строку, состояние объекта не трогает."""
        hasher = SHA256()
        hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def _compress(h, block):
        """64 раунда сжатия одного блока (FIPS 180-4, п. 6.2.2)."""
        w = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(16)]
        for t in range(16, 64):
            s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
            s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
            w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK)

        a, b, c, d, e, f, g, hh = h
        for t in range(64):
            big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            t1 = (hh + big_s1 + ch + _K[t] + w[t]) & _MASK
            big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (big_s0 + maj) & _MASK
            hh, g = g, f
            f, e = e, (d + t1) & _MASK
            d, c = c, b
            b, a = a, (t1 + t2) & _MASK

        for i, x in enumerate((a, b, c, d, e, f, g, hh)):
            h[i] = (h[i] + x) & _MASK


def sha256_hex(data):
    """Одноразовый SHA-256 произвольных данных -> hex-строка."""
    return SHA256().hash(data)