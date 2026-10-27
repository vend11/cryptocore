"""Тесты хеш-функций Sprint 4: NIST, hashlib, CLI, интероп, лавинный эффект."""

import hashlib
import os
import shutil
import subprocess
import sys

import pytest

from cryptocore.hash import compute_file
from cryptocore.hash.sha256 import SHA256
from cryptocore.hash.sha3_256 import SHA3_256

SLOW = os.environ.get("CRYPTOCORE_SLOW_TESTS") == "1"
MSG_56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
MSG_112 = (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
           b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")

SHA256_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (MSG_56, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (MSG_112, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    (b"a" * 1000000,
     "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
]

SHA3_VECTORS = [
    (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
    (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
    (MSG_56, "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
    (MSG_112, "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"),
    (b"a" * 1000000,
     "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1"),
]


def _run_cli(*argv, stdin=None):
    """Запускает CLI отдельным процессом."""
    return subprocess.run(
        [sys.executable, "-m", "cryptocore.main", *argv],
        input=stdin, capture_output=True)


# --- TEST-1: векторы NIST ---


@pytest.mark.parametrize("data, expected", SHA256_VECTORS,
                         ids=["empty", "abc", "2-block", "4-block", "million-a"])
def test_sha256_nist_vectors(data, expected):
    assert SHA256().hash(data) == expected


@pytest.mark.parametrize("data, expected", SHA3_VECTORS,
                         ids=["empty", "abc", "2-block", "4-block", "million-a"])
def test_sha3_nist_vectors(data, expected):
    assert SHA3_256().hash(data) == expected


# --- TEST-2: пустой вход и сверка с hashlib ---


def test_hashlib_cross_check_various_lengths():
    import random
    rng = random.Random(42)
    for n in [0, 1, 2, 54, 55, 56, 57, 63, 64, 65, 127, 128,
              135, 136, 137, 255, 256, 1000, 4096, 8192, 8193]:
        data = rng.randbytes(n)
        assert SHA256().hash(data) == hashlib.sha256(data).hexdigest(), n
        assert SHA3_256().hash(data) == hashlib.sha3_256(data).hexdigest(), n


def test_output_is_lowercase_hex():
    for digest in (SHA256().hash(b"x"), SHA3_256().hash(b"x")):
        assert digest == digest.lower()
        assert len(digest) == 64


# --- HASH-5: потоковая обработка и переиспользование ---


def test_streaming_updates_match_oneshot():
    import random
    rng = random.Random(7)
    data = rng.randbytes(20000)
    for cls, reference in ((SHA256, hashlib.sha256),
                           (SHA3_256, hashlib.sha3_256)):
        for chunk in (1, 3, 64, 65, 135, 136, 137, 4096):
            h = cls()
            for i in range(0, len(data), chunk):
                h.update(data[i:i + chunk])
            assert h.hexdigest() == reference(data).hexdigest(), (cls, chunk)


def test_digest_reusable_and_continuable():
    h = SHA256()
    h.update(b"abc")
    assert h.digest() == h.digest()
    h.update(b"def")
    assert h.hexdigest() == hashlib.sha256(b"abcdef").hexdigest()

    h = SHA3_256()
    h.update(b"abc")
    assert h.digest() == h.digest()
    h.update(b"def")
    assert h.hexdigest() == hashlib.sha3_256(b"abcdef").hexdigest()


def test_padding_structure():
    for size in (0, 1, 55, 56, 63, 64, 100):
        padded = SHA256().padding(b"a" * size)
        assert len(padded) % 64 == 0
        assert padded[size] == 0x80
        assert padded[size + 1:-8] == b"\x00" * (len(padded) - size - 9)
        assert int.from_bytes(padded[-8:], "big") == size * 8


# --- CLI: подкоманда dgst ---


def test_cli_dgst_sha256(tmp_path):
    f = tmp_path / "doc.txt"
    f.write_bytes(b"abc")
    r = _run_cli("dgst", "--algorithm", "sha256", "--input", str(f))
    assert r.returncode == 0
    expected = f"{hashlib.sha256(b'abc').hexdigest()}  {f}\n"
    assert r.stdout.decode() == expected


def test_cli_dgst_sha3_256(tmp_path):
    f = tmp_path / "backup.tar"
    f.write_bytes(b"x" * 1000)
    r = _run_cli("dgst", "--algorithm", "sha3-256", "--input", str(f))
    assert r.returncode == 0
    expected = f"{hashlib.sha3_256(b'x' * 1000).hexdigest()}  {f}\n"
    assert r.stdout.decode() == expected


def test_cli_dgst_algorithm_case_insensitive(tmp_path):
    f = tmp_path / "f.bin"
    f.write_bytes(b"abc")
    r = _run_cli("dgst", "--algorithm", "SHA256", "--input", str(f))
    assert r.returncode == 0
    assert r.stdout.decode().startswith(hashlib.sha256(b"abc").hexdigest())


def test_cli_dgst_empty_file(tmp_path):
    f = tmp_path / "empty"
    f.write_bytes(b"")
    r = _run_cli("dgst", "--algorithm", "sha256", "--input", str(f))
    assert r.returncode == 0
    assert r.stdout.decode() == (
        f"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        f"  {f}\n")


def test_cli_dgst_stdin():
    r = _run_cli("dgst", "--algorithm", "sha256", "--input", "-",
                 stdin=b"abc")
    assert r.returncode == 0
    assert r.stdout.decode() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -\n")


def test_cli_dgst_output_flag(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"abc")
    out = tmp_path / "data.sha256"
    r = _run_cli("dgst", "--algorithm", "sha256", "--input", str(f),
                 "--output", str(out))
    assert r.returncode == 0
    assert r.stdout == b""
    expected = f"{hashlib.sha256(b'abc').hexdigest()}  {f}\n"
    assert out.read_text() == expected


def test_cli_dgst_missing_input_file():
    r = _run_cli("dgst", "--algorithm", "sha256", "--input", "no_such_file.bin")
    assert r.returncode != 0
    assert "error" in r.stderr.decode().lower()


def test_cli_dgst_unknown_algorithm(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    r = _run_cli("dgst", "--algorithm", "md5", "--input", str(f))
    assert r.returncode != 0


@pytest.mark.parametrize("pre_args, post_args", [
    (["--key", "00" * 16], []),
    ([], ["--key", "00" * 16]),
    (["--iv", "00" * 16], []),
    ([], ["--iv", "00" * 16]),
    (["--encrypt"], []),
    ([], ["--encrypt"]),
    (["--decrypt"], []),
    (["--mode", "ctr"], []),
    ([], ["--mode", "ctr"]),
], ids=["key-pre", "key-post", "iv-pre", "iv-post", "enc-pre", "enc-post",
        "dec-pre", "mode-pre", "mode-post"])
def test_cli_dgst_rejects_crypto_args(tmp_path, pre_args, post_args):
    """CLI-3: dgst не принимает --key/--iv/--encrypt/--decrypt/--mode."""
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    argv = [*pre_args, "dgst", "--algorithm", "sha256",
            "--input", str(f), *post_args]
    r = _run_cli(*argv)
    assert r.returncode != 0


def test_cli_dgst_output_overwrite_input(tmp_path):
    f = tmp_path / "same.txt"
    f.write_bytes(b"precious")
    r = _run_cli("dgst", "--algorithm", "sha256",
                 "--input", str(f), "--output", str(f))
    assert r.returncode != 0
    assert "overwrite" in r.stderr.decode().lower()
    assert f.read_bytes() == b"precious"


# --- TEST-3: интероп с системными утилитами ---


def _hash_of(reference_output):
    """Первое поле строки вывода sha256sum/sha3sum."""
    return reference_output.split()[0]


@pytest.mark.skipif(shutil.which("sha256sum") is None,
                    reason="sha256sum not available")
def test_interop_sha256sum(tmp_path):
    f = tmp_path / "interop.bin"
    f.write_bytes(os.urandom(4096))
    mine = _run_cli("dgst", "--algorithm", "sha256", "--input", str(f))
    sysout = subprocess.run(["sha256sum", str(f)], capture_output=True)
    assert mine.returncode == 0
    assert mine.stdout.decode().split()[0] == _hash_of(sysout.stdout.decode())


@pytest.mark.skipif(shutil.which("sha3sum") is None,
                    reason="sha3sum not available")
def test_interop_sha3sum(tmp_path):
    f = tmp_path / "interop.bin"
    f.write_bytes(os.urandom(4096))
    mine = _run_cli("dgst", "--algorithm", "sha3-256", "--input", str(f))
    sysout = subprocess.run(["sha3sum", "-a", "256", str(f)],
                            capture_output=True)
    assert mine.returncode == 0
    assert mine.stdout.decode().split()[0] == _hash_of(sysout.stdout.decode())


# --- TEST-5: лавинный эффект ---


def test_avalanche_effect(capsys):
    """Смена одного бита меняет ~половину бит хеша."""
    original = b"Hello, world!"
    modified = b"Hello, world?"
    bin1 = bin(int(SHA256().hash(original), 16))[2:].zfill(256)
    bin2 = bin(int(SHA256().hash(modified), 16))[2:].zfill(256)
    diff = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))
    print(f"Bits changed: {diff}/256")
    assert 100 < diff < 156


def test_avalanche_single_bit_random():
    import random
    rng = random.Random(1)
    for _ in range(5):
        data = rng.randbytes(64)
        flip = bytearray(data)
        pos = rng.randrange(256)
        flip[pos // 8] ^= 1 << (pos % 8)
        bin1 = bin(int(SHA256().hash(bytes(data)), 16))[2:].zfill(256)
        bin2 = bin(int(SHA256().hash(bytes(flip)), 16))[2:].zfill(256)
        diff = sum(a != b for a, b in zip(bin1, bin2))
        assert 100 < diff < 156


# --- TEST-4 / TEST-6: тяжёлые тесты (CRYPTOCORE_SLOW_TESTS=1) ---


@pytest.mark.skipif(not SLOW,
                    reason="set CRYPTOCORE_SLOW_TESTS=1 (>1GB, медленно)")
def test_large_file_over_1gb(tmp_path):
    """TEST-4: файл больше 1 ГБ хешируется корректно (чанковая обработка)."""
    import hashlib as hl

    f = tmp_path / "big.bin"
    chunk = os.urandom(1 << 20)
    with open(f, "wb") as fh:
        for _ in range(1100):
            fh.write(chunk)
    assert f.stat().st_size > (1 << 30)

    h = SHA256()
    with open(f, "rb") as fh:
        for block in iter(lambda: fh.read(8192), b""):
            h.update(block)
    ref = hl.sha256()
    with open(f, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            ref.update(block)
    assert h.hexdigest() == ref.hexdigest()


@pytest.mark.skipif(not SLOW,
                    reason="set CRYPTOCORE_SLOW_TESTS=1 (замер скорости)")
def test_performance_report(capsys):
    """TEST-6: скорость реализации против hashlib на 2 МБ."""
    import time

    data = os.urandom(1 << 21)
    start = time.perf_counter()
    SHA256().hash(data)
    mine = time.perf_counter() - start
    start = time.perf_counter()
    hashlib.sha256(data).hexdigest()
    ref = time.perf_counter() - start
    print(f"own SHA-256: {2 / mine:.2f} MB/s, hashlib: {2 / ref:.2f} MB/s")
    assert mine > 0