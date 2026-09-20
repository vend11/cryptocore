import os
import shutil
import subprocess
import sys

import pytest
from Crypto.Cipher import AES

from cryptocore.padding import pad, unpad
from cryptocore.modes import ecb

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KEY_HEX = "000102030405060708090a0b0c0d0e0f"


def _cli():
    exe = shutil.which("cryptocore")
    return [exe] if exe else [sys.executable, "-m", "cryptocore.main"]


def run_cli(*args):
    return subprocess.run(_cli() + list(args), capture_output=True, text=True)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 100])
def test_pkcs7_roundtrip(size):
    data = os.urandom(size)
    assert unpad(pad(data)) == data


def test_pkcs7_full_block_added():
    assert pad(b"A" * 16) == b"A" * 16 + b"\x10" * 16


def test_pkcs7_pad_value():
    assert pad(b"AAAA") == b"AAAA" + b"\x0c" * 12


@pytest.mark.parametrize("bad", [
    b"",
    b"A" * 15,
    b"A" * 15 + b"\x00",
    b"A" * 15 + b"\x02",
    b"A" * 14 + b"\x01\x02",
])
def test_pkcs7_invalid(bad):
    with pytest.raises(ValueError):
        unpad(bad)


@pytest.mark.parametrize("size", [0, 1, 16, 17, 100, 1024])
def test_ecb_roundtrip(size):
    data = os.urandom(size)
    assert ecb.decrypt(KEY, ecb.encrypt(KEY, data)) == data


def test_ecb_output_length():
    assert len(ecb.encrypt(KEY, b"x" * 5)) == 16
    assert len(ecb.encrypt(KEY, b"x" * 16)) == 32


def test_ecb_known_answer():
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = ecb.encrypt(KEY, pt)
    assert ct[:16] == bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


def test_ecb_matches_library_reference():
    for size in (5, 16, 33):
        data = os.urandom(size)
        ref = AES.new(KEY, AES.MODE_ECB).encrypt(pad(data))
        assert ecb.encrypt(KEY, data) == ref


def test_ecb_decrypt_bad_length():
    with pytest.raises(ValueError):
        ecb.decrypt(KEY, b"short")


def test_ecb_decrypt_bad_padding():
    #блок с некорректным паддингом
    block = b"A" * 15 + b"\x00"
    ct = AES.new(KEY, AES.MODE_ECB).encrypt(block)
    with pytest.raises(ValueError):
        ecb.decrypt(KEY, ct)


def test_cli_roundtrip_text(tmp_path):
    src = tmp_path / "plaintext.txt"
    enc = tmp_path / "ciphertext.bin"
    dec = tmp_path / "decrypted.txt"
    src.write_text("Hello, CryptoCore!\n", encoding="utf-8")

    r1 = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                 "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
    r2 = run_cli("--algorithm", "aes", "--mode", "ecb", "--decrypt",
                 "--key", KEY_HEX, "--input", str(enc), "--output", str(dec))
    assert r1.returncode == 0
    assert r2.returncode == 0
    assert dec.read_bytes() == src.read_bytes()


def test_cli_roundtrip_binary_and_defaults(tmp_path):
    src = tmp_path / "data.bin"
    data = os.urandom(1000)
    src.write_bytes(data)

    r1 = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                 "--key", KEY_HEX, "--input", str(src))
    assert r1.returncode == 0
    assert (tmp_path / "data.bin.enc").read_bytes() != data

    r2 = run_cli("--algorithm", "aes", "--mode", "ecb", "--decrypt",
                 "--key", KEY_HEX, "--input", str(tmp_path / "data.bin.enc"))
    assert r2.returncode == 0
    assert (tmp_path / "data.bin.enc.dec").read_bytes() == data


def test_cli_empty_file(tmp_path):
    src = tmp_path / "empty.bin"
    enc = tmp_path / "e.enc"
    dec = tmp_path / "e.dec"
    src.write_bytes(b"")
    r1 = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                 "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
    r2 = run_cli("--algorithm", "aes", "--mode", "ecb", "--decrypt",
                 "--key", KEY_HEX, "--input", str(enc), "--output", str(dec))
    assert r1.returncode == 0 and r2.returncode == 0
    assert dec.read_bytes() == b""


def test_cli_missing_operation():
    r = run_cli("--algorithm", "aes", "--mode", "ecb",
                "--key", KEY_HEX, "--input", "x.txt")
    assert r.returncode != 0
    assert r.stderr


def test_cli_conflicting_flags(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt", "--decrypt",
                "--key", KEY_HEX, "--input", str(f))
    assert r.returncode != 0
    assert r.stderr


def test_cli_bad_key_hex(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--key", "zz-not-hex", "--input", str(f))
    assert r.returncode != 0
    assert "key" in r.stderr.lower()


def test_cli_bad_key_length(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--key", "aabb", "--input", str(f))
    assert r.returncode != 0


def test_cli_missing_input_file(tmp_path):
    r = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--key", KEY_HEX, "--input", str(tmp_path / "nope.txt"))
    assert r.returncode != 0
    assert "nope.txt" in r.stderr