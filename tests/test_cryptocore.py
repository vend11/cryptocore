"""Тесты CryptoCore: PKCS#7, режимы, CLI, IV, интероперабельность с OpenSSL."""

import os
import shutil
import subprocess
import sys

import pytest
from Crypto.Cipher import AES
from Crypto.Util import Counter

from cryptocore.modes import cbc, cfb, ctr, ecb, ofb
from cryptocore.padding import pad, unpad

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
KEY_HEX = "000102030405060708090a0b0c0d0e0f"

IV_MODES = ("cbc", "cfb", "ofb", "ctr")
MODE_MODULES = {"cbc": cbc, "cfb": cfb, "ofb": ofb, "ctr": ctr}

OPENSSL = shutil.which("openssl")
requires_openssl = pytest.mark.skipif(
    OPENSSL is None, reason="openssl not available")


def _cli():
    exe = shutil.which("cryptocore")
    return [exe] if exe else [sys.executable, "-m", "cryptocore.main"]


def run_cli(*args):
    return subprocess.run(_cli() + list(args), capture_output=True, text=True)


def run_openssl(*args):
    return subprocess.run([OPENSSL, "enc", *args],
                          capture_output=True, text=True)


# --- PKCS#7 ---

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


# --- ECB (Sprint 1) ---

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
    # блок с некорректным паддингом
    block = b"A" * 15 + b"\x00"
    ct = AES.new(KEY, AES.MODE_ECB).encrypt(block)
    with pytest.raises(ValueError):
        ecb.decrypt(KEY, ct)


# --- Спринт 2: векторы NIST SP 800-38A ---

NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST_IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
NIST_CTR_IV = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
NIST_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710")

NIST_EXPECTED = {
    "cbc": (
        "7649abac8119b246cee98e9b12e9197d"
        "5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e22229516"
        "3ff1caa1681fac09120eca307586e1a7"
    ),
    "cfb": (
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "c8a64537a0b3a93fcde3cdad9f1ce58b"
        "26751f67a3cbb140b1808cf187a4f4df"
        "c04b05357c5d1c0eeac4c66f9ff7f2e6"
    ),
    "ofb": (
        "3b3fd92eb72dad20333449f8e83cfb4a"
        "7789508d16918f03f53c52dac54ed825"
        "9740051e9c5fecf64344f7a82260edcc"
        "304c6528f659c77866a510d9c1d6ae5e"
    ),
    "ctr": (
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee"
    ),
}


@pytest.mark.parametrize("mode", IV_MODES)
def test_nist_sp800_38a_vectors(mode):
    mod = MODE_MODULES[mode]
    iv = NIST_CTR_IV if mode == "ctr" else NIST_IV
    ct = mod.encrypt(NIST_KEY, iv, NIST_PLAINTEXT)
    expected = bytes.fromhex(NIST_EXPECTED[mode])
    # у CBC сверху добавлен блок паддинга
    assert ct[:len(expected)] == expected
    assert mod.decrypt(NIST_KEY, iv, ct) == NIST_PLAINTEXT


# --- Спринт 2: режимы ---

@pytest.mark.parametrize("mode", IV_MODES)
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 100])
def test_mode_roundtrip(mode, size):
    # TEST-1: round-trip, включая неполные финальные блоки
    data = os.urandom(size)
    iv = os.urandom(16)
    mod = MODE_MODULES[mode]
    assert mod.decrypt(KEY, iv, mod.encrypt(KEY, iv, data)) == data


@pytest.mark.parametrize("mode", ("cfb", "ofb", "ctr"))
def test_stream_modes_do_not_pad(mode):
    data = os.urandom(37)
    iv = os.urandom(16)
    assert len(MODE_MODULES[mode].encrypt(KEY, iv, data)) == len(data)


def test_cbc_pads_to_block():
    data = os.urandom(37)
    iv = os.urandom(16)
    assert len(cbc.encrypt(KEY, iv, data)) == 48


@pytest.mark.parametrize("mode", IV_MODES)
def test_mode_matches_library_reference(mode):
    data = os.urandom(37)
    iv = os.urandom(16)
    mod = MODE_MODULES[mode]
    ours = mod.encrypt(KEY, iv, data)
    if mode == "cbc":
        ref = AES.new(KEY, AES.MODE_CBC, iv=iv).encrypt(pad(data))
    elif mode == "cfb":
        ref = AES.new(KEY, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(data)
    elif mode == "ofb":
        ref = AES.new(KEY, AES.MODE_OFB, iv=iv).encrypt(data)
    else:
        ctr_param = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        ref = AES.new(KEY, AES.MODE_CTR, counter=ctr_param).encrypt(data)
    assert ours == ref


# --- Спринт 2: CLI и работа с IV ---

@pytest.mark.parametrize("mode", IV_MODES)
def test_cli_roundtrip_iv_modes(tmp_path, mode):
    src = tmp_path / "plain.bin"
    enc = tmp_path / "cipher.bin"
    dec = tmp_path / "result.bin"
    data = os.urandom(53)
    src.write_bytes(data)

    r1 = run_cli("--algorithm", "aes", "--mode", mode, "--encrypt",
                 "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
    assert r1.returncode == 0
    assert len(enc.read_bytes()) >= 16  # минимум IV в файле

    r2 = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt",
                 "--key", KEY_HEX, "--input", str(enc), "--output", str(dec))
    assert r2.returncode == 0
    assert dec.read_bytes() == data


@pytest.mark.parametrize("mode", IV_MODES)
def test_cli_decrypt_with_explicit_iv(tmp_path, mode):
    # IV-3: расшифровка с явным --iv, файл без IV-заголовка
    src = tmp_path / "plain.bin"
    enc = tmp_path / "cipher.bin"
    ct = tmp_path / "cipher_only.bin"
    dec = tmp_path / "result.bin"
    data = os.urandom(53)
    src.write_bytes(data)

    r1 = run_cli("--algorithm", "aes", "--mode", mode, "--encrypt",
                 "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
    assert r1.returncode == 0

    raw = enc.read_bytes()
    ct.write_bytes(raw[16:])

    r2 = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt",
                 "--key", KEY_HEX, "--iv", raw[:16].hex(),
                 "--input", str(ct), "--output", str(dec))
    assert r2.returncode == 0
    assert dec.read_bytes() == data


@pytest.mark.parametrize("mode", IV_MODES)
def test_cli_iv_is_random(tmp_path, mode):
    # IV-1: IV генерируется заново при каждом шифровании
    src = tmp_path / "plain.bin"
    src.write_bytes(b"same plaintext")
    ivs = []
    for i in (1, 2):
        enc = tmp_path / f"c{i}.bin"
        r = run_cli("--algorithm", "aes", "--mode", mode, "--encrypt",
                    "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
        assert r.returncode == 0
        ivs.append(enc.read_bytes()[:16])
    assert ivs[0] != ivs[1]


@pytest.mark.parametrize("mode", IV_MODES)
def test_cli_empty_file_iv_modes(tmp_path, mode):
    src = tmp_path / "empty.bin"
    enc = tmp_path / "e.enc"
    dec = tmp_path / "e.dec"
    src.write_bytes(b"")
    r1 = run_cli("--algorithm", "aes", "--mode", mode, "--encrypt",
                 "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
    r2 = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt",
                 "--key", KEY_HEX, "--input", str(enc), "--output", str(dec))
    assert r1.returncode == 0 and r2.returncode == 0
    assert dec.read_bytes() == b""


def test_cli_iv_rejected_on_encrypt(tmp_path):
    # CLI-2/CLI-3: --iv нельзя при шифровании
    src = tmp_path / "f.txt"
    src.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "cbc", "--encrypt",
                "--key", KEY_HEX, "--iv", "00" * 16, "--input", str(src))
    assert r.returncode != 0
    assert "iv" in r.stderr.lower()


def test_cli_iv_rejected_with_ecb(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "ecb", "--decrypt",
                "--key", KEY_HEX, "--iv", "00" * 16, "--input", str(src))
    assert r.returncode != 0


def test_cli_bad_iv_hex(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "cbc", "--decrypt",
                "--key", KEY_HEX, "--iv", "zz-not-hex", "--input", str(src))
    assert r.returncode != 0
    assert "iv" in r.stderr.lower()


def test_cli_bad_iv_length(tmp_path):
    src = tmp_path / "f.txt"
    src.write_text("abc")
    r = run_cli("--algorithm", "aes", "--mode", "cbc", "--decrypt",
                "--key", KEY_HEX, "--iv", "aabb", "--input", str(src))
    assert r.returncode != 0
    assert "iv length" in r.stderr.lower()


@pytest.mark.parametrize("mode", IV_MODES)
def test_cli_input_too_short_for_iv(tmp_path, mode):
    # IO-3: без --iv файл короче 16 байт — ясная ошибка
    src = tmp_path / "short.bin"
    src.write_bytes(os.urandom(10))
    r = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt",
                "--key", KEY_HEX, "--input", str(src))
    assert r.returncode != 0
    assert "iv" in r.stderr.lower()


@pytest.mark.parametrize("out_name", ["same.txt", "sub/dir/../same.txt"])
def test_cli_output_overwrite_input(tmp_path, out_name):
    # --output не может перезаписать --input, данные не теряются
    src = tmp_path / "same.txt"
    src.write_bytes(b"precious data")
    out = tmp_path / out_name
    r = run_cli("--algorithm", "aes", "--mode", "ecb", "--encrypt",
                "--key", KEY_HEX, "--input", str(src), "--output", str(out))
    assert r.returncode != 0
    assert "overwrite" in r.stderr.lower()
    assert src.read_bytes() == b"precious data"


# --- Спринт 2: интероперабельность с OpenSSL ---

@requires_openssl
@pytest.mark.parametrize("mode", IV_MODES)
def test_openssl_decrypts_our_ciphertext(tmp_path, mode):
    # TEST-2: шифруем своим инструментом, расшифровываем OpenSSL
    src = tmp_path / "plain.bin"
    enc = tmp_path / "cipher.bin"
    ct = tmp_path / "cipher_only.bin"
    out = tmp_path / "openssl_dec.bin"
    data = os.urandom(53)
    src.write_bytes(data)

    r1 = run_cli("--algorithm", "aes", "--mode", mode, "--encrypt",
                 "--key", KEY_HEX, "--input", str(src), "--output", str(enc))
    assert r1.returncode == 0

    raw = enc.read_bytes()
    ct.write_bytes(raw[16:])

    r2 = run_openssl(f"-aes-128-{mode}", "-d", "-K", KEY_HEX,
                     "-iv", raw[:16].hex(),
                     "-in", str(ct), "-out", str(out))
    assert r2.returncode == 0, r2.stderr
    assert out.read_bytes() == data


@requires_openssl
@pytest.mark.parametrize("mode", IV_MODES)
def test_our_tool_decrypts_openssl_ciphertext(tmp_path, mode):
    # TEST-3: шифруем OpenSSL, расшифровываем своим инструментом
    src = tmp_path / "plain.bin"
    ct = tmp_path / "openssl_cipher.bin"
    dec = tmp_path / "result.bin"
    data = os.urandom(53)
    iv = os.urandom(16)
    src.write_bytes(data)

    r1 = run_openssl(f"-aes-128-{mode}", "-K", KEY_HEX, "-iv", iv.hex(),
                     "-in", str(src), "-out", str(ct))
    assert r1.returncode == 0, r1.stderr

    r2 = run_cli("--algorithm", "aes", "--mode", mode, "--decrypt",
                 "--key", KEY_HEX, "--iv", iv.hex(),
                 "--input", str(ct), "--output", str(dec))
    assert r2.returncode == 0, r2.stderr
    assert dec.read_bytes() == data


# --- Sprint 1: CLI-тесты ECB ---

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