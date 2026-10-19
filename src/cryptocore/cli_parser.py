"""Разбор и валидация аргументов командной строки CryptoCore."""

import argparse
import os
import sys

from cryptocore import CryptoCoreError

ALGORITHMS = ("aes",)
MODES = ("ecb", "cbc", "cfb", "ofb", "ctr")
KEY_SIZES = {"aes": 16}
IV_SIZES = {"aes": 16}


def _same_file(path_a, path_b):
    """True, если оба пути указывают на один файл (регистр, symlink, '..')."""
    return (os.path.normcase(os.path.realpath(path_a))
            == os.path.normcase(os.path.realpath(path_b)))


def _is_weak_key(key):
    """True для тривиальных ключей: все байты равны или идут с постоянным шагом."""
    if len(set(key)) < 2:
        return True
    steps = {(b - a) % 256 for a, b in zip(key, key[1:])}
    return len(steps) == 1


def _warn_if_weak_key(key):
    """Предупреждение о слабом ключе в stderr, работу не блокирует."""
    if _is_weak_key(key):
        print("cryptocore: warning: provided key looks weak "
              "(all bytes equal or sequential)", file=sys.stderr)


def build_parser():
    """Собирает argparse-парсер инструмента."""
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="CryptoCore: AES-128 block cipher tool.",
    )
    parser.add_argument("--algorithm", required=True, choices=ALGORITHMS,
                        help="cipher algorithm")
    parser.add_argument("--mode", required=True, choices=MODES,
                        help="mode of operation")
    ops = parser.add_mutually_exclusive_group(required=True)
    ops.add_argument("--encrypt", action="store_true",
                     help="encrypt the input file")
    ops.add_argument("--decrypt", action="store_true",
                     help="decrypt the input file")
    parser.add_argument("--key",
                        help="AES-128 key as a hex string (32 hex chars), "
                             "optional for --encrypt: generated if omitted")
    parser.add_argument("--iv",
                        help="IV as a hex string (32 hex chars), "
                             "decryption of cbc/cfb/ofb/ctr only")
    parser.add_argument("--input", required=True, help="path to the input file")
    parser.add_argument("--output",
                        help="output path (default: INPUT.enc / INPUT.dec)")
    return parser


def parse_args(argv=None):
    """Разбирает аргументы, валидирует ключ, IV и пути, возвращает args."""
    args = build_parser().parse_args(argv)

    if args.key is not None:  # ключ передан явно
        try:
            key = bytes.fromhex(args.key)
        except ValueError:
            raise CryptoCoreError(
                f"invalid key '{args.key}': expected a hexadecimal string") from None
        expected = KEY_SIZES[args.algorithm]
        if len(key) != expected:
            raise CryptoCoreError(
                f"invalid key length: got {len(key)} bytes, "
                f"expected {expected} bytes (AES-128)")
        _warn_if_weak_key(key)
        args.key = key
    elif not args.encrypt:  # при расшифровке ключ обязателен
        raise CryptoCoreError("--key is required for decryption")

    iv = None
    if args.iv is not None:
        # --iv только при расшифровке и не для ECB
        if args.encrypt:
            raise CryptoCoreError(
                "--iv is not allowed in encryption mode: "
                "the IV is generated automatically")
        if args.mode == "ecb":
            raise CryptoCoreError("--iv is not used in ECB mode")
        try:
            iv = bytes.fromhex(args.iv)
        except ValueError:
            raise CryptoCoreError(
                f"invalid IV '{args.iv}': expected a hexadecimal string") from None
        iv_size = IV_SIZES[args.algorithm]
        if len(iv) != iv_size:
            raise CryptoCoreError(
                f"invalid IV length: got {len(iv)} bytes, "
                f"expected {iv_size} bytes")

    if not args.output:  # вывод по умолчанию
        args.output = args.input + (".enc" if args.encrypt else ".dec")

    if _same_file(args.input, args.output):
        raise CryptoCoreError(
            f"output file '{args.output}' would overwrite the input file")

    args.iv = iv
    return args