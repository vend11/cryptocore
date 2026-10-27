"""Разбор и валидация аргументов командной строки."""

import argparse
import os

from . import CryptoCoreError

ALGORITHMS = ("aes",)
MODES = ("ecb", "cbc", "cfb", "ofb", "ctr")
KEY_SIZES = {"aes": 16}
IV_SIZES = {"aes": 16}
DIGEST_ALGORITHMS = ("sha256", "sha3-256")


def _same_file(path_a, path_b):
    """True, если оба пути указывают на один файл (регистр, symlink, '..')."""
    return (os.path.normcase(os.path.realpath(path_a))
            == os.path.normcase(os.path.realpath(path_b)))


def _build_parser():
    """Собирает парсер: крипто-операции на верхнем уровне + подкоманда dgst."""
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="AES-128 encryption tool and hash calculator")
    parser.add_argument("--algorithm", choices=ALGORITHMS, default="aes",
                        help="algorithm for encryption (aes)")
    parser.add_argument("--mode", choices=MODES, default=None,
                        help="cipher mode (default: ecb)")
    parser.add_argument("--encrypt", action="store_true", help="encrypt")
    parser.add_argument("--decrypt", action="store_true", help="decrypt")
    parser.add_argument("--key", help="hex key (32 hex chars for aes)")
    parser.add_argument("--iv", help="hex IV (32 hex chars)")
    parser.add_argument("--input", help="input file path")
    parser.add_argument("--output", help="output file path")

    sub = parser.add_subparsers(dest="command")
    dgst = sub.add_parser("dgst", help="compute message digest of a file")
    dgst.add_argument("--algorithm", required=True, type=str.lower,
                      choices=DIGEST_ALGORITHMS, help="hash algorithm")
    dgst.add_argument("--input", required=True,
                      help="file to hash ('-' for stdin)")
    dgst.add_argument("--output", help="write 'HASH  PATH' line to file")
    return parser


def _parse_hex(value, name, size):
    """Проверяет hex-строку фиксированной длины, возвращает байты."""
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise CryptoCoreError(f"{name} must be a valid hex string")
    if len(raw) != size:
        raise CryptoCoreError(
            f"invalid {name.lstrip('-')} length: "
            f"{name} must be {size * 2} hex chars ({size} bytes)")
    return raw


def _validate_dgst(args):
    """Правила подкоманды dgst: без крипто-аргументов (CLI-3)."""
    if args.key:
        raise CryptoCoreError("--key is not allowed with dgst")
    if args.iv:
        raise CryptoCoreError("--iv is not allowed with dgst")
    if args.mode:
        raise CryptoCoreError("--mode is not allowed with dgst")
    if args.encrypt or args.decrypt:
        raise CryptoCoreError("--encrypt/--decrypt is not allowed with dgst")
    if args.output and args.input != "-" and _same_file(args.input, args.output):
        raise CryptoCoreError(
            f"output file '{args.output}' would overwrite the input file")


def _validate_crypto(args):
    """Правила шифрования/расшифровки (спринты 1-3)."""
    if args.mode is None:
        args.mode = "ecb"
    if args.encrypt and args.decrypt:
        raise CryptoCoreError(
            "options --encrypt and --decrypt are mutually exclusive")
    if not args.encrypt and not args.decrypt:
        raise CryptoCoreError("either --encrypt or --decrypt is required")
    if not args.input:
        raise CryptoCoreError("--input is required")

    if args.decrypt and not args.key:
        raise CryptoCoreError("--key is required for decryption")
    if args.key:
        _parse_hex(args.key, "--key", KEY_SIZES[args.algorithm])

    if args.iv:
        if args.encrypt:
            raise CryptoCoreError("--iv is not allowed with --encrypt")
        if args.mode == "ecb":
            raise CryptoCoreError("--iv is not allowed in ecb mode")
        _parse_hex(args.iv, "--iv", IV_SIZES[args.algorithm])

    if not args.output:
        args.output = args.input + (".enc" if args.encrypt else ".dec")
    elif _same_file(args.input, args.output):
        raise CryptoCoreError(
            f"output file '{args.output}' would overwrite the input file")


def parse_args(argv=None):
    """Разбирает и валидирует аргументы, возвращает namespace."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "dgst":
        _validate_dgst(args)
        return args

    if not args.encrypt and not args.decrypt:
        parser.error("either --encrypt/--decrypt or the dgst subcommand is required")

    _validate_crypto(args)
    return args