"""Точка входа: связывает CLI, режимы шифрования, CSPRNG и хеши."""

import sys

from . import CryptoCoreError
from .cli_parser import parse_args
from .csprng import generate_random_bytes
from .file_io import read_file, write_file
from .hash import compute_file
from .modes import cbc, cfb, ctr, ecb, ofb

_MODES = {"ecb": ecb, "cbc": cbc, "cfb": cfb, "ofb": ofb, "ctr": ctr}


def _key_bytes(hex_key):
    """hex-строка ключа -> байты."""
    return bytes.fromhex(hex_key)


def _warn_weak_key(key):
    """Предупреждение о слабом ключе (нули, одинаковые или последовательные байты)."""
    weak = (len(set(key)) == 1
            or key == bytes(range(len(key)))
            or key == bytes(range(len(key) - 1, -1, -1)))
    if weak:
        print("[warning] weak key detected: do not use predictable keys",
              file=sys.stderr)


def _process(args, data):
    """Шифрует/расшифровывает данные выбранным режимом."""
    if args.encrypt:
        if args.key:
            key = _key_bytes(args.key)
        else:
            key = generate_random_bytes(16)
            print(f"[INFO] Generated random key: {key.hex()}")
        _warn_weak_key(key)

        if args.mode == "ecb":
            return _MODES[args.mode].encrypt(key, data)
        iv = generate_random_bytes(16)
        return iv + _MODES[args.mode].encrypt(key, iv, data)

    key = _key_bytes(args.key)
    if args.mode == "ecb":
        return _MODES[args.mode].decrypt(key, data)
    if args.iv:
        iv = _key_bytes(args.iv)
    else:
        if len(data) < 16:
            raise CryptoCoreError("input file is too short to contain an IV")
        iv, data = data[:16], data[16:]
    return _MODES[args.mode].decrypt(key, iv, data)


def _run_dgst(args):
    """Подкоманда dgst: хеш файла в stdout или в файл (--output)."""
    hex_digest = compute_file(args.input, args.algorithm)
    line = f"{hex_digest}  {args.input}"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
        except OSError as e:
            raise CryptoCoreError(f"cannot write output file: {e}")
    else:
        print(line)


def main(argv=None):
    """Точка входа CLI; ошибки выводятся в stderr с кодом возврата 1."""
    # на Windows print пишет \r\n в pipe, а тесты сравнивают вывод с \n
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(newline="\n")
    try:
        args = parse_args(argv)
        if args.command == "dgst":
            _run_dgst(args)
            return 0
        data = read_file(args.input)
        result = _process(args, data)
        write_file(args.output, result)
        return 0
    except (CryptoCoreError, ValueError) as e:
        print(f"cryptocore: error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())