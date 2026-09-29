"""Точка входа CryptoCore: CLI, обработка IV, файловый ввод-вывод."""

import os
import sys

from cryptocore import CryptoCoreError, cli_parser, file_io
from cryptocore.modes import cbc, cfb, ctr, ecb, ofb

BLOCK_SIZE = 16

_MODES = {
    "ecb": ecb,
    "cbc": cbc,
    "cfb": cfb,
    "ofb": ofb,
    "ctr": ctr,
}


def _process(args, data):
    """Шифрует или расшифровывает данные, возвращает байты результата."""
    module = _MODES[args.mode]

    if args.mode == "ecb":  # ECB без IV, формат файла не менялся
        if args.encrypt:
            return module.encrypt(args.key, data)
        return module.decrypt(args.key, data)

    if args.encrypt:
        iv = os.urandom(BLOCK_SIZE)  # CSPRNG
        return iv + module.encrypt(args.key, iv, data)  # IV в начале файла

    if args.iv is not None:
        iv = args.iv
    else:
        if len(data) < BLOCK_SIZE:
            raise CryptoCoreError(
                "input file is too short to contain an IV: "
                f"got {len(data)} bytes, need at least {BLOCK_SIZE}")
        iv, data = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    return module.decrypt(args.key, iv, data)


def main(argv=None):
    """Выполняет команду, возвращает код завершения процесса."""
    try:
        args = cli_parser.parse_args(argv)
        data = file_io.read_file(args.input)
        result = _process(args, data)
        file_io.write_file(args.output, result)
    except (CryptoCoreError, ValueError) as exc:
        print(f"cryptocore: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())