import argparse
from cryptocore import CryptoCoreError

ALGORITHMS = ("aes",)
MODES = ("ecb",)
KEY_SIZES = {"aes": 16}


def build_parser():
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
    parser.add_argument("--key", required=True,
                        help="AES-128 key as a hex string (32 hex chars)")
    parser.add_argument("--input", required=True, help="path to the input file")
    parser.add_argument("--output",
                        help="output path (default: INPUT.enc / INPUT.dec)")
    return parser


def parse_args(argv=None):
    args = build_parser().parse_args(argv)
    try:#ключ в hex
        key = bytes.fromhex(args.key)
    except ValueError:
        raise CryptoCoreError(
            f"invalid key '{args.key}': expected a hexadecimal string") from None

    expected = KEY_SIZES[args.algorithm]
    if len(key) != expected:
        raise CryptoCoreError(
            f"invalid key length: got {len(key)} bytes, "
            f"expected {expected} bytes (AES-128)")

    if not args.output:#вывод по умолчанию
        args.output = args.input + (".enc" if args.encrypt else ".dec")

    args.key = key
    return args