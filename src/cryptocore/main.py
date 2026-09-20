import sys
from cryptocore import CryptoCoreError, cli_parser, file_io
from cryptocore.modes import ecb

def main(argv=None):
    try:
        args = cli_parser.parse_args(argv)
        data = file_io.read_file(args.input)
        if args.encrypt:
            result = ecb.encrypt(args.key, data)
        else:
            result = ecb.decrypt(args.key, data)
        file_io.write_file(args.output, result)
    except (CryptoCoreError, ValueError) as exc:
        print(f"cryptocore: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())