from cryptocore import CryptoCoreError


def read_file(path):
    try:
        with open(path, "rb") as f:#бинарный поток
            return f.read()
    except OSError as exc:
        raise CryptoCoreError(f"cannot read input file '{path}': {exc}") from None


def write_file(path, data):
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as exc:
        raise CryptoCoreError(f"cannot write output file '{path}': {exc}") from None