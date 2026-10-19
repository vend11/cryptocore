"""Тесты CSPRNG: длина, уникальность ключей, распределение битов, ошибки."""

import pytest

from cryptocore.csprng import generate_random_bytes


@pytest.mark.parametrize("size", (1, 16, 32, 1000))
def test_output_length(size):
    assert len(generate_random_bytes(size)) == size


def test_two_calls_differ():
    assert generate_random_bytes(16) != generate_random_bytes(16)


@pytest.mark.parametrize("bad", (0, -1))
def test_invalid_size(bad):
    with pytest.raises(ValueError):
        generate_random_bytes(bad)


def test_key_uniqueness():
    # TEST-2: 1000 ключей по 16 байт, все уникальны
    keys = set()
    for _ in range(1000):
        key_hex = generate_random_bytes(16).hex()
        assert key_hex not in keys, f"duplicate key: {key_hex}"
        keys.add(key_hex)
    assert len(keys) == 1000


def test_hamming_weight_close_to_half():
    # TEST-4: доля единичных битов близка к 50%
    data = generate_random_bytes(1_000_000)
    ones = sum(bin(byte).count("1") for byte in data)
    share = ones / (len(data) * 8)
    assert 0.45 < share < 0.55