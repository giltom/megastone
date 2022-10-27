from __future__ import annotations

import abc
from typing import TypeVar, Generic


T = TypeVar('T')


def parse_hex_int(s):
    return int(s, 16)


def hex_spaces(data):
    return ' '.join(f'{b:02x}' for b in data)


def round_up(value, size):
    if value % size == 0:
        return value
    return (value // size + 1) * size

def round_down(value, size):
    return (value // size) * size


def bits_to_mask(bits):
    return (1 << bits) - 1


def size_to_mask(size):
    return bits_to_mask(size * 8)


class NamespaceMapping(abc.ABC, Generic[T]):
    """Basic mapping type that supports access by both index and attribute."""

    @abc.abstractmethod
    def __getitem__(self, key: str) -> T:
        pass

    def __getattr__(self, attr) -> T:
        try:
            return self[attr]
        except KeyError as e:
            raise AttributeError() from e

class FlagConstant:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name


def trim_range(start, size, base, max_size):
    end = start + size
    max_end = base + max_size

    fixed_start = max(start, base)
    fixed_end = min(end, max_end)
    return fixed_start, fixed_end - fixed_start


class Closeable(abc.ABC):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    @abc.abstractmethod
    def close(self):
        pass