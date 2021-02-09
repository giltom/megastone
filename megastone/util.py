import abc
from typing import TypeVar, Generic
import functools


T = TypeVar('T')


def parse_hex_int(s):
    return int(s, 16)


def hex_spaces(data):
    return ' '.join(bytes([b]).hex() for b in data)


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
    def __getitem__(self, key) -> T:
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