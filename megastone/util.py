import abc


def parse_hex_int(s):
    return int(s, 16)


def hex_spaces(data):
    return ' '.join(bytes([b]).hex() for b in data)


def round_up(value, size):
    if value % size == 0:
        return value
    return (value // size + 1) * size


class NamespaceMapping(abc.ABC):
    """Basic mapping type that supports access by both index and attribute."""

    @abc.abstractmethod
    def __getitem__(self, key):
        pass

    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError as e:
            raise AttributeError() from e

class FlagConstant:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return self.name