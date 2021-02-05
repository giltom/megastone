import abc


def parse_hex_int(s):
    return int(s, 16)


def hex_spaces(data):
    return ' '.join(bytes([b]).hex() for b in data)


def round_up(value, size):
    if value % size == 0:
        return value
    return (value // size + 1) * size


def bits_to_mask(bits):
    return (1 << bits) - 1


def size_to_mask(size):
    return bits_to_mask(size * 8)


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

class ExceptionSaver:
    """Helper class used to store raised exceptions and raise them later."""

    def __init__(self):
        self._exception = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._exception = exc_value
        self.handle_exception(exc_value)
        return True #suppress the exception

    def check(self):
        exception = self._exception
        self._exception = None
        if exception is not None:
            raise exception

    def handle_exception(self, e):
        pass #hook for subclasses