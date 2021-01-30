import abc
import sys
import warnings


def parse_hex_int(s):
    return int(s, 16)


def hex_spaces(data):
    return ' '.join(bytes([b]).hex() for b in data)


def warning(s):
    warnings.warn(s, MegastoneWarning, stacklevel=2)


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


class MegastoneError(Exception):
    """Base class for all custom exceptions."""
    pass

class MegastoneWarning(Warning):
    """Base class for all custom warnings."""
    pass

def disable_warnings():
    """Disable all megastone warnings."""
    warnings.simplefilter('ignore', MegastoneWarning)