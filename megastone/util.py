import abc


def parse_hex_int(s):
    return int(s, 16)


def hex_spaces(data):
    return ' '.join(bytes([b]).hex() for b in data)


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

    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        return True