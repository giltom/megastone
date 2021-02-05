import enum
from dataclasses import dataclass


class AccessType(enum.Flag):
    """Flag enum representing a type (or types) of memory access"""

    NONE = 0
    R = enum.auto()
    W = enum.auto()
    X = enum.auto()

    RW = R | W
    RX = R | X
    WX = W | X
    RWX = R | W | X

    @property
    def read(self):
        return bool(self & AccessType.R)

    @property
    def write(self):
        return bool(self & AccessType.W)

    @property
    def execute(self):
        return bool(self & AccessType.X)

    @property
    def is_data(self):
        return self.read or self.write

    def contains(self, other):
        """Return True if these Permissions contain all of the permissions in other."""
        return self & other == other

    @classmethod
    def parse(cls, string):
        """Parse a string of the form "rwx" and return an AccessType."""
        total = cls.NONE
        for c in string:
            try:
                perm = cls[c.upper()]
            except KeyError:
                pass
            else:
                total |= perm
        return total

    @classmethod
    def flags(cls):
        return [cls.R, cls.W, cls.X]

    def __str__(self):
        res = ''
        for flag in self.flags():
            if self & flag:
                res += flag.name
        return res

    @property
    def verbose_name(self):
        parts = []
        for flag in self.flags():
            if self & flag:
                parts.append(FULL_NAMES[flag])
        return '/'.join(parts)


FULL_NAMES = {
    AccessType.R: 'READ',
    AccessType.W: 'WRITE',
    AccessType.X: 'EXECUTE'
}


@dataclass(frozen=True)
class Access:
    """Represents an access to memory."""

    type: AccessType
    address: int
    size: int
    value: int = None #value for writes

    def __repr__(self):
        result = f'{self.__class__.__name__}(type=AccessType.{self.type.name}, address=0x{self.address:X}, size={self.size}'
        if self.value is not None:
            result += f', value=0x{self.value:X}'
        result += ')'
        return result