import enum
from dataclasses import dataclass


class AccessType(enum.Enum):
    READ = enum.auto()
    WRITE = enum.auto()
    EXECUTE = enum.auto()


@dataclass(frozen=True)
class Access:
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