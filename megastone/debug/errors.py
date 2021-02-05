import enum


from megastone.errors import MegastoneError
from megastone.mem import AccessType, Access


class FaultCause(enum.Enum):
    UNMAPPED = enum.auto()
    PROTECTED = enum.auto()


class CPUError(MegastoneError):
    def __init__(self, message, address):
        super().__init__(message)
        self.address = address


class InvalidInsnError(CPUError):
    def __init__(self, address):
        super().__init__(f'Invalid instruction at 0x{address:X}', address)


class MemFaultError(CPUError):
    def __init__(self, address, cause: FaultCause, access: Access):
        message = f'Memory fault at PC=0x{address:X}: {access.type.verbose_name} {cause.name}'
        if access.type.is_data:
            message += f', address=0x{access.address:X}, size=0x{access.size:X}'
        super().__init__(message, address)
        self.cause = cause
        self.access = access

    def __repr__(self):
        return f'{self.__class__.__name__}(0x{self.address:X}, FaultCause.{self.cause.name}, {self.access})'