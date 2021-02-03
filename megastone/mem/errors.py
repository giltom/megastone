from megastone.errors import MegastoneError
from .access import Access


class MemoryAccessError(MegastoneError):
    """Exception raised when the user accesses invalid memory."""

    def __init__(self, access: Access, reason):
        message = f'Memory {access.type.verbose_name} error at 0x{access.address}: {reason}'
        super().__init__(message)
        self.access = access