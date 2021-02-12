from __future__ import annotations

from megastone.debug import CPUError
from megastone.mem import AccessType, Access
from megastone.errors import MegastoneError
from megastone.emulator import Emulator
from megastone.util import size_to_mask, trim_range


class Device:
    """Helper class for MMIO emulation."""

    def __init__(self, name: str, address: int, size: int):
        self.name = name
        self.address = address
        self.size = size
        self.emu: Emulator = None
        self._hook = None

    def read(self, offset: int, size: int) -> bytes:
        """Read `size` bytes from the device at the given offset."""
        return None

    def write(self, offset: int, data: bytes):
        """Write `data` to the device at the given offest."""
        pass

    @property
    def attached(self):
        """Whether this Device is currently attached to an emulator."""
        return self.emu is not None
    
    def attach(self, emu: Emulator):
        """Attack to the given Emulator."""
        if self.attached:
            raise RuntimeError('A Device instance can only be attached to one Emulator')
        
        if not emu.mem.is_mapped(self.address, self.size):
            emu.mem.map(self.address, self.size, self.name, AccessType.RW)
        self._hook = emu.add_rw_hook(self._hook_func, self.address, self.size)
        self.emu = emu

    def detach(self):
        """Detach from the current Emulator."""
        if not self.attached:
            raise RuntimeError('Device is not attached')
        
        self.emu.remove_hook(self._hook)
        self._hook = None
        self.emu = None
    
    def _hook_func(self, emu: Emulator):
        assert emu is self.emu

        access = emu.curr_access
        address, size = trim_range(access.address, access.size, self.address, self.size)
        offset = address - self.address
        
        try:
            if access.type is AccessType.R:
                self._handle_read(offset, size)
            else:
                self.write(offset, access.value[:size])
        except DeviceError as e:
            raise DeviceFaultError(self, emu.pc, access, str(e)) from e

    def _handle_read(self, offset, size):
        data = self.read(offset, size)
        if data is not None:
            self.emu.mem.write(self.address + offset, data) #write result to memory so it's visible by the CPU


class DeviceError(MegastoneError):
    """Raise this error to indicate an invalid access to the device. This will be translated automatically into a DeviceFaultError."""
    pass


class DeviceFaultError(CPUError):
    def __init__(self, device: Device, address, access: Access, reason):
        message = f'Fault raised by {device.name} at PC=0x{address:X}: {access.verbose()}: {reason}'
        super().__init__(message, address)
        self.device = device
        self.access = access

    def __repr__(self):
        return f'{self.__class__.__name__}(0x{self.address:X}, {self.access})'


class RegisterDevice(Device):
    """
    Helper class for MMIO device consisting of many registers.

    Subclasses of this class should implement one or two methods for each register:
    read_NAME(self) -> int
    write_NAME(self, value: int)
    They should also define the offsets attribute, either at the class level or at the instance level.
    This should be a dict mapping offset to register name.
    """

    offsets: dict[int, str] = {}

    def reg_read(self, name) -> int:
        """Read the register with the given name and return its value."""
        return self._get_func('read', name)()

    def reg_write(self, name, value: int):
        """Write to the register with the given name."""
        self._get_func('write', name)(value)

    def read(self, offset, size) -> bytes:
        func = self._get_func_by_offset(offset, 'read')
        if func is None:
            return None
        value = func() & size_to_mask(size)
        return self.emu.arch.endian.encode_int(value, size)

    def write(self, offset, data):
        func = self._get_func_by_offset(offset, 'write')
        if func is None:
            return
        value = self.emu.arch.endian.decode_int(data)
        func(value)

    def _get_func_by_offset(self, offset, prefix):
        name = self.offsets.get(offset)
        if name is None:
            raise DeviceError(f'No register is defined at offset 0x{offset:X}')

        try:
            return self._get_func(prefix, name)
        except AttributeError:
            return None
    
    def _get_func(self, prefix, name):
        return getattr(self, f'{prefix}_{name}')