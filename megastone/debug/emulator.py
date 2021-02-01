from contextlib import contextmanager

import unicorn

from .debugger import Access, AccessType, CPUError, Debugger, Hook, ALL_ADDRESSES, InvalidInsnError, MemFaultError, FaultCause
from megastone.mem.memory import MappableMemory, Permissions, Segment, SegmentMemory
from megastone.arch.architecture import Architecture
from megastone.arch.regs import Register
from megastone.util import MegastoneError, warning, round_up
from megastone.files.execfile import ExecFile


PERM_TO_UC_PROT = {
    Permissions.R: unicorn.UC_PROT_READ,
    Permissions.W: unicorn.UC_PROT_WRITE,
    Permissions.X: unicorn.UC_PROT_EXEC
}

ACCESS_TYPE_TO_UC_TYPE = {
    AccessType.READ: unicorn.UC_HOOK_MEM_READ,
    AccessType.WRITE: unicorn.UC_HOOK_MEM_WRITE,
    AccessType.EXECUTE : unicorn.UC_HOOK_CODE
}

UC_ACCESS_TO_ACCESS_TYPE = {
    unicorn.UC_MEM_READ : AccessType.READ,
    unicorn.UC_MEM_READ_UNMAPPED : AccessType.READ,
    unicorn.UC_MEM_WRITE_PROT : AccessType.READ,

    unicorn.UC_MEM_WRITE : AccessType.WRITE,
    unicorn.UC_MEM_WRITE_UNMAPPED : AccessType.WRITE,
    unicorn.UC_MEM_WRITE_PROT : AccessType.WRITE,

    unicorn.UC_MEM_FETCH : AccessType.EXECUTE,
    unicorn.UC_MEM_FETCH_UNMAPPED : AccessType.EXECUTE,
    unicorn.UC_MEM_FETCH_PROT : AccessType.EXECUTE
}

UC_ACCESS_TO_FAULT_CAUSE = {
    unicorn.UC_MEM_READ_UNMAPPED : FaultCause.UNMAPPED,
    unicorn.UC_MEM_WRITE_UNMAPPED : FaultCause.UNMAPPED,
    unicorn.UC_MEM_FETCH_UNMAPPED : FaultCause.UNMAPPED,

    unicorn.UC_MEM_READ_PROT : FaultCause.PROTECTED,
    unicorn.UC_MEM_WRITE_PROT : FaultCause.PROTECTED,
    unicorn.UC_MEM_FETCH_PROT : FaultCause.PROTECTED
}


def perms_to_uc_prot(perms: Permissions):
    result = unicorn.UC_PROT_NONE
    for perm, prot in PERM_TO_UC_PROT.items():
        if perms & perm:
            result |= prot
    return result


class UnicornMemory(MappableMemory):
    def __init__(self, arch, uc: unicorn.Uc):
        super().__init__(arch)
        self._uc = uc

    def map(self, name, start, size, perms=Permissions.RWX) -> Segment:
        if start % Emulator.PAGE_SIZE != 0:
            raise MegastoneError(f'Emulator segment addresses must be aligned 0x{Emulator.PAGE_SIZE:X}')
        if size % Emulator.PAGE_SIZE != 0:
            warning(f'Rounding up segment size to multiple of 0x{Emulator.PAGE_SIZE:X}')
            size = Emulator.round_up(size)

        seg = Segment(name, start, size, perms, self)
        self._add_segment(seg)
        self._uc.mem_map(start, size, perms_to_uc_prot(perms))
        return seg

    def write_data(self, address, data):
        self._uc.mem_write(address, data)

    def read_data(self, address, size):
        return bytes(self._uc.mem_read(address, size))


class Emulator(Debugger):
    """Emulator based on the Unicorn engine. Implements the full Debugger interface."""

    mem: MappableMemory

    PAGE_SIZE = 0x1000

    def __init__(self, arch: Architecture):
        uc = arch.isa.create_uc()
        super().__init__(UnicornMemory(arch, uc))

        self._uc = uc
        self._stopped = False
        self._fault_cause: FaultCause = None
        self._fault_access: Access = None
        #since hooks are called from C, exceptions raised inside a hook won't propagate up to emu_start()
        #so we save the exception in this variable and raise it later
        self._hook_exception: Exception = None  

        self._uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, self._mem_invalid_hook)
        
    @classmethod
    def from_memory(cls, mem: SegmentMemory):
        """Create an Emulator from an existing SegmentMemory."""
        emu = cls(mem.arch)
        emu.mem.load_memory(mem)
        return emu

    @classmethod
    def from_execfile(cls, exe: ExecFile):
        """
        Create an Emulator from an ExecFile.

        Architecture, memory layout, starting address, and initial ISA are automatically determined.
        """
        emu = cls(exe.arch)
        emu.mem.load_memory(exe.mem)
        emu.pc = exe.entry
        return emu

    @staticmethod
    def round_up(n):
        """Return n rounded up to the emulator page size."""
        return round_up(n, Emulator.PAGE_SIZE)

    def allocate_stack(self, size, *, name='stack', perms=Permissions.RWX):
        """Allocate a stack segment and set the SP to point to its top."""
        segment = self.mem.allocate(name, size, perms)
        self.sp = segment.end - self.arch.word_size
        return segment

    def get_reg(self, reg: Register) -> int:
        return self._uc.reg_read(reg.uc_id)

    def set_reg(self, reg: Register, value):
        return self._uc.reg_write(reg.uc_id, value)

    def _run(self, count=None):
        start = self.isa.address_to_pointer(self.pc)
        if count is None:
            count = 0

        self._fault_cause = None
        self._fault_access = None
        self._hook_exception = None
        
        try:
            self._uc.emu_start(start, -1, count=count) #for now i'm hoping that setting until=-1 means that it won't stop 
        except unicorn.UcError as e:
            self._handle_uc_error(e)
        if self._hook_exception is not None:
            raise self._hook_exception

    def _handle_uc_error(self, e: unicorn.UcError):
        if self._fault_cause is not None:
            raise MemFaultError(self.pc, self._fault_cause, self._fault_access) from None
        if e.errno == unicorn.UC_ERR_INSN_INVALID:
            raise InvalidInsnError(self.pc) from None
        raise CPUError(str(e), self.pc) from None

    def _add_hook(self, hook: Hook):
        uc_type = ACCESS_TYPE_TO_UC_TYPE[hook.type]

        if hook.type is AccessType.EXECUTE:
            callback = self._code_hook
        else:
            callback = self._data_hook

        if hook.address is ALL_ADDRESSES:
            begin, end = 1, 0
        else:
            begin, end = hook.address, hook.address + hook.size - 1

        hook._data = self._uc.hook_add(uc_type, callback, user_data=hook, begin=begin, end=end)

    def remove_hook(self, hook: Hook):
        self._uc.hook_del(hook._data)

    def stop(self):
        super().stop()
        self._uc.emu_stop()

    @contextmanager
    def _catch_hook_exceptions(self):
        try:
            yield
        except Exception as e:
            self._hook_exception = e
            self._uc.emu_stop()

    def _code_hook(self, uc, address, size, hook: Hook):
        with self._catch_hook_exceptions():
            self._handle_hook(hook)

    def _data_hook(self, uc, uc_access, address, size, value, hook: Hook):
        with self._catch_hook_exceptions():
            access_type = UC_ACCESS_TO_ACCESS_TYPE[uc_access]
            if access_type is not AccessType.WRITE:
                value = None
            access = Access(access_type, address, size, value)
            self._handle_hook(hook, access)

    def _mem_invalid_hook(self, uc, uc_access, address, size, value, user_data):
        with self._catch_hook_exceptions():
            cause = UC_ACCESS_TO_FAULT_CAUSE.get(uc_access, None)
            access_type = UC_ACCESS_TO_ACCESS_TYPE.get(uc_access, None)

            if cause is not None and access_type is not None:
                if access_type is not AccessType.WRITE:
                    value = None
                self._fault_cause = cause
                self._fault_access = Access(access_type, address, size, value)

            return False