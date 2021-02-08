from contextlib import contextmanager

import unicorn

from megastone.debug import CPUError, Debugger, Hook, ALL_ADDRESSES, InvalidInsnError, MemFaultError, FaultCause
from megastone.mem import MappableMemory, Access, AccessType, Segment, SegmentMemory, MemoryAccessError
from megastone.arch import Architecture, Register
from megastone.util import round_up, round_down
from megastone.errors import UnsupportedError
from megastone.files import ExecFile


ACCESS_TYPE_TO_UC_PROT = {
    AccessType.R: unicorn.UC_PROT_READ,
    AccessType.W: unicorn.UC_PROT_WRITE,
    AccessType.X: unicorn.UC_PROT_EXEC
}

ACCESS_TYPE_TO_UC_HOOK = {
    AccessType.R: unicorn.UC_HOOK_MEM_READ,
    AccessType.W: unicorn.UC_HOOK_MEM_WRITE,
    AccessType.RW: unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
    AccessType.X: unicorn.UC_HOOK_CODE
}

UC_ACCESS_TO_ACCESS_TYPE = {
    unicorn.UC_MEM_READ: AccessType.R,
    unicorn.UC_MEM_READ_UNMAPPED: AccessType.R,
    unicorn.UC_MEM_WRITE_PROT: AccessType.R,

    unicorn.UC_MEM_WRITE: AccessType.W,
    unicorn.UC_MEM_WRITE_UNMAPPED: AccessType.W,
    unicorn.UC_MEM_WRITE_PROT: AccessType.W,

    unicorn.UC_MEM_FETCH: AccessType.X,
    unicorn.UC_MEM_FETCH_UNMAPPED: AccessType.X,
    unicorn.UC_MEM_FETCH_PROT: AccessType.X
}

UC_ACCESS_TO_FAULT_CAUSE = {
    unicorn.UC_MEM_READ_UNMAPPED: FaultCause.UNMAPPED,
    unicorn.UC_MEM_WRITE_UNMAPPED: FaultCause.UNMAPPED,
    unicorn.UC_MEM_FETCH_UNMAPPED: FaultCause.UNMAPPED,

    unicorn.UC_MEM_READ_PROT: FaultCause.PROTECTED,
    unicorn.UC_MEM_WRITE_PROT: FaultCause.PROTECTED,
    unicorn.UC_MEM_FETCH_PROT: FaultCause.PROTECTED
}


def perms_to_uc_prot(perms: AccessType):
    result = 0
    for atype, flag in ACCESS_TYPE_TO_UC_PROT.items():
        if perms & atype:
            result |= flag
    return result


class UnicornMemory(MappableMemory):
    def __init__(self, arch, uc: unicorn.Uc):
        super().__init__(arch)
        self._uc = uc

    def map(self, name, start, size, perms=AccessType.RWX):
        #Unicorn only supports mappings aligned to 0x1000
        end = start + size
        start = round_down(start, Emulator.PAGE_SIZE)
        end = round_up(end, Emulator.PAGE_SIZE)
        size = end - start

        seg = Segment(name, start, size, perms, self)
        self._add_segment(seg)
        self._uc.mem_map(start, size, perms_to_uc_prot(perms))
        return seg

    def _read(self, address, size):
        try:
            return bytes(self._uc.mem_read(address, size))
        except unicorn.UcError as e:
            raise MemoryAccessError(Access(AccessType.R, address, size), str(e))

    def _write(self, address, data):
        try:
            self._uc.mem_write(address, data)
        except unicorn.UcError as e:
            raise MemoryAccessError(Access(AccessType.W, address, len(data), data), str(e))


class Emulator(Debugger):
    """Emulator based on the Unicorn engine. Implements the full Debugger interface."""

    mem: MappableMemory

    PAGE_SIZE = 0x1000

    def __init__(self, arch: Architecture):
        uc = arch.create_uc()
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
        emu.jump(exe.entry)
        return emu

    def allocate_stack(self, size, *, name='stack', perms=AccessType.RWX):
        """Allocate a stack segment and set the SP to point to its top."""
        segment = self.mem.allocate(name, size, perms)
        self.sp = segment.end - self.arch.word_size
        return segment

    def _read_reg(self, reg: Register) -> int:
        return self._uc.reg_read(reg.uc_id)

    def _write_reg(self, reg: Register, value):
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
        uc_type = ACCESS_TYPE_TO_UC_HOOK.get(hook.type, None)
        if uc_type is None:
            raise UnsupportedError(f'Hook type {hook.type} is not supported by unicorn')

        if hook.type is AccessType.X:
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
        except BaseException as e:
            self._hook_exception = e
            self._uc.emu_stop()

    def _code_hook(self, uc, address, size, hook: Hook):
        with self._catch_hook_exceptions():
            self._handle_hook(hook)

    def _data_hook(self, uc, uc_access, address, size, value, hook: Hook):
        with self._catch_hook_exceptions():
            access_type = UC_ACCESS_TO_ACCESS_TYPE[uc_access]
            value = self._get_access_value(access_type, size, value)
            access = Access(access_type, address, size, value)
            self._handle_hook(hook, access)

    def _mem_invalid_hook(self, uc, uc_access, address, size, value, user_data):
        with self._catch_hook_exceptions():
            cause = UC_ACCESS_TO_FAULT_CAUSE.get(uc_access, None)
            access_type = UC_ACCESS_TO_ACCESS_TYPE.get(uc_access, None)
            value = self._get_access_value(access_type, size, value)

            if cause is not None and access_type is not None:
                self._fault_cause = cause
                self._fault_access = Access(access_type, address, size, value)

            return False

    def _get_access_value(self, atype, size, value):
        if atype is AccessType.W:
            return self.arch.endian.encode_int(value, size)
        return None