from __future__ import annotations

from contextlib import contextmanager

import unicorn

from megastone.debug import CPUError, Debugger, Hook, InvalidInsnError, MemFaultError, FaultCause, HookType
from megastone.mem import MappableMemory, Access, AccessType, Segment, SegmentMemory
from megastone.arch import Architecture, Register
from megastone.util import round_up, round_down
from megastone.errors import UnsupportedError, warning
from megastone.files import ExecFile


ACCESS_TYPE_TO_UC_PROT = {
    AccessType.R: unicorn.UC_PROT_READ,
    AccessType.W: unicorn.UC_PROT_WRITE,
    AccessType.X: unicorn.UC_PROT_EXEC
}

HOOK_TYPE_TO_UC_HOOK = {
    HookType.READ: unicorn.UC_HOOK_MEM_READ,
    HookType.WRITE: unicorn.UC_HOOK_MEM_WRITE,
    HookType.ACCESS: unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
    HookType.CODE: unicorn.UC_HOOK_CODE,
    HookType.BLOCK: unicorn.UC_HOOK_BLOCK,
    HookType.INTERRUPT: unicorn.UC_HOOK_INTR
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

STACK_NAME = 'stack'
DEFAULT_STACK_SIZE = 0x100000
RET_FLAG_NAME = 'ret_flag'

def perms_to_uc_prot(perms: AccessType):
    result = 0
    for atype, flag in ACCESS_TYPE_TO_UC_PROT.items():
        if perms & atype:
            result |= flag
    return result


def uc_prot_to_perms(uc_prot: int):
    result = AccessType.NONE
    for atype, flag in ACCESS_TYPE_TO_UC_PROT.items():
        if uc_prot & flag:
            result |= atype
    return result


class UnicornMemory(MappableMemory):
    def __init__(self, arch, uc: unicorn.Uc):
        super().__init__(arch)
        self._uc = uc

    def _handle_new_segment(self, seg: Segment):
        self._init_mapping(seg.start, seg.size, seg.perms)

    def _read(self, address, size):
        try:
            return bytes(self._uc.mem_read(address, size))
        except unicorn.UcError as e:
            self._raise_read_error(address, size, str(e))

    def _write(self, address, data):
        try:
            self._uc.mem_write(address, data)
        except unicorn.UcError as e:
            self._raise_write_error(address, data, str(e))

    def _init_mapping(self, start, size, perms):
        if size == 0:
            return

        end = start + size
        start = round_down(start, Emulator.PAGE_SIZE)
        end = round_up(end, Emulator.PAGE_SIZE)
        first_page = start
        last_page = end - Emulator.PAGE_SIZE
        uc_prot = perms_to_uc_prot(perms)

        #Segments can't overlap anyway, so we only need to check the first and last pages
        
        start_prot = self._get_uc_prot(first_page)
        if start_prot is not None:
            self._adjust_page(first_page, start_prot, uc_prot)
            start += Emulator.PAGE_SIZE

        if last_page != first_page:
            end_prot = self._get_uc_prot(last_page)
            if end_prot is not None:
                self._adjust_page(last_page, end_prot, uc_prot)
                end -= Emulator.PAGE_SIZE

        if start < end:
            self._uc.mem_map(start, end - start, uc_prot)

    def _adjust_page(self, page, old_prot, new_prot):
        if old_prot == new_prot:
            return
        
        comb_prot = old_prot | new_prot
        atype = uc_prot_to_perms(comb_prot)
        warning(f'Page at 0x{page:X} will have permissions {atype.name} due to overlap')
        self._uc.mem_protect(page, Emulator.PAGE_SIZE, comb_prot)

    def _get_uc_prot(self, address):
        for start, end, prot in self._uc.mem_regions():
            if start <= address < end:
                return prot
        return None


class Emulator(Debugger):
    """Emulator based on the Unicorn engine. Implements the full Debugger interface."""

    mem: UnicornMemory

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

    def allocate_stack(self, size=DEFAULT_STACK_SIZE, perms=AccessType.RWX):
        """Allocate a stack segment and set the SP to point to its top."""
        segment = self.mem.allocate(size, name=STACK_NAME, perms=perms)
        self.reset_sp()
        return segment

    def reset_sp(self):
        """Reset the SP to the top of the stack."""
        self.sp = self.mem.segments[STACK_NAME].end - self.arch.word_size

    def save_context(self):
        """Save and return the current CPU context."""
        return self._uc.context_save()

    def restore_context(self, ctx):
        """Restore the CPU from the given context."""
        self._uc.context_restore(ctx)

    def _get_flag_retaddr(self) -> int:
        if RET_FLAG_NAME not in self.mem.segments:
            self.mem.allocate(self.arch.max_insn_size, name=RET_FLAG_NAME, perms=AccessType.X)
        return self.mem.segments[RET_FLAG_NAME].address

    def _read_reg(self, reg: Register) -> int:
        return self._uc.reg_read(reg.uc_id)

    def _write_reg(self, reg: Register, value):
        return self._uc.reg_write(reg.uc_id, value)

    def _run(self, count=None):
        start = self.isa.address_to_pointer(self.pc)
        if count is None:
            #WORKAROUND FOR UNICORN BUG: PC doesn't update properly if count is not given. So we set it to the maximum value.
            count = -1

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
        uc_type = HOOK_TYPE_TO_UC_HOOK.get(hook.type, None)
        if uc_type is None:
            raise UnsupportedError(f'Hook type {hook.type} is not supported by unicorn')

        if hook.type is HookType.CODE or hook.type is HookType.BLOCK:
            callback = self._code_hook
        elif hook.type is HookType.INTERRUPT:
            callback = self._interrupt_hook
        else:
            callback = self._data_hook

        if hook.address is None:
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

    def _interrupt_hook(self, uc, int_num, hook: Hook):
        with self._catch_hook_exceptions():
            self._handle_hook(hook, int_num=int_num)

    def _get_access_value(self, atype, size, value):
        if atype is AccessType.W:
            return self.arch.endian.encode_int(value, size)
        return None