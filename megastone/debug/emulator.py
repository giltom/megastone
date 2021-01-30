from dataclasses import dataclass

import unicorn

from .debugger import Access, Debugger, Hook, CodeHook, DataHook, StopReason, StopType, HookFunc
from megastone.mem.memory import MappableMemory, Permissions, Segment, SegmentMemory
from megastone.arch.architecture import Architecture
from megastone.arch.isa import InstructionSet
from megastone.arch.regs import Register
from megastone.util import MegastoneError, warning, round_up
from megastone.files.execfile import ExecFile


PERM_TO_UC_PROT = {
    Permissions.R: unicorn.UC_PROT_READ,
    Permissions.W: unicorn.UC_PROT_WRITE,
    Permissions.X: unicorn.UC_PROT_EXEC
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
        self._trace_hook: Hook = None
        
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

    def get_reg(self, reg: Register) -> int:
        return self._uc.reg_read(reg.uc_id)

    def set_reg(self, reg: Register, value):
        return self._uc.reg_write(reg.uc_id, value)

    def _run(self, count=None):
        start = self.isa.address_to_pointer(self.pc)
        if count is None:
            count = 0
        #for now i'm hoping that setting until=-1 means that it won't stop 
        self._uc.emu_start(start, -1, count=count)
        #TODO: handle errors properly

    def _add_hook(self, hook: Hook):
        if isinstance(hook, CodeHook):
            uc_hook = self._create_code_hook(hook, hook.address, hook.address)
        elif isinstance(hook, DataHook):
            uc_hook = None
        else:
            assert False
        hook._data = uc_hook #Store the UC handle in the data field so we can remove the hook later

    def remove_hook(self, hook: Hook):
        self._uc.hook_del(hook._data)

    def stop(self):
        super().stop()
        self._uc.emu_stop()

    def trace(self, func: HookFunc):
        """Arange for the given function to be called before every instruction."""
        self._trace_hook = Hook(func)
        self._trace_hook._data = self._create_code_hook(self._trace_hook, 1, 0)
        
    def stop_trace(self):
        """Stop tracing."""
        self.remove_hook(self._trace_hook)
        self._trace_hook = None

    def _create_code_hook(self, hook: Hook, begin, end):
        return self._uc.hook_add(unicorn.UC_HOOK_CODE, self._handle_code_hook, user_data=hook, begin=begin, end=end)

    def _handle_code_hook(self, uc, address, size, hook: CodeHook):
        self._handle_hook(hook)