import abc
from dataclasses import dataclass, field
import enum
from megastone.arch.isa import InstructionSet

from megastone.mem import Memory
from megastone.arch import Register
from megastone.util import NamespaceMapping, MegastoneError


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


class HookFunc(abc.ABC):
    """ABC that can be used to define hooks (you can also use a plain function)."""

    @abc.abstractmethod
    def __call__(self, dbg):
        """
        Function that runs every time the hook is hit.
        
        By default, the hook will not stop execution. If you want to stop, call dbg.stop().
        """
        pass


class StopHookFunc(HookFunc):
    """Basic hook that simply stops execution."""

    def __call__(self, dbg):
        dbg.stop()

HOOK_STOP = StopHookFunc()


@dataclass(eq=False)
class Hook:
    """
    Hook object that can be used to inspect or remove existing hooks.

    Do not instantiate directly; call Debugger.add_x_hook().
    """
    func: HookFunc
    _data: object = field(init=False, repr=False)


@dataclass(eq=False)
class CodeHook(Hook):
    address: int


@dataclass(eq=False)
class DataHook(Hook):
    address: int
    size: int
    type: AccessType


class CPUError(MegastoneError):
    def __init__(self, message, address):
        super().__init__(message)
        self.address = address


class InvalidInsnError(CPUError):
    def __init__(self, address):
        super().__init__(f'Invalid instruction at 0x{address:X}', address)


class FaultCause(enum.Enum):
    UNMAPPED = enum.auto()
    PROTECTED = enum.auto()


class MemFaultError(CPUError):
    def __init__(self, address, cause: FaultCause, access: Access):
        message = f'Memory fault at PC=0x{address:X}: {access.type.name} {cause.name}'
        if access.type is not AccessType.EXECUTE:
            message += f', address=0x{access.address:X}, size={access.size}'
            if access.type is AccessType.WRITE:
                message += f', value=0x{access.value}'
        super().__init__(message, address)
        self.cause = cause
        self.access = access

    def __repr__(self):
        return f'{self.__class__.__name__}(0x{self.address:X}, FaultCause.{self.cause.name}, {self.access})'


class StopType(enum.Enum):
    COUNT = enum.auto()  #reached max instruction count
    HOOK = enum.auto()   #stopped by hook


@dataclass(frozen=True)
class StopReason:
    type: StopType
    hook: Hook = None #Hook if stopped by hook


class Debugger(abc.ABC):
    """Abstract Debugger class. Provides access to memory, registers and start/stop/step/continue controls."""

    def __init__(self, mem: Memory):
        self.mem = mem
        self.arch = self.mem.arch
        self.regs = RegisterMapping(self)

        self.curr_hook: Hook = None
        self.curr_access: Access = None
        self._last_hook: Hook = None
        self._stopped = False

    @abc.abstractmethod
    def get_reg(self, reg: Register) -> int:
        pass

    @abc.abstractmethod
    def set_reg(self, reg: Register, value):
        pass

    @property
    def isa(self):
        """The current instruction set."""
        return self.arch.isa_from_regs(self.regs)

    @property
    def pc(self):
        """The current program counter."""
        return self.regs.gen_pc

    @pc.setter
    def pc(self, value):
        self.regs.gen_pc = value

    @property
    def sp(self):
        """The current stack pointer."""
        return self.regs.gen_sp

    @sp.setter
    def sp(self, value):
        self.regs.gen_sp = value

    def run(self, count=None, *, address=None, isa: InstructionSet=None) -> StopReason:
        """
        Resume execution.

        `count`, if given, is the maximum number of instructions to run. If None, the number is unlimited.
        `address` is the address to run from. If None, resume from the current PC.
        `isa` is the ISA to start in. If None, determine from address. This only has meaning if address is given.
        Return a `StopReason`.
        Raise `CPUError` on errors.
        """
        self._stopped = False

        if address is not None:
            if isa is not None:
                address = isa.address_to_pointer(address)
            self.pc = address

        self._run(count)

        if self._stopped:
            return StopReason(StopType.HOOK, self._last_hook)
        else:
            return StopReason(StopType.COUNT)

    @abc.abstractmethod
    def _run(self, count=None):
        #Run for count instructions while handling exceptions, hooks, etc.
        pass

    def step(self):
        """Run a single instruction."""
        return self.run(1)

    def add_code_hook(self, address, func: HookFunc) -> CodeHook:
        """Add a hook at the given address and return a CodeHook object."""
        hook = CodeHook(func=func, address=address)
        self._add_hook(hook)
        return hook

    def add_data_hook(self, address, size, type: AccessType, func: HookFunc) -> DataHook:
        """Add a data hook at the given address and return a DataHook object."""
        hook = DataHook(func=func, address=address, size=size, type=type)
        self._add_hook(hook)
        return hook

    @abc.abstractmethod
    def _add_hook(self, hook: Hook):
        pass

    @abc.abstractmethod
    def remove_hook(self, hook: Hook):
        """Remove the given hook."""
        pass
    
    def stop(self):
        """Call from within a hook function to stop execution."""
        self._stopped = True

    def disassemble(self, count):
        """Disassemble count instructions at the PC and return them."""
        return self.mem.disassemble(self.pc, count, self.isa)

    @property
    def curr_insn(self):
        """Return the current instruction about to be executed."""
        return self.mem.disassemble_one(self.pc, self.isa)

    def _handle_hook(self, hook: Hook, access: Access = None):
        #Implementations should call this on every hook that is triggered
        self.curr_hook = hook
        self._last_hook = hook
        self.curr_access = access
        try:
            hook.func(self)
        finally:
            self.curr_hook = None
            self.curr_access = None


class RegisterMapping(NamespaceMapping):
    """Helper class used to access registers."""

    def __init__(self, dbg: Debugger):
        super().__setattr__('_dbg', dbg)
        super().__setattr__('_generic_regs', dict(
            gen_pc=dbg.arch.pc_reg,
            gen_sp=dbg.arch.sp_reg,
            retaddr=dbg.arch.retaddr_reg,
            retval=dbg.arch.retval_reg
        ))

    def __getitem__(self, key):
        reg = self._name_to_reg(key)
        return self._dbg.get_reg(reg)
    
    def __setitem__(self, key, value):
        reg = self._name_to_reg(key)
        self._dbg.set_reg(reg, value)

    def __setattr__(self, attr, value):
        try:
            self[attr] = value
        except KeyError as e:
            raise AttributeError('No such register') from e

    def _name_to_reg(self, name):
        reg = self._generic_regs.get(name, None)
        if reg is not None:
            return reg
        return self._dbg.arch.regs[name]