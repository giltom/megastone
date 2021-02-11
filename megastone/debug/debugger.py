import abc
from dataclasses import dataclass
import enum

from megastone.mem import Memory, Access, AccessType
from megastone.arch import Register, BaseRegisterState, InstructionSet
from megastone.util import FlagConstant
from .hooks import HOOK_STOP, Hook, HookFunc, HOOK_BREAK, ReplaceFunctionHookFunc



ALL_ADDRESSES = FlagConstant('ALL_ADDRESSES')



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
        self.regs = RegisterState(self)
        self.stack = StackView(self)
        self.curr_hook: Hook = None
        self.curr_access: Access = None
        self.start_pc = None

        self._stop_hook: Hook = None #Hook that stopped execution

    @property
    def isa(self):
        """The current instruction set."""
        #The default implementation assumes that a change to the ISA (i.e. by writing to PC)
        #is immediately visible in the other registers (e.g. the CPSR)
        #This is true for Unicorn but this property may need to be overriden in other implementations.
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

    def jump(self, address, isa: InstructionSet = None):
        """
        Set the program counter to the given address.

        In ARM/THUMB, the instruction set will be determined from the address,
        unless `isa` is given, in which case that ISA will be forced.
        """
        #The default implementation assumes that writing a 1 to the LSB of PC changes to thumb mode
        #This is true for Unicorn but this function may need to be overriden in other implementations
        if isa is not None:
            address = isa.address_to_pointer(self.arch.pointer_to_address(address))
        self.pc = address

    def run(self, count=None, *, address=None, isa: InstructionSet = None) -> StopReason:
        """
        Resume execution.

        `count`, if given, is the maximum number of instructions to run. If None, the number is unlimited.
        If `address` is given, a jump to that address will be performed before execution starts.
        The meaning of `address` and `isa` is the same as in `jump()`.
        Raise `CPUError` on errors.
        """
        self._stop_hook = None

        if address is not None:
            self.jump(address, isa)
        self.start_pc = self.pc
        self._run(count)

        if self._stop_hook:
            return StopReason(StopType.HOOK, self._stop_hook)
        else:
            return StopReason(StopType.COUNT)

    @abc.abstractmethod
    def _run(self, count=None):
        #Run for count instructions while handling exceptions, hooks, etc.
        pass

    def step(self):
        """Run a single instruction."""
        return self.run(1)

    def add_hook(self, func: HookFunc, type: AccessType, address, size=1):
        """
        Add a hook at the given addresses and return a the new Hook instance.
        
        If `address` is `ALL_ADDRESSES`, `size` is ignored and the hook will affect all addresses.
        Different Debugger implementations may support only some combinations of arguments.
        """
        hook = Hook(address=address, size=size, type=type, func=func)
        self._add_hook(hook)
        return hook

    def add_code_hook(self, func: HookFunc, address, size=1):
        """Add a code (execute) hook at the given address and return a Hook object."""
        return self.add_hook(func, AccessType.X, address, size)

    def add_read_hook(self, func: HookFunc, address, size=1):
        """Add a read hook at the given address and return a Hook object."""
        return self.add_hook(func, AccessType.R, address, size)

    def add_write_hook(self, func: HookFunc, address, size=1):
        """Add a write hook at the given address and return a Hook object."""
        return self.add_hook(func, AccessType.W, address, size)

    def add_rw_hook(self, func: HookFunc, address, size=1):
        """Add a read/write hook at the given address and return a Hook object."""
        return self.add_hook(func, AccessType.RW, address, size)

    def trace(self, func: HookFunc):
        """Hook all instructions."""
        return self.add_code_hook(func, ALL_ADDRESSES)

    def add_breakpoint(self, address):
        """Add a HOOK_BREAK at the given address."""
        return self.add_code_hook(HOOK_BREAK, address)

    def run_until(self, stop_address, *, start_address=None, isa=None):
        """Run until reaching stop_address, optionally from start_address/isa."""
        #We don't use HOOK_STOP_ONCE bc we want to remove the hook even if we don't hit it.
        hook = self.add_code_hook(HOOK_STOP, stop_address)
        try:
            self.run(address=start_address, isa=isa)
        finally:
            self.remove_hook(hook)

    def add_watchpoint(self, address, size=1, type=AccessType.W):
        return self.add_hook(HOOK_BREAK, type, address, size)
        
    @abc.abstractmethod
    def _add_hook(self, hook: Hook):
        #Internal hooking implementation.
        #This function may save arbitrary information in `hook._data` for later use.
        pass

    def _handle_hook(self, hook: Hook, access: Access = None):
        #Implementations should call this on every hook that is triggered
        self.curr_hook = hook
        self.curr_access = access
        try:
            hook.func(self)
        finally:
            self.curr_hook = None
            self.curr_access = None

    @abc.abstractmethod
    def remove_hook(self, hook: Hook):
        """Remove the given hook."""
        pass
    
    def stop(self):
        """Call from within a hook function to stop execution."""
        #You can override this if extra bookkeeping is needed,
        #but make sure to call super().stop()
        self._stop_hook = self.curr_hook

    def disassemble(self, count):
        """Disassemble count instructions at the PC and return them."""
        return self.mem.disassemble(self.pc, count, self.isa)

    def get_curr_insn(self):
        """Return the current instruction about to be executed."""
        return self.mem.disassemble_one(self.pc, self.isa)

    def return_from_function(self, retval=None):
        """
        Return from the current function.

        If `retval` is given, return that value.
        This works only work at the very start of the function (before SP/LR has been modified).
        Also note that this won't work with calling conventions that expect the callee to pop the arguments of the stack.
        """
        if retval is not None:
            self.regs.retval = retval

        if self.arch.retaddr_reg is not None:
            self.pc = self.regs.retaddr
        else:
            self.pc = self.stack.pop()

    def replace_function(self, address, func: HookFunc):
        """
        "replace" the function at `address` with the given callback.

        If `func` returns a none-None value, this value will be returned from the function.
        Note that you need to parse the function arguments yourself -
        `func` only gets the `Debugger` as an argument, as usual.
        This function has the same limitations as `return_from_function`.
        Return the added `Hook` that can be removed later.
        """
        wrapped = ReplaceFunctionHookFunc(func)
        return self.add_code_hook(wrapped, address)

    @abc.abstractmethod
    def _read_reg(self, reg: Register) -> int:
        pass

    @abc.abstractmethod
    def _write_reg(self, reg: Register, value):
        pass


class StackView:
    """
    Helper class used to access the stack.

    This class can be indexes to access the words on the stack.
    """

    def __init__(self, dbg: Debugger):
        self._dbg = dbg

    def get_address(self, index: int):
        """Return the address of the word at the given index."""
        return self._dbg.sp + index * self._dbg.arch.word_size

    def __getitem__(self, key):
        if isinstance(key, slice):
            if key.stop is None:
                raise ValueError('Stack slices must have a stop index')
            return [self[i] for i in range(*key.indices(key.stop))]
        return self._dbg.mem.read_word(self.get_address(key))

    def __setitem__(self, key, value):
        return self._dbg.mem.write_word(self.get_address(key), value)

    def push(self, value):
        """Push the given value to the stack."""
        self._dbg.sp -= self._dbg.arch.word_size
        self[0] = value
    
    def pop(self) -> int:
        """Pop a value from the stack and return it."""
        value = self[0]
        self._dbg.sp += self._dbg.arch.word_size
        return value


class RegisterState(BaseRegisterState):
    """Helper class used to access registers."""

    def __init__(self, dbg: Debugger):
        super().__init__(dbg.arch)
        self._dbg = dbg

    def read(self, reg) -> Register:
        return self._dbg._read_reg(reg)

    def write(self, reg, value):
        return self._dbg._write_reg(reg, value)