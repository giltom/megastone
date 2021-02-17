from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import enum

from megastone.mem import AccessType

if TYPE_CHECKING:
    from .debugger import Debugger


class HookType(enum.Enum):
    CODE = enum.auto()
    READ = enum.auto()
    WRITE = enum.auto()
    ACCESS = enum.auto()
    BLOCK = enum.auto()
    INTERRUPT = enum.auto()

    @classmethod
    def from_access_type(cls, access_type):
        value = ACCESS_TYPE_TO_HOOK_TYPE.get(access_type)
        if value is None:
            raise ValueError(f'Access type {access_type} has no equivalent hook type')
        return value

    @property
    def access_type(self):
        return HOOK_TYPE_TO_ACCESS_TYPE.get(self)

    @property
    def is_data(self):
        atype = self.access_type
        if atype is None:
            return False
        return atype.is_data

    
HOOK_TYPE_TO_ACCESS_TYPE = {
    HookType.CODE: AccessType.X,
    HookType.READ: AccessType.R,
    HookType.WRITE: AccessType.W,
    HookType.ACCESS: AccessType.RW
}

ACCESS_TYPE_TO_HOOK_TYPE = {value: key for key, value in HOOK_TYPE_TO_ACCESS_TYPE.items()}


class HookFunc(abc.ABC):
    """ABC that can be used to define hooks (you can also use a plain function)."""

    @abc.abstractmethod
    def __call__(self, dbg: Debugger):
        """
        Function that runs every time the hook is hit.
        
        By default, the hook will not stop execution. If you want to stop, call dbg.stop().
        """
        pass


@dataclass(eq=False)
class Hook:
    """
    Hook object that can be used to inspect or remove existing hooks.

    Do not instantiate directly; call Debugger.add_x_hook().
    """
    address: int
    size: int
    type: HookType
    func: HookFunc
    _data: object = field(init=False, repr=False)


class StopHookFunc(HookFunc):
    """Basic hook that simply stops execution."""

    def __call__(self, dbg: Debugger):
        dbg.stop()

    def __repr__(self):
        return 'HOOK_STOP'

HOOK_STOP = StopHookFunc()


class StopOnceHookFunc(HookFunc):
    """A hook that will stop execution once, then remove itself."""
    
    def __call__(self, dbg: Debugger):
        dbg.remove_hook(dbg.curr_hook)
        dbg.stop()

    def __repr__(self):
        return 'HOOK_STOP_ONCE'

HOOK_STOP_ONCE = StopOnceHookFunc()


class BreakHookFunc(HookFunc):
    """Breakpoint-like hook: stops execution unless starting execution from its address."""

    def __call__(self, dbg: Debugger):
        if dbg.start_pc != dbg.pc:
            dbg.stop()

    def __repr__(self):
        return 'HOOK_BREAK'

HOOK_BREAK = BreakHookFunc()


class ReplaceFunctionHookFunc(HookFunc):
    def __init__(self, func: HookFunc):
        self.func = func
    
    def __call__(self, dbg: Debugger):
        dbg.return_from_function(self.func(dbg))

    def __repr__(self):
        return f'ReplaceFunctionHookFunc({self.func})'