import abc
from dataclasses import dataclass, field


from .access import AccessType


class HookFunc(abc.ABC):
    """ABC that can be used to define hooks (you can also use a plain function)."""

    @abc.abstractmethod
    def __call__(self, dbg):
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
    type: AccessType
    func: HookFunc
    _data: object = field(init=False, repr=False)


class StopHookFunc(HookFunc):
    """Basic hook that simply stops execution."""

    def __call__(self, dbg):
        dbg.stop()

    def __repr__(self):
        return 'HOOK_STOP'

HOOK_STOP = StopHookFunc()


class StopOnceHookFunc(HookFunc):
    """A hook that will stop execution once, then remove itself."""
    
    def __call__(self, dbg):
        dbg.remove_hook(dbg.curr_hook)
        dbg.stop()

    def __repr__(self):
        return 'HOOK_STOP_ONCE'

HOOK_STOP_ONCE = StopOnceHookFunc()


class BreakHookFunc(HookFunc):
    """Breakpoint-like hook: stops execution unless starting execution from its address."""

    def __call__(self, dbg):
        if dbg.start_pc != dbg.pc:
            dbg.stop()

    def __repr__(self):
        return 'HOOK_BREAK'

HOOK_BREAK = BreakHookFunc()


class ReplaceFunctionHookFunc(HookFunc):
    def __init__(self, func: HookFunc):
        self.func = func
    
    def __call__(self, dbg):
        dbg.return_from_function(self.func(dbg))

    def __repr__(self):
        return f'ReplaceFunctionHookFunc({self.func})'