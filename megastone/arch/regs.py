from __future__ import annotations

import importlib
import abc
from collections.abc import Generator
import dataclasses
from typing import TYPE_CHECKING

import unicorn

from megastone.util import NamespaceMapping

if TYPE_CHECKING:
    from megastone.arch import Architecture


INVALID_REG_NAMES = ['invalid']


@dataclasses.dataclass(frozen=True)
class Register:
    """Configuration of a single CPU register"""

    name: str
    cs_id: int = None
    uc_id: int = None

    def __repr__(self):
        return f"<Register '{self.name}'>"

    def __str__(self):
        return self.name


def _reg_ids_from_module(module, prefix):
    reg_ids = {}
    for attr, value in module.__dict__.items():
        if attr.startswith(prefix):
            reg_name = attr[len(prefix):].lower()
            if reg_name in INVALID_REG_NAMES:
                continue
            reg_ids[reg_name] = value
    return reg_ids


class RegisterSet(NamespaceMapping[Register]):
    """The set of registers in an architecture. Note that this can include many aliases for the same register."""

    def __init__(self, registers):
        """Initialize a new register set with the given Registers"""
        self._regs: dict[str, Register] = {}
        for reg in registers:
            self._regs[reg.name] = reg

    @classmethod
    def from_libs(cls, arch_name):
        """
        Automatically create a RegisterSet from unicorn/capstone data.
        
        `arch_name` should be the unicorn/capstone name of the architecture (hopfully consistent).
        """
        #Some black magic that is necessary to avoid repeating lots of code...
        try:
            cs_module = importlib.import_module(f'capstone.{arch_name}_const')
        except ModuleNotFoundError:
            cs_ids = {}
        else:
            cs_prefix = f'{arch_name.upper()}_REG_'
            cs_ids = _reg_ids_from_module(cs_module, cs_prefix)

        uc_module = getattr(unicorn, f'{arch_name}_const', None)
        if uc_module is None:
            uc_ids = {}
        else:
            uc_prefix = f'UC_{arch_name.upper()}_REG_'
            uc_ids = _reg_ids_from_module(uc_module, uc_prefix)

        regs = {name : Register(name, cs_id=cs_id) for name, cs_id in cs_ids.items()}
        for name, uc_id in uc_ids.items():
            if name in regs:
                regs[name] = dataclasses.replace(regs[name], uc_id=uc_id)
            else:
                regs[name] = Register(name, uc_id=uc_id)

        if len(regs) == 0:
            raise RuntimeError(f'Architecture {arch_name} not found in keystone or capstone!')

        return cls(regs.values())

    def __iter__(self) -> Generator[Register]:
        yield from self._regs.values()

    def __len__(self):
        return len(self._regs)
    
    def __getitem__(self, key):
        return self._regs[key]

    def has_reg_name(self, name):
        return name in self._regs


class BaseRegisterState(NamespaceMapping[int]):
    """
    Base class representing the current register state in the CPU.
    
    Registers can be read and modified via dict-like or namespace-like access.
    """

    def __init__(self, arch: Architecture):
        self._arch = arch
        self._generic_regs = dict(
            gen_pc=arch.pc_reg,
            gen_sp=arch.sp_reg,
            retaddr=arch.retaddr_reg,
            retval=arch.retval_reg
        )

    @abc.abstractmethod
    def read(self, reg: Register) -> int:
        """Read the value of a Register."""
        pass

    @abc.abstractmethod
    def write(self, reg: Register, value):
        """Set the value of a register."""
        pass

    def set(self, **kwargs):
        """Set the values of multiple registers."""
        for name, value in kwargs.items():
            self[name] = value

    def get(self, *args):
        """Get the values of multiple registers."""
        return tuple(self[name] for name in args)

    def __getitem__(self, key) -> int:
        reg = self._name_to_reg(key)
        return self.read(reg)
    
    def __setitem__(self, key, value):
        reg = self._name_to_reg(key)
        self.write(reg, value)

    def __setattr__(self, attr, value):
        if attr.startswith('_'):
            super().__setattr__(attr, value)
            return

        try:
            self[attr] = value
        except KeyError as e:
            raise AttributeError('No such register') from e

    def _name_to_reg(self, name):
        reg = self._generic_regs.get(name, None)
        if reg is not None:
            return reg
        return self._arch.regs[name]