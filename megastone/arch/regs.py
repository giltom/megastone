from dataclasses import dataclass
import importlib

import unicorn

INVALID_REG_NAMES = ['invalid']

class Register:
    """Configuration of a single CPU register"""

    def __init__(self, name, *, cs_id=None, uc_id=None):
        self.name = name
        self.cs_id = cs_id
        self.uc_id = uc_id

    def __repr__(self):
        return f"<Register '{self.name}'>"

def _reg_ids_from_module(module, prefix):
    reg_ids = {}
    for attr, value in module.__dict__.items():
        if attr.startswith(prefix):
            reg_name = attr[len(prefix):].lower()
            if reg_name in INVALID_REG_NAMES:
                continue
            reg_ids[reg_name] = value
    return reg_ids

class RegisterSet:
    """The set of registers in an architecture. Note that this can include many aliases for the same register."""

    def __init__(self, registers):
        """Initialize a new register set with the given Registers"""
        self._regs = {}
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
                regs[name].uc_id = uc_id
            else:
                regs[name] = Register(name, uc_id=uc_id)

        if len(regs) == 0:
            raise RuntimeError(f'Architecture {arch_name} not found in keystone or capstone!')

        return cls(regs.values())

    def __iter__(self):
        yield from self._regs.values()

    def names(self):
        yield from self._regs

    def __len__(self):
        return len(self._regs)
    
    def __getitem__(self, key):
        return self._regs[key]
    
    def __getattr__(self, name):
        if name in self._regs:
            return self._regs[name]
        raise AttributeError()