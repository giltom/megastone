from __future__ import annotations

import enum
import platform
from collections.abc import Iterable

import unicorn

from megastone.db import DatabaseEntry
from megastone.util import bits_to_mask, size_to_mask
from .isa import InstructionSet
from .regs import BaseRegisterState, Register, RegisterSet


class Endian(enum.Enum):
    LITTLE = 'little'
    BIG = 'big'

    def decode_int(self, data, *, signed=False):
        """Convert bytes to int in this endian"""
        return int.from_bytes(data, self.value, signed=signed)
    
    def encode_int(self, value: int, size):
        """Convert int to bytes in this endian"""
        if value < 0:
            value = value & size_to_mask(size)
        return value.to_bytes(size, self.value)



class Architecture(DatabaseEntry):
    """
    Contains information about an Architecture.
    
    An architecture can have one or more InstructionSets. Most arches have only one.
    """

    def __init__(self, *, 
        name: str,
        alt_names: Iterable[str] = (),                   #List of alternate names recognized by by_name().
        bits: int,                               #Number of bits in a word
        endian: Endian,
        isas: Iterable[InstructionSet],                             #List of instruction sets. The first one will be the default. Most arches have only one.
        regs: RegisterSet = None,                #Register set (can be None if disassembly and emulation aren't supported)
        pc_name: str = None,                 #Program counter register
        sp_name: str = None,                 #Stack pointer register
        retaddr_name: str = None,            #Name of register containing return address (if None, retaddr is stored on the stack)
        retval_name: str = None,        #Name of register containing return value
        uc_arch: int = None,            #Unicorn arch ID, None if unicorn isn't supported
        uc_mode: int = 0,               #Unicorn mode ID
    ):
        super().__init__(name, alt_names)
        self.bits = bits
        self.word_size = bits // 8
        self.endian = endian
        self.isas = tuple(isas)
        self.regs = regs
        self.pc_reg = regs[pc_name] if pc_name is not None else None
        self.sp_reg = regs[sp_name] if sp_name is not None else None
        self.retaddr_reg = regs[retaddr_name] if retaddr_name is not None else None
        self.retval_reg = regs[retval_name] if retval_name is not None else None
        self.uc_arch = uc_arch
        self.uc_mode = uc_mode

        for isa in self.isas:
            isa.arch = self

    @staticmethod
    def native():
        """Return the native Architecture of this machine."""
        return Architecture.by_name(platform.machine())

    @property
    def isa(self):
        """The Architecture's single ISA. Raises AttributeError if there is more than one ISA."""
        if len(self.isas) > 1:
            raise AttributeError('Arch has multiple ISAs')
        return self.isas[0]

    @property
    def default_isa(self):
        """Return the default ISA."""
        return self.isas[0]

    @property
    def word_mask(self):
        return bits_to_mask(self.bits)

    @property
    def uc_supported(self):
        return self.uc_arch is not None

    @property
    def fully_supported(self):
        return self.uc_supported and all(isa.ks_supported and isa.cs_supported for isa in self.isas)

    def create_uc(self):
        """Create and return a Unicorn Uc object for this architecture"""
        return unicorn.Uc(self.uc_arch, self.uc_mode)
    
    def encode_word(self, value):
        """Convert an int to bytes representing a word in this architecture"""
        return self.endian.encode_int(value, self.word_size)

    def decode_word(self, data, *, signed=False):
        """Convert bytes representing a word in this architecture to an int"""
        if len(data) != self.word_size:
            raise ValueError(f'Invalid word length {len(data)}, expected {self.word_size}')
        return self.endian.decode_int(data, signed=signed)

    def add_to_db(self):
        """Register this Architecture and all of its InstructionSets in the database so they can be found by by_name()"""
        Architecture.register(self)
        for isa in self.isas:
            InstructionSet.register(isa)

    def pointer_to_address(self, pointer):
        """Convert a pointer to a code address (relevant for thumb)."""
        return pointer

    def isa_from_pointer(self, address):
        """Try to determine the current ISA from an address."""
        return self.isa

    def isa_from_regs(self, regs: BaseRegisterState):
        """Determine the current ISA from a BaseRegisterState."""
        return self.isa


class SimpleArchitecture(Architecture):
    """An Architecture with only one ISA."""
    
    def __init__(self, *,
        name: str,
        alt_names: Iterable[str] = (),
        bits: int,
        endian: Endian,
        regs: RegisterSet = None, 
        pc_name: Register = None,      
        sp_name: Register = None,        
        retaddr_name: Register = None,          
        retval_name: Register = None,            
        insn_alignment: int,  
        min_insn_size: int,    
        max_insn_size: int,    
        ks_arch: int = None,     
        ks_mode: int = 0,    
        cs_arch: int = None,   
        cs_mode: int = 0,   
        uc_arch: int = None,   
        uc_mode: int = 0,  
    ):
        isa = InstructionSet(
            name=name,
            alt_names=alt_names,
            insn_alignment=insn_alignment,
            min_insn_size=min_insn_size,
            max_insn_size=max_insn_size,
            ks_arch=ks_arch,
            ks_mode=ks_mode,
            cs_arch=cs_arch,
            cs_mode=cs_mode
        )

        return super().__init__(
            name=name,
            alt_names=alt_names,
            bits=bits,
            endian=endian,
            isas=[isa],
            regs=regs,
            pc_name=pc_name,
            sp_name=sp_name,
            retaddr_name=retaddr_name,
            retval_name=retval_name,
            uc_arch=uc_arch,
            uc_mode=uc_mode
        )