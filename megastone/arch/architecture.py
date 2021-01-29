import enum
import platform

from .regs import Register, RegisterSet
from megastone.db import DatabaseEntry
from .isa import InstructionSet


class Endian(enum.Enum):
    LITTLE = 'little'
    BIG = 'big'

    def decode_int(self, data, *, signed=False):
        """Convert bytes to int in this endian"""
        return int.from_bytes(data, self.value, signed=signed)
    
    def encode_int(self, value, size):
        """Convert int to bytes in this endian"""
        return int.to_bytes(value, size, signed=True)

    def encode_8(self, value):
        return self.encode_int(value, 1)

    def encode_16(self, value):
        return self.encode_int(value, 2)
    
    def encode_32(self, value):
        return self.encode_int(value, 4)
    
    def encode_64(self, value):
        return self.encode_int(value, 8)



class Architecture(DatabaseEntry):
    """
    Contains information about an Architecture.
    
    An architecture can have one or more InstructionSets. Most arches have only one.
    """

    def __init__(self, *, 
        name: str,
        alt_names: tuple = (),                   #List of alternate names recognized by by_name().
        bits: int,                               #Number of bits in a word
        endian: Endian,
        isas: tuple,                             #List of instruction sets. The first one will be the default. Most arches have only one.
        regs: RegisterSet = None,                #Register set (can be None if disassembly and emulation aren't supported)
        pc_reg: Register = None,                 #Program counter register
        sp_reg: Register = None,                 #Stack pointer register
        retaddr_reg: Register = None,            #Name of register containing return address (if None, retaddr is stored on the stack)
        retval_reg: Register = None              #Name of register containing return value
    ):
        super().__init__(name, alt_names)
        self.bits = bits
        self.word_size = bits // 8
        self.endian = endian
        self.isas = tuple(isas)
        self.regs = regs
        self.pc_reg = pc_reg
        self.sp_reg = sp_reg
        self.retaddr_reg = retaddr_reg
        self.retval_reg = retval_reg

    @staticmethod
    def native():
        """Return the native Architecture of this machine."""
        return Architecture.by_name(platform.machine())

    @property
    def isa(self) -> InstructionSet:
        """The Architecture's default ISA."""
        return self.isas[0]
    
    def assemble(self, assembly, address=0):
        """Assemble with the default ISA. See InstructionSet.assemble()."""
        return self.isa.assemble(assembly, address)

    def disassemble(self, code, address=0, *, count=0):
        """Disassemble with the default ISA. See InstructionSet.disassemble()."""
        return self.isa.disassemble(code, address, count=count)

    def disassemble_one(self, code, address=0):
        """Disassemble one instruction with the default ISA. See InstructionSet.disassemble_one()."""
        return self.isa.disassemble_one(code, address)
    
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


class SimpleArchitecture(Architecture):
    """An Architecture with only one ISA."""
    
    def __init__(self, *,
        name: str,
        alt_names: tuple = (),
        bits: int,
        endian: Endian,
        regs: RegisterSet = None, 
        pc_reg: Register = None,      
        sp_reg: Register = None,        
        retaddr_reg: Register = None,          
        retval_reg: Register = None,            
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
            cs_mode=cs_mode,
            uc_arch=uc_arch,
            uc_mode=uc_mode
        )

        return super().__init__(
            name=name,
            alt_names=alt_names,
            bits=bits,
            endian=endian,
            isas=[isa],
            regs=regs,
            pc_reg=pc_reg,
            sp_reg=sp_reg,
            retaddr_reg=retaddr_reg,
            retval_reg=retval_reg
        )