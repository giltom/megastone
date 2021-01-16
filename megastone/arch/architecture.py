from dataclasses import dataclass, field, MISSING
import enum
import platform

import unicorn


from .regs import Register, RegisterSet


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


def derived_field(default=MISSING):
    return field(init=False, default=default)


@dataclass(repr=False, eq=False)
class Architecture:
    """Contains information about an architecture/instruction set."""

    name: str               #Name of architecture. Should be lowercase.
    alt_names: list         #List of alternate names recognized by by_name(). Does not need to include `name`.
    bits: int               #Number of bits in a word
    endian: Endian          #Endian enum
    insn_alignment: int     #Required alignment of instructions
    min_insn_size: int      #Size of smallest instruction
    max_insn_size: int      #Size of largest instruction

    word_size: int  = derived_field()       #Number of bytes in a word

    regs: RegisterSet = None                #Register set (can be None if disassembly and emulation aren't supported)
    pc_reg: Register = None                 #Program counter register
    sp_reg: Register = None                 #Stack pointer register
    retaddr_reg: Register = None            #Name of register containing return address (if None, retaddr is stored on the stack).
    retval_reg: Register = None             #Name of register containing return value
    has_retaddr_reg: bool = derived_field() #Is the return address stored in a register?
    
    ks_arch: int = None                     #Keystone arch ID, None if keystone isn't supported
    ks_mode: int = 0                        #Keystone mode ID
    ks_supported: bool = derived_field()    #Keystone supports this arch?

    cs_arch: int = None                     #Capstone arch ID, None if capstone isn't supported
    cs_mode: int = 0                        #Capstone mode ID
    cs_supported: bool = derived_field()    #Capstone supports this arch?

    uc_arch: int = None                     #Unicorn arch ID, None if unicorn isn't supported
    uc_mode: int = 0                        #Unicorn mode ID
    uc_supported: bool = derived_field()    #Unicorn supports this arch?


    _arches = []    #List of registered architectures (class variable)

    @staticmethod
    def register(arch):
        """Register the given architecture so it can be found with by_name()."""
        Architecture._arches.append(arch)

    @staticmethod
    def by_name(name):
        """
        Return the registered Architecture with the given name.

        This function is very liberal with the names and will accept case-differences and many alternate names for each architecture.
        The special name `'native'` will resolve to the machine's native architecture.
        Raise `ValueError` if the architecture was not found.
        """
        name = name.lower()
        if name == 'native':
            return Architecture.native()
        for arch in Architecture._arches:
            if arch.name == name or name in arch.alt_names:
                return arch
        raise ValueError(f'Unknown architecture name {name}')

    @staticmethod
    def all():
        """Return an iterable over all registered architectures."""
        yield from Architecture._arches

    @staticmethod
    def all_names():
        """Return an iterable of the names of all registered architectures."""
        for arch in Architecture.all():
            yield arch.name

    @staticmethod
    def native():
        """Return this machine's native Architecture."""
        return Architecture.by_name(platform.machine())


    def __post_init__(self):
        self.word_size = self.bits // 8
        self.has_retaddr_reg = self.retaddr_reg is not None
        self.ks_supported = self.ks_arch is not None
        self.cs_supported = self.cs_arch is not None
        self.uc_supported = self.uc_arch is not None

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

    def __repr__(self):
        return f"<Architecture '{self.name}'>"

    def update_arch(self, regs):
        """
        This function can be overriden in a subclass to support switching to a different architecture at runtime (e.g. ARM/THUMB).

        `regs` is a mapping that maps register names to their values.
        If the CPU has switched to a different architecture, this function should return it.
        Otherwise it should return `self`.
        """
        return self