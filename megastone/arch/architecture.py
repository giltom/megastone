from dataclasses import dataclass, field, MISSING
import enum
import platform

import keystone
import capstone
import unicorn


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

    pc_reg: str                         #Name of program counter register
    sp_reg: str                         #Name of stack pointer register
    retval_reg: str                     #Name of register containing return value
    lr_reg: str                         #Name of link register, None if there is no link register (retaddr is on the stack)
    has_lr_reg: bool = derived_field()  #Does this arch have a link register?
    
    ks_arch: int = None                     #Keystone arch ID, None if keystone isn't supported
    ks_mode: int = 0                        #Keystone mode ID
    ks_supported: bool = derived_field()    #Keystone supports this arch?
    ks: keystone.Ks = derived_field(None)   #Keystone object

    cs_arch: int = None                     #Capstone arch ID, None if capstone isn't supported
    cs_mode: int = 0                        #Capstone mode ID
    cs_supported: bool = derived_field()    #Capstone supports this arch?
    cs: capstone.Cs = derived_field(None)   #Capstone object

    uc_arch: int = None                         #Unicorn arch ID, None if unicorn isn't supported
    uc_mode: int = 0                            #Unicorn mode ID
    uc_reg_prefix: str = None                   #Prefix of Unicorn register names (e.g. 'UC_X_REG_')
    uc_const_module: object = None              #Module containing unicorn constants
    uc_supported: bool = derived_field()        #Unicorn supports this arch?


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

        self.has_lr_reg = self.lr_reg is not None

        self.ks_supported = self.ks_arch is not None
        if self.ks_supported:
            self.ks = keystone.Ks(self.ks_arch, self.ks_mode)

        self.cs_supported = self.cs_arch is not None
        if self.cs_supported:
            self.cs = capstone.Cs(self.cs_arch, self.cs_mode)
            self.cs.detail = True

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
    
    def assemble(self, assembly, address=0):
        """
        Assemble the given instructions and return the assembled bytes.

        `address`, if given, is the base address of the instructions.
        """
        if not self.ks_supported:
            raise RuntimeError('Architecute isn\'t supported by keystone')
        data, _ = self.ks.asm(assembly, addr=address, as_bytes=True)
        if data is None:
            raise ValueError('Invalid assembly')
        return data
    
    def disassemble(self, code, address=0, *, count=0):
        """
        Disassemble the given machine code and yield assembly instructions.

        `address` - The base address of the code.
        `count` - Maximum number of instructions to disassemble (if not given - unlimited)
        """
        if not self.cs_supported:
            raise RuntimeError('Architecute isn\'t supported by capstone') 
        yield from self.cs.disasm(code, offset=address, count=count)

    def disassemble_one(self, code, address=0):
        """Disassemble and return the first instruction in the given code."""
        result = list(self.disassemble(code, address=address, count=1))
        return result[0]

    def uc_reg_name(self, reg_name):
        """Return the Unicorn name of the given register."""
        return self.uc_reg_prefix + reg_name.upper()

    def uc_reg_id(self, reg_name):
        """
        Return the Unicorn register ID of the register with the given name.
        
        Raise ValueError if the register name is invalid.
        """
        try:
            return getattr(self.uc_const_module, self.uc_reg_name(reg_name))
        except AttributeError as e:
            raise ValueError(f'Invalid register name "{reg_name}"') from e

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