import keystone
import capstone
import unicorn

from .db import DatabaseEntry

class InstructionSet(DatabaseEntry):
    """
    Represents an instruction set for assembling/disassembling instructions.

    Most architectures have exactly one instruction set, but some have more (e.g. ARM/THUMB)
    """

    def __init__(self, *,
        name: str,               #Name of architecture. Should be lowercase.
        alt_names: tuple = (),   #List of alternate names recognized by by_name().
        insn_alignment: int,     #Required alignment of instructions
        min_insn_size: int,      #Size of smallest instruction
        max_insn_size: int,      #Size of largest instruction
        ks_arch: int = None,     #Keystone arch ID, None if keystone isn't supported
        ks_mode: int = 0,        #Keystone mode ID
        cs_arch: int = None,     #Capstone arch ID, None if capstone isn't supported
        cs_mode: int = 0,        #Capstone mode ID
        uc_arch: int = None,     #Unicorn arch ID, None if unicorn isn't supported
        uc_mode: int = 0,        #Unicorn mode ID
    ):
        super().__init__(name, alt_names)
        self.insn_alignment = insn_alignment
        self.min_insn_size = min_insn_size,
        self.max_insn_size = max_insn_size,
        self.ks_arch = ks_arch
        self.ks_mode = ks_mode
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        self.uc_arch = uc_arch
        self.uc_mode = uc_mode

        self.ks = None
        if self.ks_supported:
            self.ks = keystone.Ks(self.ks_arch, self.ks_mode)
        
        self.uc = None
        if self.cs_supported:
            self.cs = capstone.Cs(self.cs_arch, self.cs_mode)
            self.cs.detail = True

        InstructionSet.register(self)

    @property
    def ks_supported(self):
        return self.ks_arch is not None

    @property
    def cs_supported(self):
        return self.cs_arch is not None
    
    @property
    def uc_supported(self):
        return self.uc_arch is not None

    def assemble(self, assembly, address=0):
        """
        Assemble the given instructions and return the assembled bytes.

        `address`, if given, is the base address of the instructions.
        """
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
        yield from self.cs.disasm(code, offset=address, count=count)

    def disassemble_one(self, code, address=0):
        """Disassemble and return the first instruction in the given code."""
        result = list(self.disassemble(code, address=address, count=1))
        if len(result) == 0:
            raise ValueError('Invalid instruction')
        return result[0]

    def create_uc(self):
        """Create and return a Unicorn Uc object for this architecture"""
        return unicorn.Uc(self.uc_arch, self.uc_mode)