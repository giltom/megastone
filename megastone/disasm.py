import capstone

from megastone import Architecture

class Disassembler:
    """High-level disassembler class."""

    def __init__(self, arch: Architecture, *, detailed=True):
        """
        Create a new disassembler.
        
        `arch` - The architecture.
        `detailed` - Whether to analyze instructions and include additional details at the cost of performance.
        """
        if not arch.cs_supported:
            raise RuntimeError(f'Architecture {arch.name} isn\'t supported by capstone')

        self.arch = arch
        self.cs = capstone.Cs(arch.cs_arch, arch.cs_mode)
        self.cs.detail = detailed
    
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
