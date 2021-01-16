import keystone

from megastone import Architecture

class Assembler:
    """High-level assembler class."""

    def __init__(self, arch: Architecture):
        """
        Create a new disassembler.
        
        `arch` - The architecture.
        `detailed` - Whether to analyze instructions and include additional details at the cost of performance.
        """
        if not arch.ks_supported:
            raise RuntimeError(f'Architecture {arch.name} isn\'t supported by keystone')

        self.arch = arch
        self.ks = keystone.Ks(arch.ks_arch, arch.ks_mode)
    
    def assemble(self, assembly, address=0):
        """
        Assemble the given instructions and return the assembled bytes.

        `address`, if given, is the base address of the instructions.
        """
        data, _ = self.ks.asm(assembly, addr=address, as_bytes=True)
        if data is None:
            raise ValueError('Invalid assembly')
        return data
