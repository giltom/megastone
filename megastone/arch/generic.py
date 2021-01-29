from .architecture import SimpleArchitecture, Endian


class GenericArchitecture(SimpleArchitecture):
    """Simplest possible architecture that specifies endianess and word size without supporting assembly/disassembly."""

    def __init__(self, bits, endian):
        if endian == Endian.LITTLE:
            name = f'le{bits}'
        else:
            name = f'be{bits}'
        super().__init__(
            name=name,
            bits=bits,
            endian=endian,
            insn_alignment=1,
            min_insn_size=bits//8,
            max_insn_size=bits//8
        )


for bits in [16, 32, 64]:
    for endian in Endian:
        GenericArchitecture(bits, endian).add_to_db()