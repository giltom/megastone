import keystone as ks
import capstone as cs
import unicorn as uc


from ..architecture import SimpleArchitecture, Endian
from ..regs import RegisterSet


MIPS_REGS = RegisterSet.from_libs('mips')

class MIPSArchitecture(SimpleArchitecture):
    """MIPS family architecture"""

    def __init__(self, **kwargs):
        kwargs.update(
            regs=MIPS_REGS,
            insn_alignment=4,
            insn_sizes=[4],
            ks_arch=ks.KS_ARCH_MIPS,
            cs_arch=cs.CS_ARCH_MIPS,
            uc_arch=uc.UC_ARCH_MIPS,
            pc_name='pc',
            sp_name='sp',
            retval_name='v0',
            retaddr_name='ra'
        )
        super().__init__(**kwargs)


class MIPS32Architecture(MIPSArchitecture):
    def __init__(self, **kwargs):
        kwargs.update(
            bits=32,
            ks_mode=ks.KS_MODE_MIPS32,
            cs_mode=cs.CS_MODE_MIPS32,
            uc_mode=uc.UC_MODE_MIPS32,
            gdb_name='mips'
        )
        super().__init__(**kwargs)


class MIPS64Architecture(MIPSArchitecture):
    def __init__(self, **kwargs):
        kwargs.update(
            bits=64,
            ks_mode=ks.KS_MODE_MIPS64,
            cs_mode=cs.CS_MODE_MIPS64,
            uc_mode=uc.UC_MODE_MIPS64,
            gdb_name='mips:isa64'
        )
        super().__init__(**kwargs)


ARCH_MIPS = MIPS32Architecture(
    name='mips',
    alt_names=['mips32', 'mipseb', 'mips32eb', 'mipsbe', 'mips32be'],
    endian=Endian.BIG
)
ISA_MIPS = ARCH_MIPS.isa

ARCH_MIPS64 = MIPS64Architecture(
    name='mips64',
    alt_names=['mips64eb', 'mips64be'],
    endian=Endian.BIG
)
ISA_MIPS64 = ARCH_MIPS64.isa


ARCH_MIPSLE = MIPS32Architecture(
    name='mipsle',
    alt_names=['mipsel', 'mips32le', 'mips32el'],
    endian=Endian.LITTLE
)
ISA_MIPSLE = ARCH_MIPSLE.isa

ARCH_MIPS64LE = MIPS64Architecture(
    name='mips64le',
    alt_names=['mips64el'],
    endian=Endian.LITTLE
)
ISA_MIPS64LE = ARCH_MIPS64LE.isa