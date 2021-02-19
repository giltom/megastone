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


ARCH_MIPS = MIPSArchitecture(
    name='mips',
    alt_names=['mips32', 'mipseb', 'mips32eb'],
    bits=32,
    endian=Endian.BIG,
    ks_mode=ks.KS_MODE_MIPS32 | ks.KS_MODE_BIG_ENDIAN,
    cs_mode=cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN,
    uc_mode=uc.UC_MODE_MIPS32 | uc.UC_MODE_BIG_ENDIAN,
    gdb_name='mips'
)
ISA_MIPS = ARCH_MIPS.isa
ARCH_MIPS.add_to_db()

ARCH_MIPS64 = MIPSArchitecture(
    name='mips64',
    alt_names=['mips64eb'],
    bits=64,
    endian=Endian.BIG,
    ks_mode=ks.KS_MODE_MIPS64 | ks.KS_MODE_BIG_ENDIAN,
    cs_mode=cs.CS_MODE_MIPS64 | cs.CS_MODE_BIG_ENDIAN,
    uc_mode=uc.UC_MODE_MIPS64 | uc.UC_MODE_BIG_ENDIAN,
    gdb_name='mips:isa64'
)
ISA_MIPS64 = ARCH_MIPS64.isa
ARCH_MIPS64.add_to_db()