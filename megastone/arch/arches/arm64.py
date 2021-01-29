import unicorn
import keystone
import capstone
import capstone.arm64_const

from ..architecture import SimpleArchitecture, Endian
from ..regs import RegisterSet


ARM64_REGS = RegisterSet.from_libs('arm64')

ARCH_ARM64 = SimpleArchitecture(
    name='arm64',
    alt_names=['aarch64', 'armv8'],
    bits=64,
    endian=Endian.LITTLE,
    insn_alignment=4,
    min_insn_size=4,
    max_insn_size=4,
    regs=ARM64_REGS,
    pc_reg=ARM64_REGS.pc,
    sp_reg=ARM64_REGS.sp,
    retval_reg=ARM64_REGS.x0,
    retaddr_reg=ARM64_REGS.lr,
    ks_arch=keystone.KS_ARCH_ARM64,
    cs_arch=capstone.CS_ARCH_ARM64,
    uc_arch=unicorn.UC_ARCH_ARM64
)
ISA_ARM64 = ARCH_ARM64.isa
ARCH_ARM64.add_to_db()