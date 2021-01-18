import unicorn
import keystone
import capstone
import capstone.x86_const

from .architecture import SimpleArchitecture, Endian
from .regs import RegisterSet


X86_REGS = RegisterSet.from_libs('x86')


class X86Architecture(SimpleArchitecture):
    """X86-family architecture"""

    def __init__(self, *,
        name,
        alt_names,
        bits,
        pc_reg,
        sp_reg,
        retval_reg,
        ks_mode,
        cs_mode,
        uc_mode
    ):
        super().__init__(
            name=name,
            alt_names=alt_names,
            bits=bits,
            endian=Endian.LITTLE,
            insn_alignment=1,
            min_insn_size=1,
            max_insn_size=15,
            regs=X86_REGS,
            pc_reg=pc_reg,
            sp_reg=sp_reg,
            retval_reg=retval_reg,
            ks_arch=keystone.KS_ARCH_X86,
            ks_mode=ks_mode,
            cs_arch=capstone.CS_ARCH_X86,
            cs_mode=cs_mode,
            uc_arch=unicorn.UC_ARCH_X86,
            uc_mode=uc_mode
        )


ARCH_X86_16 = X86Architecture(
    name='x86-16',
    alt_names=['x86_16', 'x8616', 'x86-realmode'],
    bits=16,
    pc_reg=X86_REGS.ip,
    sp_reg=X86_REGS.sp,
    retval_reg=X86_REGS.ax,
    ks_mode=keystone.KS_MODE_16,
    cs_mode=capstone.CS_MODE_16,
    uc_mode=unicorn.UC_MODE_16
)
ISA_X86_16 = ARCH_X86_16.isa

ARCH_X86 = X86Architecture(
    name='x86',
    alt_names=['x86-32', 'x86_32', 'x8632', 'i386'],
    bits=32,
    pc_reg=X86_REGS.eip,
    sp_reg=X86_REGS.esp,
    retval_reg=X86_REGS.eax,
    ks_mode=keystone.KS_MODE_32,
    cs_mode=capstone.CS_MODE_32,
    uc_mode=unicorn.UC_MODE_32
)
ISA_X86 = ARCH_X86.isa

ARCH_X86_64 = X86Architecture(
    name='x86-64',
    alt_names=['x86_64', 'x8664', 'x64', 'amd64'],
    bits=64,
    pc_reg=X86_REGS.rip,
    sp_reg=X86_REGS.rsp,
    retval_reg=X86_REGS.rax,
    ks_mode=keystone.KS_MODE_64,
    cs_mode=capstone.CS_MODE_64,
    uc_mode=unicorn.UC_MODE_64
)
ISA_X86_64 = ARCH_X86_64.isa