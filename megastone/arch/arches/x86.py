import unicorn
import keystone
import capstone
import capstone.x86_const

from ..architecture import SimpleArchitecture, Endian
from ..regs import RegisterSet


X86_REGS = RegisterSet.from_libs('x86')


class X86Architecture(SimpleArchitecture):
    """X86-family architecture"""

    def __init__(self, **kwargs):
        kwargs.update(
            endian=Endian.LITTLE,
            regs=X86_REGS,
            insn_alignment=1,
            insn_sizes=range(1, 16),
            ks_arch=keystone.KS_ARCH_X86,
            cs_arch=capstone.CS_ARCH_X86,
            uc_arch=unicorn.UC_ARCH_X86,
        )
        super().__init__(**kwargs)


ARCH_X86_16 = X86Architecture(
    name='x86-16',
    alt_names=['x86_16', 'x8616', 'x86-realmode', '8086'],
    bits=16,
    pc_name='ip',
    sp_name='sp',
    retval_name='ax',
    ks_mode=keystone.KS_MODE_16,
    cs_mode=capstone.CS_MODE_16,
    uc_mode=unicorn.UC_MODE_16
)
ISA_X86_16 = ARCH_X86_16.isa
ARCH_X86_16.add_to_db()

ARCH_X86 = X86Architecture(
    name='x86',
    alt_names=['x86-32', 'x86_32', 'x8632', 'i386'],
    bits=32,
    pc_name='eip',
    sp_name='esp',
    retval_name='eax',
    ks_mode=keystone.KS_MODE_32,
    cs_mode=capstone.CS_MODE_32,
    uc_mode=unicorn.UC_MODE_32,
    gdb_name='i386'
)
ISA_X86 = ARCH_X86.isa
ARCH_X86.add_to_db()

ARCH_X86_64 = X86Architecture(
    name='x86-64',
    alt_names=['x86_64', 'x8664', 'x64', 'amd64', 'i386:x86-64'],
    bits=64,
    pc_name='rip',
    sp_name='rsp',
    retval_name='rax',
    ks_mode=keystone.KS_MODE_64,
    cs_mode=capstone.CS_MODE_64,
    uc_mode=unicorn.UC_MODE_64,
    gdb_name='i386:x86-64'
)
ISA_X86_64 = ARCH_X86_64.isa
ARCH_X86_64.add_to_db()