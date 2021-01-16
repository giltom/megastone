import unicorn
import keystone
import capstone

from .architecture import Architecture, Endian


class X86Architecture(Architecture):
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
            pc_reg=pc_reg,
            sp_reg=sp_reg,
            retval_reg=retval_reg,
            lr_reg=None,
            ks_arch=keystone.KS_ARCH_X86,
            ks_mode=ks_mode,
            cs_arch=capstone.CS_ARCH_X86,
            cs_mode=cs_mode,
            uc_arch=unicorn.UC_ARCH_X86,
            uc_mode=uc_mode,
            uc_reg_prefix='UC_X86_REG_',
            uc_const_module=unicorn.x86_const
        )


ARCH_X86_16 = X86Architecture(
    name='x86-16',
    alt_names=['x86_16', 'x8616', 'x86-realmode'],
    bits=16,
    pc_reg='ip',
    sp_reg='sp',
    retval_reg='ax',
    ks_mode=keystone.KS_MODE_16,
    cs_mode=capstone.CS_MODE_16,
    uc_mode=unicorn.UC_MODE_16
)
Architecture.register(ARCH_X86_16)

ARCH_X86 = X86Architecture(
    name='x86',
    alt_names=['x86-32', 'x86_32', 'x8632', 'i386'],
    bits=32,
    pc_reg='eip',
    sp_reg='esp',
    retval_reg='eax',
    ks_mode=keystone.KS_MODE_32,
    cs_mode=capstone.CS_MODE_32,
    uc_mode=unicorn.UC_MODE_32
)
Architecture.register(ARCH_X86)

ARCH_X86_64 = X86Architecture(
    name='x86-64',
    alt_names=['x86_64', 'x8664', 'x64', 'amd64'],
    bits=64,
    pc_reg='rip',
    sp_reg='rsp',
    retval_reg='rax',
    ks_mode=keystone.KS_MODE_64,
    cs_mode=capstone.CS_MODE_64,
    uc_mode=unicorn.UC_MODE_64
)
Architecture.register(ARCH_X86_64)