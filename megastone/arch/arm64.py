import unicorn
import keystone
import capstone

from .architecture import Architecture, Endian

ARCH_ARM64 = Architecture(
    name='arm64',
    alt_names=['aarch64', 'armv8'],
    bits=64,
    endian=Endian.LITTLE,
    insn_alignment=4,
    min_insn_size=4,
    max_insn_size=4,
    pc_reg='pc',
    sp_reg='sp',
    retval_reg='x0',
    lr_reg='lr',
    ks_arch=keystone.KS_ARCH_ARM64,
    cs_arch=capstone.CS_ARCH_ARM64,
    uc_arch=unicorn.UC_ARCH_ARM64,
    uc_reg_prefix='UC_ARM64_REG_',
    uc_const_module=unicorn.arm64_const
)
Architecture.register(ARCH_ARM64)