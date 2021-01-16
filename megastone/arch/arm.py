import unicorn
import keystone
import capstone
import capstone.arm_const

from .architecture import Architecture, Endian
from .regs import RegisterSet


CPSR_THUMB_MASK = 1 << 5


ARM_REGS = RegisterSet.from_libs('arm')


class ARMArchitecture(Architecture):
    """Base class for 32-bit ARM architectures."""

    def __init__(self, *,
        name,
        alt_names,
        min_insn_size,
        ks_mode,
        cs_mode,
        uc_mode
    ):
        super().__init__(
            name=name,
            alt_names=alt_names,
            bits=32,
            endian=Endian.LITTLE,
            insn_alignment=min_insn_size,
            min_insn_size=min_insn_size,
            max_insn_size=4,
            regs=ARM_REGS,
            pc_reg=ARM_REGS.pc,
            sp_reg=ARM_REGS.sp,
            retval_reg=ARM_REGS.r0,
            retaddr_reg=ARM_REGS.lr,
            ks_arch=keystone.KS_ARCH_ARM,
            ks_mode=ks_mode,
            cs_arch=capstone.CS_ARCH_ARM,
            cs_mode=cs_mode,
            uc_arch=unicorn.UC_ARCH_ARM,
            uc_mode=uc_mode
        )
    
    def update_arch(self, regs):
        if regs['cpsr'] & CPSR_THUMB_MASK:
            return ARCH_THUMB
        return ARCH_ARM


ARCH_ARM = ARMArchitecture(
    name='arm',
    alt_names=['arm32', 'armle'],
    min_insn_size=4,
    ks_mode=keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
    uc_mode=unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN
)
Architecture.register(ARCH_ARM)

ARCH_THUMB = ARMArchitecture(
    name='thumb',
    alt_names=['arm-thumb', 'armthumb'],
    min_insn_size=2,
    ks_mode=keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN,
    uc_mode=unicorn.UC_MODE_THUMB | unicorn.UC_MODE_LITTLE_ENDIAN
)
Architecture.register(ARCH_THUMB)