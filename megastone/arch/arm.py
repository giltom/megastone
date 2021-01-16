import unicorn
import keystone
import capstone

from .architecture import Architecture, Endian


CPSR_THUMB_MASK = 1 << 5


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
            pc_reg='pc',
            sp_reg='sp',
            retval_reg='r0',
            lr_reg='lr',
            ks_arch=keystone.KS_ARCH_ARM,
            ks_mode=ks_mode,
            cs_arch=capstone.CS_ARCH_ARM,
            cs_mode=cs_mode,
            uc_arch=unicorn.UC_ARCH_ARM,
            uc_mode=uc_mode,
            uc_reg_prefix='UC_ARM_REG_',
            uc_const_module=unicorn.arm_const
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
    min_insn_size=4,
    ks_mode=keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN,
    uc_mode=unicorn.UC_MODE_THUMB | unicorn.UC_MODE_LITTLE_ENDIAN
)
Architecture.register(ARCH_THUMB)