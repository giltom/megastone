import unicorn
import keystone
import capstone
import capstone.arm_const

from ..architecture import Architecture, Endian
from ..regs import RegisterSet
from ..isa import InstructionSet
from megastone.util import MegastoneError


PC_THUMB_MASK = 1
CPSR_THUMB_MASK = 1 << 5


class ARMInstructionSet(InstructionSet):
    def __init__(self, *,
        name: str,
        alt_names: tuple = (),
        min_insn_size: int,
        ks_mode: int,
        cs_mode: int,
        uc_mode: int
    ):
        super().__init__(
            name=name,
            alt_names=alt_names,
            insn_alignment=min_insn_size,
            min_insn_size=min_insn_size,
            max_insn_size=4,
            ks_arch=keystone.KS_ARCH_ARM,
            ks_mode=ks_mode,
            cs_arch=capstone.CS_ARCH_ARM,
            cs_mode=cs_mode,
            uc_arch=unicorn.UC_ARCH_ARM,
            uc_mode=uc_mode
        )


class ThumbInstructionSet(ARMInstructionSet):
    def address_to_pointer(self, address):
        return address | PC_THUMB_MASK

    def pointer_to_address(self, pointer):
        return pointer & ~PC_THUMB_MASK


class ARMArchitecture(Architecture):
    """Base class for 32-bit ARM architectures."""

    def __init__(self, *,
        name: str,
        alt_names: tuple = (),
        endian: Endian,
        arm_isa: InstructionSet,
        thumb_isa: InstructionSet
    ):
        isas = [isa for isa in [arm_isa, thumb_isa] if isa is not None]
        super().__init__(
            name=name,
            alt_names=alt_names,
            bits=32,
            endian=endian,
            isas=isas,
            regs=ARM_REGS,
            pc_reg=ARM_REGS.pc,
            sp_reg=ARM_REGS.sp,
            retval_reg=ARM_REGS.r0,
            retaddr_reg=ARM_REGS.lr
        )
        self.arm = arm_isa
        self.thumb = thumb_isa

    def isa_from_address(self, address) -> InstructionSet:
        return self._get_isa(address & 1)

    def isa_from_regs(self, regs) -> InstructionSet:
        return self._get_isa(regs.cpsr & CPSR_THUMB_MASK)

    def _get_isa(self, thumb):
        if thumb:
            isa = self.thumb
        else:
            isa = self.arm
        if isa is None:
            raise MegastoneError('Architecture doesn\'t support the current instruction set')
        return isa


ARM_REGS = RegisterSet.from_libs('arm')

ISA_ARM = ARMInstructionSet(
    name='arm',
    alt_names=['arm32', 'armle'],
    min_insn_size=4,
    ks_mode=keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN,
    uc_mode=unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN
)

ISA_THUMB = ThumbInstructionSet(
    name='thumb',
    min_insn_size=2,
    ks_mode=keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN,
    uc_mode=unicorn.UC_MODE_THUMB | unicorn.UC_MODE_LITTLE_ENDIAN
)

ARCH_ARM = ARMArchitecture(
    name='arm',
    alt_names=['arm32', 'armle'],
    endian=Endian.LITTLE,
    arm_isa=ISA_ARM,
    thumb_isa=ISA_THUMB
)
ARCH_ARM.add_to_db()