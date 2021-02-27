import unicorn
import keystone
import capstone
import capstone.arm_const

from ..architecture import Architecture, Endian
from ..regs import RegisterState, RegisterSet
from ..isa import InstructionSet
from megastone.errors import MegastoneError


PC_THUMB_MASK = 1
CPSR_THUMB_MASK = 1 << 5


class ARMInstructionSet(InstructionSet):
    def __init__(self, **kwargs):
        kwargs.update(
            insn_alignment=min(kwargs['insn_sizes']),
            ks_arch=keystone.KS_ARCH_ARM,
            cs_arch=capstone.CS_ARCH_ARM
        )
        super().__init__(**kwargs)


class ThumbInstructionSet(ARMInstructionSet):
    def address_to_pointer(self, address: int):
        return address | PC_THUMB_MASK


class ARMArchitecture(Architecture):
    """Base class for 32-bit ARM architectures."""

    def __init__(self, *,
        arm_isa: InstructionSet,
        thumb_isa: InstructionSet,
        **kwargs
    ):
        isas = [isa for isa in [arm_isa, thumb_isa] if isa is not None]
        kwargs.update(
            bits=32,
            isas=isas,
            regs=ARM_REGS,
            pc_name='pc',
            sp_name='sp',
            retval_name='r0',
            retaddr_name='lr',
            uc_arch=unicorn.UC_ARCH_ARM,
            uc_mode=unicorn.UC_MODE_ARM | unicorn.UC_MODE_LITTLE_ENDIAN
        )
        super().__init__(**kwargs)
        self.arm = arm_isa
        self.thumb = thumb_isa

    def pointer_to_address(self, pointer: int):
        return pointer & ~PC_THUMB_MASK

    def isa_from_pointer(self, pointer):
        return self._get_isa(pointer & 1)

    def isa_from_regs(self, regs: RegisterState):
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
    insn_sizes=[4],
    ks_mode=keystone.KS_MODE_ARM | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_ARM | capstone.CS_MODE_LITTLE_ENDIAN
)

ISA_THUMB = ThumbInstructionSet(
    name='thumb',
    insn_sizes=[2, 4],
    ks_mode=keystone.KS_MODE_THUMB | keystone.KS_MODE_LITTLE_ENDIAN,
    cs_mode=capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN
)

ARCH_ARM = ARMArchitecture(
    name='arm',
    alt_names=['arm32', 'armle'],
    endian=Endian.LITTLE,
    arm_isa=ISA_ARM,
    thumb_isa=ISA_THUMB,
    gdb_name='arm'
)
ARCH_ARM.add_to_db()