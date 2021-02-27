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


class BaseARMInstructionSet(InstructionSet):
    def __init__(self, **kwargs):
        kwargs.update(
            insn_alignment=min(kwargs['insn_sizes']),
            ks_arch=keystone.KS_ARCH_ARM,
            cs_arch=capstone.CS_ARCH_ARM
        )
        super().__init__(**kwargs)


class ARMInstructionSet(BaseARMInstructionSet):
    def __init__(self, **kwargs):
        kwargs.update(
            insn_sizes=[4],
            ks_mode=keystone.KS_MODE_ARM,
            cs_mode=capstone.CS_MODE_ARM
        )
        super().__init__(**kwargs)


class ThumbInstructionSet(BaseARMInstructionSet):
    def __init__(self, **kwargs):
        kwargs.update(
            insn_sizes=[2, 4],
            ks_mode=keystone.KS_MODE_THUMB,
            cs_mode=capstone.CS_MODE_THUMB
        )
        super().__init__(**kwargs)

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
            uc_mode=unicorn.UC_MODE_ARM,
            gdb_name='arm',
            elf_machine='EM_ARM'
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
    alt_names=['arm32', 'armle', 'armel'],
    endian=Endian.LITTLE
)

ISA_THUMB = ThumbInstructionSet(
    name='thumb',
    alt_names=['thumble', 'thumbel'],
    endian=Endian.LITTLE
)

ARCH_ARM = ARMArchitecture(
    name='arm',
    alt_names=['arm32', 'armle', 'armel'],
    endian=Endian.LITTLE,
    arm_isa=ISA_ARM,
    thumb_isa=ISA_THUMB,
)


ISA_ARMBE = ARMInstructionSet(
    name='armbe',
    alt_names=['arm32be', 'armeb'],
    endian=Endian.BIG
)

ISA_THUMBBE = ThumbInstructionSet(
    name='thumbbe',
    alt_names=['thumbbe'],
    endian=Endian.BIG
)

ARCH_ARMBE = ARMArchitecture(
    name='armbe',
    alt_names=['arm32be', 'armeb'],
    endian=Endian.BIG,
    arm_isa=ISA_ARMBE,
    thumb_isa=ISA_THUMBBE
)