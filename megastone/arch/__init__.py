from .architecture import Architecture, Endian
from .isa import InstructionSet
from .regs import Register, RegisterSet

from .x86 import X86_REGS, ARCH_X86_16, ISA_X86_16, ARCH_X86, ISA_X86, ARCH_X86_64, ISA_X86_64
from .arm import ARM_REGS, ARCH_ARM, ISA_ARM, ISA_THUMB
from .arm64 import ARM64_REGS, ARCH_ARM64, ISA_ARM64