from __future__ import annotations

import enum

import capstone


GROUP_BRANCH_RELATIVE = 7 #as far as i can tell this is consistent for all arches


class Instruction:
    """Disassembled instruction."""

    def __init__(self, cs_insn: capstone.CsInsn):
        self.cs_insn = cs_insn
        
        self._groups = None
        self._regs_read = None
        self._regs_written = None
        self._regs_accessed = None
        self._operands = None

    @property
    def mnemonic(self) -> str:
        """The instruction mnemonic"""
        return self.cs_insn.mnemonic

    @property
    def op_string(self) -> str:
        """The operands as a string."""
        return self.cs_insn.op_str

    @property
    def address(self) -> int:
        """The address of the instruction."""
        return self.cs_insn.address

    @property
    def size(self) -> int:
        """The size of the encoded instruction."""
        return self.cs_insn.size

    @property
    def bytes(self):
        """The encoded instruction bytes."""
        return bytes(self.cs_insn.bytes)

    @property
    def operands(self) -> list[Operand | MemoryOperand | ImmediateOperand | RegisterOperand]:
        if self._operands is None:
            operands = []
            for i, cs_op in enumerate(self.cs_insn.operands):
                op_type = CS_OP_TO_OP_TYPE.get(cs_op.type, OperandType.OTHER)
                op_class = OP_TYPE_TO_CLASS.get(op_type, Operand)
                operands.append(op_class(self, op_type, cs_op, i))
            self._operands = operands
        return self._operands

    @property
    def num_operands(self):
        return len(self.cs_insn.operands)

    def __str__(self):
        return f'{self.mnemonic} {self.op_string}'

    def __repr__(self):
        return f'<{self.__class__.__name__} 0x{self.address:X}: {self.bytes.hex()}  {self.mnemonic} {self.op_string}>'

    def __eq__(self, other):
        """Compare both the instruction bytes and the address."""
        if not isinstance(other, Instruction):
            return False
        return self.address == other.address and self.bytes == other.bytes

    def __hash__(self):
        return hash((self.address, self.bytes))

    @property
    def regs_read(self) -> list[str]:
        """Names of Registers read by the instruction."""
        self._init_regs()
        return self._regs_read

    @property
    def regs_written(self) -> list[str]:
        """Names of Registers written by the instruction."""
        self._init_regs()
        return self._regs_written

    @property
    def regs_accessed(self) -> list[str]:
        """Names of Registers read or written by the instruction."""
        if self._regs_accessed is None:
            self._regs_accessed = sorted(set(self.regs_read + self.regs_written))
        return self._regs_accessed

    @property
    def groups(self) -> list[str]:
        """Names of groups that this instruction belongs to."""
        if self._groups is None:
            self._groups = [self.cs_insn.group_name(i, 'unknown') for i in self.cs_insn.groups]
        return self._groups

    @property
    def is_jump(self):
        """True if this is a jump instruction."""
        return self._is_group(capstone.CS_GRP_JUMP)

    @property
    def is_call(self):
        """
        True if this is a call instruction.
        
        Note that some instructions (i.e. BL) can be both a call and a jump if they are ambiguous.
        """
        return self._is_group(capstone.CS_GRP_CALL)

    @property
    def is_ret(self):
        """True if this is a ret instruction."""
        return self._is_group(capstone.CS_GRP_RET)

    @property
    def is_iret(self):
        """True if this is an interrupt return instruction."""
        return self._is_group(capstone.CS_GRP_IRET)

    @property
    def is_interrupt(self):
        """True if this is an interrupt instruction (syscalll, SVC, etc.)"""
        return self._is_group(capstone.CS_GRP_INT)

    @property
    def is_privileged(self):
        """True if this is a privileged instruction."""
        return self._is_group(capstone.CS_GRP_PRIVILEGE)

    @property
    def is_relative(self):
        """True if this is a relative jump/call."""
        return self._is_group(GROUP_BRANCH_RELATIVE)

    @property
    def is_absolute(self):
        """True if this is an absolute jump/call."""
        return (self.is_jump or self.is_call) and not self.is_relative

    def _is_group(self, gid):
        return gid in self.cs_insn.groups
    
    def _init_regs(self):
        if self._regs_read is None:
            ids_read, ids_written = self.cs_insn.regs_access()
            self._regs_read = sorted(self._get_reg_name(i) for i in ids_read)
            self._regs_written = sorted(self._get_reg_name(i) for i in ids_written)

    def _get_reg_name(self, id):
        return self.cs_insn.reg_name(id)


class OperandType(enum.Enum):
    REGISTER = enum.auto()
    IMMEDIATE = enum.auto()
    MEMORY = enum.auto()
    OTHER = enum.auto()


class Operand:
    def __init__(self, insn: Instruction, type: OperandType, cs_op, index: int):
        self.insn = insn
        self.type = type
        self.cs_op = cs_op
        self.index = index

    @property
    def is_reg(self):
        return self.type is OperandType.REGISTER
    
    @property
    def is_immediate(self):
        return self.type is OperandType.IMMEDIATE

    @property
    def is_memory(self):
        return self.type is OperandType.MEMORY

    def __repr__(self):
        return f'<Operand: {self.type}>'


class RegisterOperand(Operand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._reg = None

    @property
    def reg(self) -> str:
        """The name of the register."""
        if self._reg is None:
            self._reg = self.insn._get_reg_name(self.cs_op.reg)
        return self._reg

    def __repr__(self):
        return f'<{self.__class__.__name__} {repr(self.reg)}>'

    def __str__(self):
        return self.reg


class ImmediateOperand(Operand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.value: int = self.cs_op.imm

    def __repr__(self):
        return f'<{self.__class__.__name__} {hex(self.value)}>'

    def __str__(self):
        return hex(self.value)

    def __int__(self):
        return self.value


class MemoryOperand(Operand):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._initialized = False
        self._base_reg = None
        self._index_reg = None
        self._scale = None
        self._offset = None

    @property
    def base_reg(self) -> str | None:
        self._init_attributes()
        return self._base_reg

    @property
    def index_reg(self) -> str | None:
        self._init_attributes()
        return self._index_reg

    @property
    def scale(self) -> int:
        self._init_attributes()
        return self._scale

    @property
    def offset(self) -> int:
        self._init_attributes()
        return self._offset

    @property
    def is_direct(self):
        """True if this is a direct memory access (immediate address)."""
        return self.base_reg is None and self.index_reg is None

    def __repr__(self):
        parts = []
        if self.base_reg is not None:
            parts.append(f'base_reg={repr(self.base_reg)}')
        if self.index_reg is not None:
            parts.append(f'index_reg={repr(self.index_reg)}')
        if self.scale != 1:
            parts.append(f'scale={self.scale}')
        if self.offset != 0 or len(parts) == 0:
            parts.append(f'offset={hex(self.offset)}')
        return f'<{self.__class__.__name__}({", ".join(parts)})'

    def __str__(self):
        parts = []
        if self.base_reg is not None:
            parts.append(self.base_reg)
        if self.index_reg is not None:
            if self.scale != 1:
                parts.append(f'{self.scale}*{self.index_reg}')
            else:
                parts.append(self.index_reg)
        if self.offset != 0 or len(parts) == 0:
            parts.append(hex(self.offset))
        return ' + '.join(parts)
        
    def _init_attributes(self):
        if self._initialized:
            return
        
        self._base_reg = self._get_reg('base')
        self._index_reg = self._get_reg('index')
        self._scale = getattr(self.cs_op.mem, 'scale', 1)
        self._offset = getattr(self.cs_op.mem, 'disp', 0)
        self._initialized = True
    
    def _get_reg(self, attr_name):
        reg_id = getattr(self.cs_op.mem, attr_name, 0)
        if reg_id == 0:
            return None
        return self.insn._get_reg_name(reg_id)


CS_OP_TO_OP_TYPE = {
    capstone.CS_OP_REG: OperandType.REGISTER,
    capstone.CS_OP_IMM: OperandType.IMMEDIATE,
    capstone.CS_OP_MEM: OperandType.MEMORY
}


OP_TYPE_TO_CLASS = {
    OperandType.REGISTER: RegisterOperand,
    OperandType.IMMEDIATE: ImmediateOperand,
    OperandType.MEMORY: MemoryOperand
}