import pytest
import dataclasses

import megastone as ms
from megastone.util import hex_spaces


def test_armthumb_add(arm_isa: ms.InstructionSet):
    insn = arm_isa.parse_instruction('add r0, r1, r2')

    assert not insn.is_jump
    assert not insn.is_call
    assert not insn.is_ret
    assert not insn.is_iret
    assert not insn.is_interrupt
    assert not insn.is_relative
    assert not insn.is_absolute
    assert not insn.is_privileged

    assert len(insn.operands) == insn.num_operands == 3
    assert insn.operands[0].reg == 'r0'
    assert insn.operands[1].reg == 'r1'
    assert insn.operands[2].reg == 'r2'

    assert insn.regs_read == ['r1', 'r2']
    assert insn.regs_written == ['r0']
    assert insn.regs_accessed == ['r0', 'r1', 'r2']
    assert insn.regs_accessed == ['r0', 'r1', 'r2']

    assert insn.bytes == arm_isa.assemble('add r0, r1, r2')

    for i, op in enumerate(insn.operands):
        assert op.is_reg
        assert not op.is_immediate
        assert not op.is_memory
        assert op.index == i

def test_armthumb_b(arm_isa: ms.InstructionSet):
    insn = arm_isa.parse_instruction('B 0x1000')

    assert insn.is_jump
    assert not insn.is_call
    assert insn.is_relative

    assert insn.num_operands == 1
    assert insn.operands[0].is_immediate
    assert insn.operands[0].value == 0x1000

def test_armthumb_blx(arm_isa: ms.InstructionSet):
    insn = arm_isa.parse_instruction('BLX R0')

    assert insn.is_call
    assert insn.is_absolute

    assert insn.num_operands == 1
    assert insn.operands[0].reg == 'r0'
    assert insn.operands[0].is_reg

def test_armthumb_mem(arm_isa: ms.InstructionSet):
    insn = arm_isa.parse_instruction('LDR R0, [R1, #-4]')

    assert insn.num_operands == 2
    assert insn.operands[0].reg == 'r0'

    op = insn.operands[1]
    assert op.is_memory
    assert op.base_reg == 'r1'
    assert op.index_reg is None
    assert op.scale == 1
    assert op.offset == -4

def test_armthumb_mem_index(arm_isa: ms.InstructionSet):
    insn = arm_isa.parse_instruction('LDR R1, [R2, R3]')

    assert insn.num_operands == 2

    op = insn.operands[1]
    assert op.base_reg == 'r2'
    assert op.index_reg == 'r3'
    assert op.scale == 1
    assert op.offset == 0
    assert str(op) == 'r2 + r3'

def test_armthumb_svc(arm_isa):
    assert arm_isa.parse_instruction('svc #40').is_interrupt

def test_armthumb_priv(arm_isa):
    assert arm_isa.parse_instruction('MCR p15, 0, r0, c0, c0, 0').is_privileged

def test_armthumb_sp(arm_isa):
    insn = arm_isa.parse_instruction('SUB SP, #12')

    assert insn.operands[0].reg == 'sp'

def test_armthumb_pc():
    insn = ms.ISA_ARM.parse_instruction('LDR PC, =0x2000')

    assert insn.operands[0].reg == 'pc'
    assert insn.operands[1].base_reg == 'pc'

def test_x86_add():
    insn = ms.ISA_X86.parse_instruction('add eax, ebx')

    assert insn.num_operands == 2
    assert insn.operands[0].reg == 'eax'
    assert insn.operands[1].reg == 'ebx'

    assert insn.regs_written == ['eax', 'eflags']
    assert insn.regs_read == ['eax', 'ebx']

def test_x86_jmp():
    insn = ms.ISA_X86.parse_instruction('jmp 0x1000')

    assert insn.is_jump
    assert insn.is_relative
    assert not insn.is_call
    
    assert insn.num_operands == 1
    assert insn.operands[0].value == 0x1000

def test_x86_call():
    insn = ms.ISA_X86_16.parse_instruction('call 0x300')

    assert insn.is_call
    assert insn.is_relative
    assert not insn.is_jump

def test_x86_jmp_reg():
    insn = ms.ISA_X86_64.parse_instruction('call rax')

    assert insn.is_call
    assert insn.is_absolute

    assert insn.num_operands == 1
    assert insn.operands[0].reg == 'rax'

def test_x86_ret():
    assert ms.ISA_X86_64.parse_instruction('ret').is_ret

def test_x86_iret():
    assert ms.ISA_X86.parse_instruction('iret').is_iret

def test_x86_syscall():
    assert ms.ISA_X86_64.parse_instruction('syscall').is_interrupt

def test_x86_mem():
    insn = ms.ISA_X86_64.parse_instruction('mov rax, [rbx + 2*rcx + 0x80]')

    assert insn.num_operands == 2

    op = insn.operands[1]
    assert op.base_reg == 'rbx'
    assert op.index_reg == 'rcx'
    assert op.scale == 2
    assert op.offset == 0x80

    assert str(op) == 'rbx + 2*rcx + 0x80'
    assert repr(op) == "<MemoryOperand(base_reg='rbx', index_reg='rcx', scale=2, offset=0x80)"

def test_x86_direct():
    insn = ms.ISA_X86.parse_instruction('mov eax, dword ptr [0x8000]')

    assert insn.num_operands == 2

    op = insn.operands[1]
    assert op.is_direct
    assert op.offset == 0x8000
    assert op.base_reg is None
    assert op.index_reg is None
    assert op.scale == 1
    
    assert str(op) == '0x8000'
    assert repr(op) == "<MemoryOperand(offset=0x8000)"

def test_arm64_add():
    insn = ms.ISA_ARM64.parse_instruction('ADD X0, X1, X2')

    for i, op in enumerate(insn.operands):
        assert op.reg == f'x{i}'

def test_arm64_ret():
    assert ms.ISA_ARM64.parse_instruction('RET').is_ret

def test_arm64_b():
    insn = ms.ISA_ARM64.parse_instruction('B 0x1000')

    assert insn.is_jump and insn.is_relative
    assert not insn.is_call
    assert insn.num_operands == 1
    assert insn.operands[0].value == 0x1000

def test_arm64_mem():
    insn = ms.ISA_ARM64.parse_instruction('LDR X0, [X1, X2]')

    op = insn.operands[1]
    assert op.base_reg == 'x1'
    assert op.index_reg == 'x2'

def test_arm64_sp():
    insn = ms.ISA_ARM64.parse_instruction('MOV X0, SP')
    assert insn.operands[1].reg == 'sp'

def test_arm64_lr():
    assert ms.ISA_ARM64.parse_instruction('MOV X0, LR').operands[1].reg == 'x30'

@pytest.mark.xfail(reason="Unicorn doesn't recognize ARM64 calls properly")
def test_arm64_call():
    insn = ms.ISA_ARM64.parse_instruction('BL 0x1000')

    assert insn.is_call

def test_mips_add():
    insn = ms.ISA_MIPS.parse_instruction('add $t0, $t1, $t2')

    assert insn.num_operands == 3
    for i, op in enumerate(insn.operands):
        assert op.reg == f't{i}'
        assert str(op) == f't{i}'
        assert f"'t{i}'" in repr(op)

def test_mips_immediate():
    insn = ms.ISA_MIPS.parse_instruction('lui $v0, 100')

    assert insn.num_operands == 2
    assert insn.operands[0].reg == 'v0'
    assert insn.operands[1].value == 100

    assert str(insn.operands[1]) == hex(100)
    assert int(insn.operands[1]) == 100
    assert hex(100) in repr(insn.operands[1])

def test_mips_mem():
    insn = ms.ISA_MIPS.parse_instruction('sw $a0, 0x8($sp)')

    assert insn.num_operands == 2
    assert insn.operands[0].reg == 'a0'

    op = insn.operands[1]
    assert op.base_reg == 'sp'
    assert op.index_reg is None
    assert op.offset == 0x8
    assert op.scale == 1
    assert str(op) == 'sp + 0x8'

def test_mips_j():
    insn = ms.ISA_MIPS.parse_instruction('j 0x8000')

    assert insn.num_operands == 1
    assert insn.is_jump and insn.is_absolute
    assert insn.operands[0].value == 0x8000

@pytest.mark.xfail(reason="Unicorn doesn't recognize MIPS jal properly")
def test_mips_jal():
    insn = ms.ISA_MIPS.parse_instruction('jal 0x8000')

    assert insn.is_jump or insn.is_call

def test_mips_beq():
    insn = ms.ISA_MIPS.parse_instruction('beq $t1, $t2, 0x800')

    assert insn.is_jump
    assert insn.is_relative
    assert insn.operands[2].value == 0x800

def test_insn_eq():
    insns = [ms.ISA_MIPS64.parse_instruction('move $t2, $t3') for _ in range(2)]

    assert insns[0] == insns[1]
    assert hash(insns[0]) == hash(insns[1])
    assert insns[0] != 4

def test_groups():
    insn = ms.ISA_THUMB.parse_instruction('SUB R1, R2, R3')

    assert insn.groups == ['thumb2']
    assert insn.groups == ['thumb2']

def test_unknown_op():
    insn = ms.ISA_ARM.parse_instruction('MRC p15, 0, r0, c1, c2, 3')

    assert insn.num_operands == 6
    assert insn.operands[0].type == ms.OperandType.OTHER
    assert 'OTHER' in repr(insn.operands[0])

def test_format():
    address = 0x980
    assembly = 'add eax, ebx'
    code = ms.ISA_X86.assemble(assembly, address=address)
    hex_code = hex_spaces(code)
    insn = ms.ISA_X86.parse_instruction(assembly, address=address)

    assert insn.format() == f'0x{address:X}  {hex_code}  {assembly}'
    
    assert insn.format(address=False) == f'{hex_code}  {assembly}'

    assert insn.format(data=False) == f'0x{address:X}  {assembly}'
    assert insn.format(data_size=1) == f'0x{address:X}  {code[0]:02X}+ {assembly}'
    assert insn.format(data_size=len(code)) == insn.format()
    assert insn.format(data_size=len(code) + 1) == f'0x{address:X}  {hex_code}     {assembly}'
    assert insn.format(data_size=len(code) + 2) == f'0x{address:X}  {hex_code}        {assembly}'

    assert insn.format(mnem_len=4) == f'0x{address:X}  {hex_code}  {insn.mnemonic}  {insn.op_string}'
    assert insn.format(upper=True) == f'0x{address:X}  {hex_code}  {assembly.upper()}'