import pytest

from megastone import (Debugger, Emulator, ARCH_ARM, HOOK_STOP, HOOK_STOP_ONCE,
    StopType, HookFunc, AccessType, InvalidInsnError, MemFaultError, Access, FaultCause,
    ARCH_X86, CPUError)


CODE_ADDRESS = 0x1000
CODE_SIZE = 0x1000

CODE2_ADDRESS = 0x2000
DATA_ADDRESS = 0x3000
DATA_SIZE = 0x1000
STACK_ADDRESS = DATA_SIZE + DATA_SIZE - 0x20
FUNC_ADDRESS = CODE_ADDRESS + 0x100

THUMB_NOP = ARCH_ARM.thumb.assemble('nop')
ARM_NOP = ARCH_ARM.arm.assemble('nop')

def get_emulator(arch, isa):
    emu = Emulator(arch)
    map_code_segment(emu, 'code', CODE_ADDRESS, isa)
    emu.mem.map('data', DATA_ADDRESS, DATA_SIZE, AccessType.RW)
    emu.mem.default_isa = isa
    emu.sp = STACK_ADDRESS
    emu.jump(CODE_ADDRESS, isa)
    return emu

def map_code_segment(emu, name, address, isa):
    emu.mem.map(name, address, CODE_SIZE)
    nop = isa.assemble('nop')
    emu.mem.write(address, nop * (CODE_SIZE // len(nop)))

@pytest.fixture
def dbg():
    return get_emulator(ARCH_ARM, ARCH_ARM.arm)

@pytest.fixture
def armthumb_dbg(arm_isa, other_arm_isa):
    emu = get_emulator(ARCH_ARM, arm_isa)
    map_code_segment(emu, 'code2', CODE2_ADDRESS, other_arm_isa)
    return emu

@pytest.fixture
def arch_dbg(arch, isa):
    return get_emulator(arch, isa)

def test_init_pc(arch_dbg):
    assert arch_dbg.pc == CODE_ADDRESS

def test_curr_insn(arch_dbg):
    assert arch_dbg.get_current_insn().mnemonic.lower() == 'nop'

def test_step(arch_dbg, nop):
    for i in range(3):
        arch_dbg.step()
        assert arch_dbg.pc == CODE_ADDRESS + (i + 1)*len(nop)

def test_run(arch_dbg, isa, nop):
    run_addr = CODE_ADDRESS + 30 * len(nop)
    count = 11

    reason = arch_dbg.run(count, address=run_addr, isa=isa)
    assert reason.type is StopType.COUNT
    assert arch_dbg.pc == run_addr + count * len(nop)

def test_thumb_switch(armthumb_dbg, other_arm_isa):
    count = 3

    armthumb_dbg.step()
    armthumb_dbg.run(count, address=CODE2_ADDRESS, isa=other_arm_isa)
    assert armthumb_dbg.pc == CODE2_ADDRESS + count * len(other_arm_isa.assemble('nop'))

def test_thumb_address_switch(armthumb_dbg, other_arm_isa):
    armthumb_dbg.run(14)
    armthumb_dbg.jump(other_arm_isa.address_to_pointer(CODE2_ADDRESS))
    armthumb_dbg.step()
    assert armthumb_dbg.pc == CODE2_ADDRESS + len(other_arm_isa.assemble('nop'))

def test_stop_hook(arch_dbg: Debugger, nop):
    hook_addr = CODE_ADDRESS + 10 * len(nop)

    arch_dbg.add_code_hook(HOOK_STOP, hook_addr)

    for _ in range(3):
        reason = arch_dbg.run()
        assert reason.type is StopType.HOOK
        assert reason.hook.func is HOOK_STOP
        assert arch_dbg.pc == hook_addr

    arch_dbg.step()
    assert arch_dbg.pc == hook_addr

def test_stop_once_hook(arch_dbg: Debugger, isa, nop):
    hook_addr = CODE_ADDRESS + 10 * len(nop)
    stop_addr = hook_addr + 5 * len(nop)

    arch_dbg.add_code_hook(HOOK_STOP_ONCE, hook_addr)
    arch_dbg.add_code_hook(HOOK_STOP, stop_addr)

    arch_dbg.run()
    assert arch_dbg.pc == hook_addr

    arch_dbg.run()
    assert arch_dbg.pc == stop_addr

    arch_dbg.run(address=CODE_ADDRESS, isa=isa)
    assert arch_dbg.pc == stop_addr

def test_breakpoint(arch_dbg: Debugger, isa, nop):
    break_addr = CODE_ADDRESS + 3 * len(nop)
    stop_addr = break_addr + len(nop)

    arch_dbg.add_breakpoint(break_addr)
    arch_dbg.add_code_hook(HOOK_STOP, stop_addr)

    for _ in range(3):
        arch_dbg.run()
        assert arch_dbg.pc == break_addr

        arch_dbg.run()
        assert arch_dbg.pc == stop_addr

        arch_dbg.jump(CODE_ADDRESS, isa=isa)

def test_get_bad_reg(dbg):
    with pytest.raises(AttributeError):
        dbg.regs.not_real

def test_set_bad_reg(dbg):
    with pytest.raises(AttributeError):
        dbg.regs.not_real = 6

def test_disassemble(arch_dbg):
    count = 5

    insns = list(arch_dbg.disassemble(count))
    assert insns[0].address == CODE_ADDRESS

    for insn in insns:
        assert insn.mnemonic.lower() == 'nop'

class CounterHookFunc(HookFunc):
    def __init__(self):
        self.count = 0

    def __call__(self, dbg):
        self.count += 1

@pytest.fixture
def counter_hook():
    return CounterHookFunc()

def test_trace(arch_dbg, counter_hook):
    count = 10

    arch_dbg.trace(counter_hook)
    arch_dbg.run(count)
    assert counter_hook.count == count + 1

def test_run_until(arch_dbg, nop):
    stop_address = CODE_ADDRESS + len(nop)*15
    arch_dbg.run_until(stop_address)
    assert arch_dbg.pc == stop_address

class AccessHookFunc(CounterHookFunc):
    def __init__(self):
        super().__init__()
        self.access = None

    def __call__(self, dbg):
        super().__call__(dbg)
        self.access = dbg.curr_access

@pytest.fixture
def access_hook():
    return AccessHookFunc()

TEST_ADDRESS = DATA_ADDRESS + 9

@pytest.fixture
def rw_test_dbg(armthumb_dbg):
    assembly = f"""
        MOV R2, 3

        LDR R0, =0x{TEST_ADDRESS-1:X}
        LDRB R1, [R0]
        STRB R2, [R0]

        LDR R0, =0x{TEST_ADDRESS:X}
        LDRB R1, [R0]
        STRB R2, [R0]

        LDR R0, =0x{TEST_ADDRESS+1:X}
        LDRB R1, [R0]
        STRB R2, [R0]

        {'NOP;'*100}
    """
    armthumb_dbg.mem.write_code(CODE_ADDRESS, assembly)
    armthumb_dbg.add_breakpoint(CODE_ADDRESS + 0x30)
    return armthumb_dbg


def test_read_hook(rw_test_dbg: Debugger, access_hook):
    rw_test_dbg.add_read_hook(access_hook, TEST_ADDRESS)
    rw_test_dbg.run()
    assert access_hook.count == 1
    assert access_hook.access == Access(AccessType.R, TEST_ADDRESS, 1)

def test_write_hook(rw_test_dbg: Debugger, access_hook):
    rw_test_dbg.add_write_hook(access_hook, TEST_ADDRESS)
    rw_test_dbg.run()
    assert access_hook.count == 1
    assert access_hook.access == Access(AccessType.W, TEST_ADDRESS, 1, b'\x03')

def test_rw_hook(rw_test_dbg: Debugger, access_hook):
    rw_test_dbg.add_rw_hook(access_hook, TEST_ADDRESS)
    rw_test_dbg.run()
    assert access_hook.count == 2

class HookException(Exception):
    pass

def exception_hook(dbg):
    raise HookException()

def test_hook_exception(arch_dbg, nop):
    hook_addr = CODE_ADDRESS + 5 * len(nop)
    arch_dbg.add_code_hook(exception_hook, hook_addr)

    with pytest.raises(HookException):
        arch_dbg.run(10)
    assert arch_dbg.pc == hook_addr

def test_invalid_insn(dbg):
    dbg.mem.write(CODE_ADDRESS, b'\xFF\xFF\xFF\xFF')
    with pytest.raises(InvalidInsnError):
        dbg.run(10)

def test_cpu_error(dbg):
    dbg.mem.write_code(CODE_ADDRESS, 'SVC #0')
    with pytest.raises(CPUError):
        dbg.run(10)

def test_mem_fault(dbg):
    address = 0xDEADBEEF
    value = 0xFAFAFAFA

    dbg.mem.write_code(CODE_ADDRESS, f'LDR R0, ={address}; LDR R1, ={value}; STR R1, [R0]')
    with pytest.raises(MemFaultError) as info:
        dbg.run(3)
    assert info.value.cause is FaultCause.UNMAPPED
    assert info.value.access == Access(AccessType.W, address, 4, dbg.arch.encode_word(value))
    assert info.value.address == CODE_ADDRESS + 8

def test_stack_read(arch_dbg, arch):
    arch_dbg.mem.write_word(STACK_ADDRESS, 0xDEAD)
    arch_dbg.mem.write_word(STACK_ADDRESS + arch.word_size, 0xBEEF)
    
    assert arch_dbg.stack[0] == 0xDEAD
    assert arch_dbg.stack[1] == 0xBEEF
    assert arch_dbg.stack[:2] == [0xDEAD, 0xBEEF]

def test_stack_write(arch_dbg, arch):
    arch_dbg.stack[0] = 0xDEAD
    arch_dbg.stack[1] = 0xBEEF

    assert arch_dbg.mem.read_word(STACK_ADDRESS) == 0xDEAD
    assert arch_dbg.mem.read_word(STACK_ADDRESS + arch.word_size) == 0xBEEF

def test_stack_push(arch_dbg, arch):
    arch_dbg.mem.write_word(STACK_ADDRESS, 0xDEAD)

    arch_dbg.stack.push(0xBEEF)
    assert arch_dbg.sp == STACK_ADDRESS - arch.word_size
    assert arch_dbg.stack[0] == 0xBEEF
    assert arch_dbg.stack[1] == 0xDEAD

def test_stack_pop(arch_dbg, arch):
    arch_dbg.mem.write_word(STACK_ADDRESS, 0xDEAD)

    assert arch_dbg.stack.pop() == 0xDEAD
    assert arch_dbg.sp == STACK_ADDRESS + arch.word_size

def arm_replacement_func(dbg):
    return dbg.regs.r0 + dbg.regs.r1

def test_replace_func_arm(armthumb_dbg: Debugger, arm_isa, other_arm_isa):
    armthumb_dbg.mem.write_code(CODE_ADDRESS, f"""
        MOV R0, #3
        MOV R1, #4
        BLX 0x{other_arm_isa.address_to_pointer(CODE2_ADDRESS):X}
        MOV R4, R0
        {'nop;'*30}
    """)

    armthumb_dbg.mem.write_code(CODE2_ADDRESS, f"""
        MOV R0, 15
        BX LR
    """, isa=other_arm_isa)

    armthumb_dbg.add_breakpoint(CODE_ADDRESS + 0x20)

    armthumb_dbg.run()
    assert armthumb_dbg.regs.r4 == 15

    armthumb_dbg.replace_function(CODE2_ADDRESS, arm_replacement_func)
    armthumb_dbg.run(address=CODE_ADDRESS, isa=arm_isa)
    assert armthumb_dbg.regs.r4 == 7

def x86_replacement_func(dbg):
    return dbg.stack[1] + dbg.stack[2]

def test_replace_x86_func():
    dbg = get_emulator(ARCH_X86, ARCH_X86.isa)

    dbg.mem.write_code(CODE_ADDRESS, f"""
        push 15
        push 3
        call 0x{FUNC_ADDRESS:X}
        mov ebx, eax
        {'nop;'*30}
    """)

    dbg.mem.write_code(FUNC_ADDRESS, f"""
        mov eax, 10
        ret
    """)

    dbg.add_breakpoint(CODE_ADDRESS + 0x20)

    dbg.run()
    assert dbg.regs.ebx == 10

    dbg.replace_function(FUNC_ADDRESS, x86_replacement_func)
    dbg.run(address=CODE_ADDRESS)
    assert dbg.regs.ebx == 18


@pytest.mark.parametrize(['mnem', 'atype'], [('LDR', 'R'), ('STR', 'W')])
def test_watchpoint(dbg, mnem, atype):
    dbg.mem.write_code(CODE_ADDRESS, f"""
        LDR R0, =0x{DATA_ADDRESS:X}
        NOP
        NOP
        {mnem} R1, [R0]
        NOP
        NOP
        NOP
    """)
    watch_pc = CODE_ADDRESS + 3*4
    end_pc = CODE_ADDRESS + 5*4

    dbg.add_watchpoint(DATA_ADDRESS, type=AccessType[atype])
    dbg.add_breakpoint(end_pc)

    for _ in range(3):
        dbg.run()
        assert dbg.pc == watch_pc
        dbg.run()
        assert dbg.pc == end_pc
        dbg.jump(CODE_ADDRESS)