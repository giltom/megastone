from megastone.debug.errors import CPUError
import pytest

from megastone import Debugger, Emulator, ARCH_ARM, HOOK_STOP, HOOK_STOP_ONCE, StopType, HookFunc, AccessType, InvalidInsnError, MemFaultError, MemoryAccessError, FaultCause


CODE_ADDRESS = 0x1000
CODE_SIZE = 0x1000

CODE2_ADDRESS = 0x2000
DATA_ADDRESS = 0x3000
DATA_SIZE = 0x1000

THUMB_NOP = ARCH_ARM.thumb.assemble('nop')
ARM_NOP = ARCH_ARM.arm.assemble('nop')

def get_emulator(arch, isa):
    emu = Emulator(arch)
    map_code_segment(emu, 'code', CODE_ADDRESS, isa)
    emu.mem.map('data', DATA_ADDRESS, DATA_SIZE, AccessType.RW)
    emu.mem.isa = isa
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
    assert arch_dbg.curr_insn.mnemonic.lower() == 'nop'

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


TEST_ADDRESS = DATA_ADDRESS + 9

@pytest.fixture
def rw_test_dbg(armthumb_dbg):
    assembly = f"""
        LDR R0, =0x{TEST_ADDRESS-1:X}
        LDRB R1, [R0]
        STRB R1, [R0]

        LDR R0, =0x{TEST_ADDRESS:X}
        LDRB R1, [R0]
        STRB R1, [R0]

        LDR R0, =0x{TEST_ADDRESS+1:X}
        LDRB R1, [R0]
        STRB R1, [R0]
    """
    armthumb_dbg.mem.write_code(CODE_ADDRESS, assembly)
    return armthumb_dbg


def test_read_hook(rw_test_dbg: Debugger, counter_hook):
    rw_test_dbg.add_read_hook(counter_hook, TEST_ADDRESS)
    rw_test_dbg.run(9)
    assert counter_hook.count == 1

def test_write_hook(rw_test_dbg: Debugger, counter_hook):
    rw_test_dbg.add_write_hook(counter_hook, TEST_ADDRESS)
    rw_test_dbg.run(9)
    assert counter_hook.count == 1

def test_rw_hook(rw_test_dbg: Debugger, counter_hook):
    rw_test_dbg.add_rw_hook(counter_hook, TEST_ADDRESS)
    rw_test_dbg.run(9)
    assert counter_hook.count == 2

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
    assert info.value.access.type == AccessType.W
    assert info.value.access.address == address
    assert info.value.access.size == 4
    assert info.value.access.value == value
    assert info.value.address == CODE_ADDRESS + 8