import megastone as ms


BASE = 0x1000
ARCH = ms.ARCH_ARM
RO_ADDR = 0x2000


def trace_func(emu: ms.Emulator):
    try:
        print(emu.curr_insn)
    except ValueError:
        pass


def test_code(code):
    emu = ms.Emulator(ARCH)
    data = ARCH.assemble(code, BASE)
    emu.mem.load('seg', BASE, data)
    emu.mem.map('rodata', RO_ADDR, ms.Emulator.PAGE_SIZE, ms.Permissions.R)
    emu.add_code_hook(ms.HOOK_STOP, BASE + len(data))
    emu.trace(trace_func)

    emu.run(address=BASE)


ms.disable_warnings()

print(1)
test_code('MOV R0, 1; ADD R0, R0; ADD R0, R0; ADD R0, R0')

print(2)
test_code('MOV R0, 0; LDR R0, [R0]')

print(3)
test_code('MOV R0, 0; STR R0, [R0]')

print(4)
test_code('MOV R0, 0; BX R0')

print(5)
test_code('LDR R0, =0x2000; LDR R0, [R0]')

print(6)
test_code('LDR R0, =0x2000; STR R0, [R0]')

print(7)
test_code('LDR R0, =0x1002; BX R0')
