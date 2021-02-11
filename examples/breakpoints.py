from megastone import Emulator, ARCH_ARM64, HOOK_STOP_ONCE


emu = Emulator(ARCH_ARM64)
segment = emu.mem.allocate('code', 0x1000)

emu.mem.write_code(segment.address,
"""
start:
    MOV X0, 0
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    ADD X0, X0, 1
    B start
""")

emu.add_breakpoint(segment.address + 0x8)
emu.add_code_hook(HOOK_STOP_ONCE, segment.address+0x10)
emu.add_breakpoint(segment.address + 0x18)
emu.trace(lambda e: print(e.get_curr_insn(), e.regs.x0))

emu.jump(segment.address)
for _ in range(5):
    print(emu.run())