from megastone import Emulator, ARCH_ARM64


emu = Emulator(ARCH_ARM64)
segment = emu.mem.allocate('code', 0x1000)

emu.mem.write_code(segment.address,
"""
    MOV X0, 1
    ADD X0, X0, X0
    ADD X0, X0, X0
    ADD X0, X0, X0
    ADD X0, X0, X0
    ADD X0, X0, X0
    ADD X0, X0, X0
""")

emu.add_breakpoint(segment.address + 0x8)
emu.add_breakpoint(segment.address + 0x10)
emu.trace(lambda e: print(e.curr_insn, e.regs.x0))

emu.jump(segment.address)
print(emu.run())
print(emu.run())