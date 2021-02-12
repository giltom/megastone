from megastone import Emulator, ARCH_ARM


emu = Emulator(ARCH_ARM)
segment = emu.mem.allocate(0x1000, 'code')

emu.mem.write_code(segment.address,
"""
    MOV R0, 1
    ADD R0, R0
    ADD R0, R0
    ADD R0, R0
""")

emu.trace(lambda e: print(e.get_curr_insn(), e.regs.r0))
emu.run(count=4, address=segment.address)
