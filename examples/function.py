import megastone as ms


isa = ms.ISA_ARM
emu = ms.Emulator(ms.ARCH_ARM)
seg = emu.mem.allocate(0x1000)
emu.mem.write_code(seg.address, """
    PUSH {LR}
    ADD R0, R1
    ADD R0, R2
    POP {PC}
""", isa)

emu.allocate_stack()
emu.regs.set(r0=3, r1=5, r2=1)
print(emu.run_function(seg.address, isa=isa))
print(emu.run_function(seg.address, isa=isa))