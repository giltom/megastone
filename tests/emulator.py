from megastone import Emulator, ARCH_ARM, HOOK_STOP


base = 0x1000
arch = ARCH_ARM
isa = arch.thumb
emu = Emulator(arch)

assembly = """
    MOV R0, 1
    ADD R0, R0
    ADD R0, R0
    ADD R0, R0
"""
code = isa.assemble(assembly, base)
emu.mem.load('seg1', base, code)

def trace_func(emu: Emulator):
    print(emu.curr_insn, hex(emu.regs.r0))


emu.trace(trace_func)
emu.run(count=4, address=base)
