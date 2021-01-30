from megastone import Emulator, ARCH_ARM, HOOK_STOP


base = 0x1000
arch = ARCH_ARM
isa = arch.arm
emu = Emulator(arch, isa)

assembly = """
    MOV R0, 1
    ADD R0, R0
    ADD R0, R0
    ADD R0, R0
"""
code = isa.assemble(assembly, base)
emu.mem.load('seg1', base, code)
emu.pc = base

print(hex(emu.regs.cpsr))
print(emu.pc)

def func(emu: Emulator):
    print('Hello world', hex(emu.pc))

emu.add_code_hook(0x1004, func)

emu.step()
emu.step()
emu.step()
emu.step()