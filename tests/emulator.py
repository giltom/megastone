from megastone import Emulator, ARCH_ARM, ISA_THUMB, HOOK_STOP


emu = Emulator(ARCH_ARM)
emu.mem.map('seg1', 0x1000, 0x1000)
base_address = emu.mem.segments.seg1.address

assembly = """
    MOV R0, 1
    ADD R0, R0
    ADD R0, R0
    ADD R0, R0
"""
code = ISA_THUMB.assemble(assembly, base_address)
emu.mem.write(base_address, code)
emu.add_code_hook(base_address + len(code), HOOK_STOP)

emu.trace(lambda e: print(e.curr_insn, e.regs.r0))
emu.run(address=base_address, isa=ISA_THUMB)
