from megastone import Emulator, ARCH_X86, HOOK_STOP


emu = Emulator(ARCH_X86)
emu.allocate_stack(0x1000)
start_seg = emu.mem.allocate('code', 0x1000)
func_seg = emu.mem.allocate('func', 0x1000)

emu.mem.write_code(start_seg.address, f"""
    push 1
    push 2
    call 0x{func_seg.address:X}
    {'nop;'*20}
""")

emu.mem.write_code(func_seg.address, f"""
    mov eax, 700
    ret
""")

def func_hook(emu: Emulator):
    print(hex(emu.sp), emu.curr_insn) #since this opcode never runs, the trace func isn't called
    return emu.stack[1] + emu.stack[2]

emu.replace_function(func_seg.address, func_hook)
emu.trace(lambda e: print(hex(e.sp), e.curr_insn))
emu.add_code_hook(HOOK_STOP, start_seg.address + 0x10)

emu.run(address=start_seg.address)
print(emu.regs.eax)