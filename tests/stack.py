from megastone import Emulator, ARCH_X86, HOOK_STOP
import monkeyhex

emu = Emulator(ARCH_X86)
start_seg = emu.mem.allocate('code', 0x1000)
func_seg = emu.mem.allocate('func', 0x1000)
stack_seg = emu.mem.allocate('stack', 0x1000)
emu.sp = stack_seg.end - 4

emu.mem.write_code(start_seg.address, f"""
    push 1
    push 2
    call 0x{func_seg.address:X}
    {'nop;'*20}
""")

emu.mem.write_code(func_seg.address, f"""
    nop
    ret
""")

def func_hook(emu: Emulator):
    print('SP:', hex(emu.sp))
    print('stack dump:', emu.stack[:3])
    emu.return_from_function(emu.stack[1] + emu.stack[2])

emu.trace(lambda e: print(e.curr_insn))
emu.add_code_hook(func_hook, func_seg.address)
emu.add_code_hook(HOOK_STOP, start_seg.address + 0x10)
emu.run(address=start_seg.address)
print(emu.regs.eax)