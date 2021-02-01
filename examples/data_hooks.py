from megastone import Emulator, ARCH_ARM


emu = Emulator(ARCH_ARM)
code_seg = emu.mem.allocate('code', 0x1000)
data_seg = emu.mem.allocate('data', 0x1000)

data1 = data_seg.address
data2 = data_seg.address + 1
data3 = data_seg.address + 2
data4 = data_seg.address + 4
data5 = data_seg.address + 8


emu.mem.write_code(code_seg.address,
f"""
    LDR R0, ={data1}
    LDRB R1, [R0]
    STRB R1, [R0]

    LDR R0, ={data2}
    LDRB R1, [R0]
    STRB R1, [R0]

    LDR R0, ={data3}
    LDRH R1, [R0]
    STRH R1, [R0]

    LDR R0, ={data4}
    LDR R1, [R0]
    STR R1, [R0]

    LDR R0, ={data5}
    LDR R1, [R0]
    STR R1, [R0]

    LDR R0, ={data1}
    LDR R1, [R0]
    STR R1, [R0]

    LDR R0, ={data4 + 3}
    LDRB R1, [R0]
    STRB R1, [R0]

    LDR R0, ={data4 + 4}
    LDRB R1, [R0]
    STRB R1, [R0]
""")

def data_hook(emu: Emulator):
    print(emu.curr_insn, hex(emu.curr_hook.address), emu.curr_access)

def add_hooks(emu, ptr, size):
    emu.add_read_hook(data_hook, ptr, size)
    emu.add_write_hook(data_hook, ptr, size)

add_hooks(emu, data1, 1)
add_hooks(emu, data2, 1)
add_hooks(emu, data3, 2)
add_hooks(emu, data4, 4)
add_hooks(emu, data5, 4)
emu.run(count=24, address=code_seg.address)