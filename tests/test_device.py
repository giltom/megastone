from megastone.device import DeviceFaultError
import pytest

import megastone as ms


DEV_ADDR = 0x2400
DEV_SIZE = 0x100
REGDEV_ADDR = 0x2800
CODE_ADDR = 0x1000
SEG_SIZE = 0x1000
READ_CHAR = b'A'
WRITE_CHAR = b'B'


class MyDevice(ms.Device):
    def __init__(self, name: str, address: int, size: int):
        super().__init__(name, address, size)
        self.writes = []

    def read(self, offset: int, size: int) -> bytes:
        return READ_CHAR * size

    def write(self, offset: int, data: bytes):
        self.writes.append((offset, data))


class MyRegDevice(ms.RegisterDevice):
    offsets = {
        0x0: 'reg0',
        0x4: 'reg1',
        0x8: 'reg2'
    }

    def __init__(self, name: str, address: int):
        super().__init__(name, address, 0x20)
        self.reg0 = []
        self.reg1 = []
        self.reg2 = []

    def read_reg0(self):
        return 0xAA

    def write_reg0(self, value):
        self.reg0.append(value)

    def read_reg1(self):
        return 0x12345678

    def write_reg1(self, value):
        self.reg1.append(value)


def init_code(emu, assembly):
    return emu.mem.write_code(CODE_ADDR, assembly)


@pytest.fixture
def dev():
    return MyDevice('MyDevice', DEV_ADDR, DEV_SIZE)


@pytest.fixture
def regdev():
    return MyRegDevice('MyRegDevice', REGDEV_ADDR)


@pytest.fixture
def emu(dev, regdev):
    emu = ms.Emulator(ms.ARCH_ARM)
    emu.mem.map('code', CODE_ADDR, SEG_SIZE)
    emu.jump(CODE_ADDR)
    dev.attach(emu)
    regdev.attach(emu)
    return emu

def test_read(emu):
    init_code(emu, f'LDR R0, =0x{DEV_ADDR:X}; LDRH R0, [R0]')
    emu.run(2)
    assert emu.regs.r0 == 0x4141

def test_write(dev, emu):
    init_code(emu, f"""
        LDR R0, =0x{DEV_ADDR:X}
        LDR R1, =0x42424242
        STR R1, [R0]
        STRH R1, [R0, #10]
        STRB R1, [R0, #4]
    """)

    emu.run(5)
    assert dev.writes == [(0, WRITE_CHAR*4), (10, WRITE_CHAR*2), (4, WRITE_CHAR)]

def test_detach(dev, emu):
    dev.detach()
    init_code(emu, f'LDR R0, =0x{DEV_ADDR:X}; LDRH R0, [R0]')
    emu.run(2)
    assert emu.regs.r0 == 0

def test_reg_read(emu):
    init_code(emu, f'LDR R0, =0x{REGDEV_ADDR:X}; LDR R1, [R0]; LDRH R2, [R0, #4]')
    emu.run(3)
    assert emu.regs.r1 == 0xAA
    assert emu.regs.r2 == 0x5678


def test_reg_write(regdev, emu):
    init_code(emu, f"""
        LDR R0, =0x{REGDEV_ADDR:X}
        LDR R1, =0xAABBCCDD
        STR  R1, [R0, #0]
        STRH R1, [R0, #4]
        STRB R1, [R0, #4]
    """)

    emu.run(5)
    assert regdev.reg0 == [0xAABBCCDD]
    assert regdev.reg1 == [0xCCDD, 0xDD]

def test_reg_name_read(regdev):
    assert regdev.reg_read('reg1') == 0x12345678

def test_reg_name_write(regdev):
    regdev.reg_write('reg0', 0x11)
    assert regdev.reg0 == [0x11]

def test_no_func(emu, regdev):
    init_code(emu, f"""
        LDR R0, =0x{REGDEV_ADDR:X}
        LDR R1, =0xBABAFEFE
        STR  R1, [R0, #8]
        LDR R2, [R0, #8]
    """)
    emu.run(4)
    assert emu.regs.r2 == 0xBABAFEFE
    assert regdev.reg0 == []
    assert regdev.reg1 == []

def test_bad_offset(emu, regdev):
    init_code(emu, f"""
        LDR R0, =0x{REGDEV_ADDR:X}
        STR  R1, [R0, #2]
    """)
    with pytest.raises(DeviceFaultError) as info:
        emu.run(2)
    assert info.value.address == CODE_ADDR + 4
    assert info.value.access == ms.Access(ms.AccessType.W, REGDEV_ADDR+2, 4, bytes(4))
    assert info.value.device == regdev
    assert repr(info.value.access) in repr(info.value)

def test_double_attach(emu, dev):
    with pytest.raises(RuntimeError):
        dev.attach(emu)

def test_double_detach(emu, dev):
    dev.detach()
    with pytest.raises(RuntimeError):
        dev.detach()

def test_existing_map(emu):
    addr = CODE_ADDR+0x200
    dev = MyDevice('mydev2', addr, 0x100)
    dev.attach(emu)
    init_code(emu, f'LDR R0, =0x{addr:X}; STR R0, [R0]')
    emu.run(2)

    assert dev.writes == [(0, addr.to_bytes(4, 'little'))]