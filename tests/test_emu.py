import pytest
import unicorn

from megastone import Emulator, ARCH_ARM, MemoryAccessError, Access, AccessType, BufferMemory, FORMAT_BINARY, MegastoneWarning


UC_X = unicorn.UC_PROT_EXEC
UC_R = unicorn.UC_PROT_READ
UC_W = unicorn.UC_PROT_WRITE
UC_RW = UC_R | UC_W


@pytest.fixture
def emu():
    return Emulator(ARCH_ARM)

def test_read_error(emu):
    address = 0x80
    size = 0x11

    with pytest.raises(MemoryAccessError) as info:
        emu.mem.read(address, size)
    assert info.value.access == Access.read(address, size)

def test_write_error(emu):
    address = 0x1001
    data = b'3'*3

    with pytest.raises(MemoryAccessError) as info:
        emu.mem.write(address, data)
    assert info.value.access == Access(AccessType.W, address, len(data), data)

def test_alloc_stack(emu: Emulator):
    emu.allocate_stack(0x1000)

    assert emu.sp in emu.mem.segments.stack

    emu.stack[0] = 0xDEAD
    assert emu.stack[0] == 0xDEAD

def test_unaligned(emu: Emulator):
    segment = emu.mem.map(0x1080, 0x80, 'code')
    assert segment.start == 0x1080
    assert segment.size == 0x80

def test_from_mem():
    mem = BufferMemory(ARCH_ARM)
    mem.map(0x1000, 0x1000, 'seg')
    emu = Emulator.from_memory(mem)
    assert emu.mem.segments.seg.address == 0x1000

def test_from_file(arch, isa, nop):
    address = 0x3000
    entry = isa.address_to_pointer(address + 0x10)
    data = nop * 30

    file = FORMAT_BINARY.parse_bytes(data, arch=arch, base=address, entry=entry)

    emu = Emulator.from_execfile(file)

    assert isa.address_to_pointer(emu.pc) == entry
    assert emu.isa == isa
    assert emu.get_curr_insn().mnemonic == 'nop'
    assert emu.mem.read(address, len(data)) == data

def check_map_warning(records, address, perms):
    assert len(records) == 1
    assert hex(address) in records[0].message.args[0].lower()
    assert f' {perms} ' in records[0].message.args[0]

def test_overlap_start(emu: Emulator):
    seg1 = emu.mem.map(0x800, 0x1000, 'seg1', AccessType.R)
    assert seg1.address == 0x800
    assert seg1.read() == bytes(0x1000)

    with pytest.warns(MegastoneWarning) as records:
        seg2 = emu.mem.map(0x1800, 0x1000, 'seg2', AccessType.W)
    check_map_warning(records, 0x1000, 'RW')

    assert seg2.address == 0x1800
    assert seg2.read() == bytes(0x1000)

    assert emu.mem._get_uc_prot(0x0) == UC_R
    assert emu.mem._get_uc_prot(0x1000) == UC_RW

def test_overlap_end(emu: Emulator):
    seg1 = emu.mem.map(0x2800, 0x2000, 'seg1', AccessType.RW)
    assert seg1.address == 0x2800
    assert seg1.read() == bytes(0x2000)

    with pytest.warns(MegastoneWarning) as records:
        seg2 = emu.mem.map(0x1800, 0x1000, 'seg2', AccessType.W)
    check_map_warning(records, 0x2000, 'RW')

    assert seg2.address == 0x1800
    assert seg2.read() == bytes(0x1000)

    assert emu.mem._get_uc_prot(0x2000) == UC_RW
    assert emu.mem._get_uc_prot(0x1000) == UC_W

def test_overlap_full(emu: Emulator):
    seg1 = emu.mem.map(0x1200, 0x200, 'seg1', AccessType.R)
    assert seg1.address == 0x1200
    assert seg1.read() == bytes(0x200)

    with pytest.warns(MegastoneWarning) as records:
        seg2 = emu.mem.map(0x1600, 0x200, 'seg2', AccessType.RW)
    check_map_warning(records, 0x1000, 'RW')

    assert seg2.address == 0x1600
    assert seg2.read() == bytes(0x200)
    
    assert emu.mem._get_uc_prot(0x1000) == UC_RW

def test_overlap_long(emu: Emulator):
    seg1 = emu.mem.map(0x800, 0x2000, 'seg1', AccessType.R) #0x800-0x2800
    seg2 = emu.mem.map(0x4800, 0x2000, 'seg2', AccessType.X) #0x4800-0x6800

    with pytest.warns(MegastoneWarning) as records:
        seg3 = emu.mem.map(0x2800, 0x2000, 'seg3', AccessType.W) #0x2800 - 0x4800
    assert len(records) == 2
    check_map_warning([records[0]], 0x2000, 'RW')
    check_map_warning([records[1]], 0x4000, 'WX')

    assert seg3.address == 0x2800
    assert seg3.read() == bytes(0x2000)

    prots = [UC_R, UC_R, UC_RW, UC_W, UC_W | UC_X, UC_X, UC_X]
    for page, prot in zip(range(0x0, 0x7000, 0x1000), prots):
        assert emu.mem._get_uc_prot(page) == prot

def test_overlap_same(emu: Emulator):
    emu.mem.map(0x200, 0x200, 'seg1', AccessType.X)
    emu.mem.map(0x400, 0x200, 'seg2', AccessType.X)