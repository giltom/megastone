import pytest


from megastone import Emulator, ARCH_ARM, MemoryAccessError, Access, AccessType, MegastoneWarning, BufferMemory, FORMAT_BINARY


@pytest.fixture
def emu():
    return Emulator(ARCH_ARM)


def test_read_error(emu):
    address = 0x80
    size = 0x11

    with pytest.raises(MemoryAccessError) as info:
        emu.mem.read(address, size)
    assert info.value.access == Access(AccessType.R, address, size)

def test_write_error(emu):
    address = 0x1001
    data = b'3'*3

    with pytest.raises(MemoryAccessError) as info:
        emu.mem.write(address, data)
    assert info.value.access == Access(AccessType.W, address, len(data), data)

def test_alloc_stack(emu: Emulator):
    emu.allocate_stack(0x1000)

    assert emu.mem.segments.stack.contains_address(emu.sp)

    emu.stack[0] = 0xDEAD
    assert emu.stack[0] == 0xDEAD

def test_round(emu: Emulator):
    with pytest.warns(MegastoneWarning):
        segment = emu.mem.map('code', 0x1000, 0x80)
    assert segment.size == Emulator.PAGE_SIZE

def test_from_mem():
    mem = BufferMemory(ARCH_ARM)
    mem.map('seg', 0x1000, 0x1000)
    emu = Emulator.from_memory(mem)
    assert emu.mem.segments.seg.address == 0x1000

def test_from_file(arch, isa, nop):
    address = 0x3000
    entry = isa.address_to_pointer(address + 0x10)
    data = nop * 30

    file = FORMAT_BINARY.parse_bytes(data, arch=arch, base=address, entry=entry)

    with pytest.warns(MegastoneWarning):
        emu = Emulator.from_execfile(file)

    assert isa.address_to_pointer(emu.pc) == entry
    assert emu.isa == isa
    assert emu.curr_insn.mnemonic == 'nop'
    assert emu.mem.read(address, len(data)) == data