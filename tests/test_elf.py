from pathlib import Path

import pytest

from megastone import FORMAT_ELF, ARCH_MIPS, FORMAT_AUTO, AccessType, Access, MemoryAccessError, Emulator, MegastoneWarning


PATH = Path(__file__).parent / 'files/mips_test'

MAGIC = 0xDEADBEEF


@pytest.fixture
def seg_elf():
    return FORMAT_ELF.parse_file(PATH, use_segments=True)

@pytest.fixture
def sec_elf():
    return FORMAT_ELF.parse_file(PATH)

@pytest.fixture(params=[True, False])
def elf(request):
    return FORMAT_ELF.parse_file(PATH, use_segments=request.param)

@pytest.fixture
def magic_address(elf):
    return elf.symbols['start_data']

@pytest.fixture
def elf_data():
    return PATH.read_bytes()

def test_auto():
    file = FORMAT_AUTO.parse_file(PATH)
    assert file.format is FORMAT_ELF

def test_arch(seg_elf):
    assert seg_elf.arch is ARCH_MIPS

def test_symbols(sec_elf):
    assert sec_elf.symbols['__start'] == sec_elf.mem.segments['.text'].address
    assert sec_elf.symbols['start_data'] == sec_elf.mem.segments['.data'].address

def test_entry(seg_elf):
    assert seg_elf.entry == seg_elf.symbols['__start']

def test_bss(sec_elf):
    assert sec_elf.mem.segments['.bss'].size == 0x1000

def test_segs(seg_elf):
    segs = list(seg_elf.mem.segments)

    assert len(segs) == 2

    assert segs[0].perms == AccessType.RX
    assert segs[0].address == 0x400000
    assert segs[0].size == 0x00140
    assert len(segs[0].read()) == segs[0].size

    assert segs[1].perms == AccessType.RW
    assert segs[1].address == 0x00410140
    assert segs[1].size == 0x01010
    assert len(segs[1].read()) == segs[1].size
    assert seg_elf.arch.encode_word(0xDEADBEEF) in segs[1].read()

def test_text(sec_elf):
    text = sec_elf.mem.segments['.text']

    assert text.address == 0x00400130
    assert text.size == 0x10
    assert text.perms == AccessType.RX
    assert sec_elf.mem.disassemble_one(text.address).mnemonic == 'add'

def test_data(sec_elf):
    data = sec_elf.mem.segments['.data']

    assert data.perms == AccessType.RW
    assert sec_elf.mem.read_word(data.address) == 0xDEADBEEF

def test_bss(sec_elf):
    bss = sec_elf.mem.segments['.bss']

    assert bss.perms == AccessType.RW
    assert bss.size == 0x1000
    assert bss.read() == bytes(bss.size)

def test_no_patch(elf, elf_data):
    assert elf.build_bytes() == elf_data

def test_patch_magic(elf, elf_data, magic_address):
    magic2 = 0xFAFABABA
    magic_data = elf.arch.encode_word(MAGIC)
    magic2_data = elf.arch.encode_word(magic2)

    elf.mem.write_word(magic_address, magic2)
    assert elf.build_bytes() == elf_data.replace(magic_data, magic2_data)

def test_patch_error(elf):
    address = 0x41014E
    data = b'12345'
    bss_offset = 2

    with pytest.raises(MemoryAccessError) as info:
        elf.mem.write(address, data)
    assert 'ELF' in str(info.value)
    assert info.value.access == Access(AccessType.W, address+bss_offset, len(data)-bss_offset, data[bss_offset:])

def test_emu(seg_elf):
    emu = Emulator.from_execfile(seg_elf)
    assert emu.arch == ARCH_MIPS
    assert emu.pc == seg_elf.symbols['__start']
    assert emu.curr_insn.mnemonic == 'add'

def test_emu_sec(sec_elf):
    return
    with pytest.warns(MegastoneWarning) as records:
        emu = Emulator.from_execfile(sec_elf)
    assert len(records) == 1
    assert '0x400000' in records[0].message.args[0]
    assert ' RX ' in records[0].message.args[0]
    
    assert emu.arch == ARCH_MIPS
    assert emu.pc == sec_elf.symbols['__start']
    assert emu.curr_insn.mnemonic == 'add'