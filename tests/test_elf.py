from pathlib import Path

import pytest

from megastone import FORMAT_ELF, ARCH_MIPS, FORMAT_AUTO, AccessType


PATH = Path(__file__).parent / 'files/mips_test.elf'


@pytest.fixture
def seg_elf():
    return FORMAT_ELF.parse_file(PATH, use_segments=True)

@pytest.fixture
def sec_elf():
    return FORMAT_ELF.parse_file(PATH)

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
    assert segs[0].size == 0x1000

    assert segs[1].perms == AccessType.RW
    assert segs[1].address == 0x410000
    assert segs[1].size == 0x2000
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