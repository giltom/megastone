from pathlib import Path
import subprocess

import pytest

import megastone as ms


DIR = Path(__file__).parent
BINARY_PATH = DIR / 'files/proc_test'
MAGIC1 = 0xDEADBEEF
MAGIC2 = 0xBABAFAFA


@pytest.fixture
def elf():
    return ms.FORMAT_ELF.parse_file(BINARY_PATH)

@pytest.fixture
def mem():
    proc = subprocess.Popen(BINARY_PATH)
    try:
        with ms.ProcessMemory(proc.pid) as mem:
            yield mem
    finally:
        proc.kill()
        proc.wait()

@pytest.fixture
def address(elf):
    return elf.symbols['values']


def test_elf(elf, address):
    assert elf.mem.read_32(address) == MAGIC1
    assert elf.mem.read_32(address + 4) == MAGIC2

def test_read(mem, address):
    assert mem.read_32(address) == MAGIC1
    assert mem.read_32(address + 4) == MAGIC2

def test_write(mem, address):
    value = 0xCAFEBABE

    mem.write_32(address, value)
    assert mem.read_32(address) == value
    assert mem.read_32(address + 4) == MAGIC2

def test_segments(mem):
    assert '[stack]' in mem.segments
    assert mem.segments['[stack]'].perms == ms.AccessType.RW

    bin_path = str(BINARY_PATH)
    assert bin_path in mem.segments
    assert mem.segments[bin_path].address == 0x400000
    assert mem.segments[bin_path].perms == ms.AccessType.R

def test_read_error(mem):
    with pytest.raises(ms.MemoryAccessError) as info:
        mem.read(0x0, 20)

    assert info.value.access == ms.Access(ms.AccessType.R, 0, 20)

def test_len_segments(mem):
    assert len(mem.segments) == len(mem.segments)

def test_bad_segment(mem):
    assert 'bad' not in mem.segments

def test_seg_eq(mem):
    assert mem.segments['[stack]'] == mem.segments['[stack]']