from pathlib import Path

import pytest

from megastone import FORMAT_IHEX, FORMAT_AUTO, ARCH_ARM64


SEG_SIZE = 0x50


PATH = Path(__file__).parent / 'files/test.hex'


@pytest.fixture
def exe():
    return FORMAT_IHEX.parse_file(PATH, arch=ARCH_ARM64)

@pytest.fixture
def ihex_data():
    return PATH.read_bytes()

def test_auto_file():
    assert FORMAT_AUTO.parse_file(PATH, arch=ARCH_ARM64).format == FORMAT_IHEX

def test_entry():
    assert FORMAT_AUTO.parse_file(PATH, arch=ARCH_ARM64, entry=0x800).entry == 0x800

def test_arch(exe):
    assert exe.arch is ARCH_ARM64

def test_entry(exe):
    assert exe.entry == 0x100

def test_segs(exe):
    segs = list(exe.mem.segments)
    assert len(segs) == 2

    assert segs[0].start == 0x100
    assert segs[0].read() == SEG_SIZE*b'A'

    assert segs[1].start == 0x200
    assert segs[1].read() == SEG_SIZE*b'B'

def test_build(exe, ihex_data):
    assert exe.build_bytes().strip() == ihex_data.strip()

def test_patch(exe):
    exe.mem.write(0x100, SEG_SIZE*b'C')
    assert exe.build_bytes().count(b'43') == SEG_SIZE