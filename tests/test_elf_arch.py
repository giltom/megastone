from pathlib import Path

import pytest

import megastone as ms


ELF_ARCHES = [arch for arch in ms.Architecture.all() if arch.elf_supported]

ELF_DIR = Path(__file__).parent / 'files' / 'elfs'


@pytest.fixture(params=ELF_ARCHES, ids=lambda a: a.name)
def elf_arch(request):
    yield request.param

@pytest.fixture
def elf(elf_arch):
    return ms.load_file(ELF_DIR / elf_arch.name)

def test_loading(elf_arch, elf: ms.ExecFile):
    assert elf.arch is elf_arch
    assert elf.entry == elf.symbols['_start']
    opcode = str(elf.mem.disassemble_one(elf.entry))
    assert opcode == 'nop' or opcode == 'mov r0, r0'
    assert elf.mem.read_32(elf.symbols['magic']) == 0xDEADBEEF
    assert elf.arch.endian.encode_int(0xDEADBEEF, 4) in elf.segments['.data'].read()

def test_unsupported():
    with pytest.raises(ms.UnsupportedError):
        with (ELF_DIR / 'ppc').open('rb') as fileobj:
            ms.load_file(fileobj, format=ms.FORMAT_ELF)