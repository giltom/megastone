import pytest

import megastone as ms


FAKE_CHUNK_SIZE = 0x20
SEG_ADDRESS = 0x2000
SEG_SIZE = FAKE_CHUNK_SIZE * 2 + 1


@pytest.fixture
def num_nops(nop):
    return SEG_SIZE // len(nop)

def dummy(*args):
    return None

@pytest.fixture(params=[True, False], ids=lambda b: 'no_max_size' if b else 'max_size')
def mem(request, monkeypatch, arch, isa, nop, num_nops):
    mem = ms.BufferMemory(arch)
    mem.default_isa = isa
    seg = mem.map(SEG_ADDRESS, SEG_SIZE, 'seg')
    seg.write(nop * num_nops)

    monkeypatch.setattr(mem, 'DISASSEMBLY_CHUNK_SIZE', FAKE_CHUNK_SIZE)
    if request.param:
        monkeypatch.setattr(mem, '_get_max_read_size', dummy)

    return mem

@pytest.fixture(params=[None, 3, FAKE_CHUNK_SIZE + 3, 0x30000])
def count(request):
    return request.param

@pytest.fixture
def real_count(count, num_nops):
    if count is None or count > num_nops:
        return num_nops
    return count

@pytest.fixture
def disassembly(mem, count):
    return list(mem.disassemble(SEG_ADDRESS, max_num=count))

def test_insns(disassembly, nop, real_count):
    assert len(disassembly) == real_count
    for i, insn in enumerate(disassembly):
        assert insn.address == SEG_ADDRESS + i * len(nop)
        assert insn.mnemonic == 'nop'

def test_invalid(arch, mem, nop):
    if isinstance(arch, ms.MIPS64Architecture):
        return

    length = 2
    mem.write(SEG_ADDRESS + length * len(nop), b'\xFF\xFF\xFF\xFF')

    assert len(list(mem.disassemble(SEG_ADDRESS))) == 2
    assert len(list(mem.disassemble(SEG_ADDRESS, max_num=3))) == 2

def test_disasm_seg(mem, num_nops):
    assert len(list(mem.disassemble(mem.segments.seg.address))) == num_nops

def test_switch_isa(mem, isa):
    if isa is not ms.ISA_THUMB:
        return

    mem.default_isa = ms.ISA_ARM
    assert mem.disassemble_one(SEG_ADDRESS).mnemonic != 'nop'
    assert mem.disassemble_one(SEG_ADDRESS, isa=ms.ISA_THUMB).mnemonic == 'nop'

@pytest.mark.parametrize(argnames=['num_insns'], argvalues=[[0], [3]])
def test_error(mem, arch, nop, num_insns):
    if isinstance(arch, ms.MIPS64Architecture):
        return

    patch_address = SEG_ADDRESS + num_insns * len(nop)
    mem.write(patch_address, b'\xFF\xFF\xFF\xFF')

    with pytest.raises(ms.DisassemblyError) as info:
        mem.disassemble_n(SEG_ADDRESS, 4)
    assert hex(patch_address) in str(info.value).lower()

def test_disasm_bad(mem):
    with pytest.raises(ms.MemoryAccessError) as info:
        mem.disassemble_one(0x20)