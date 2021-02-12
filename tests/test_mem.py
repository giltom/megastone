import pytest
import io


from megastone import BufferMemory, ARCH_ARM, SegmentMemory, Memory, ISA_X86, MemoryAccessError, AccessType, ARCH_X86, MegastoneError, MappableMemory, Access

from .conftest import TEMP_FILE_DATA


SEG_NAME = 'seg'
SEG_ADDRESS = 0x1000
SEG_SIZE = len(TEMP_FILE_DATA)
INITIAL_DATA = b'A' * SEG_SIZE


@pytest.fixture
def arch_mem(arch, isa):
    mem = BufferMemory(arch)
    mem.default_isa = isa
    mem.load(SEG_NAME, SEG_ADDRESS, INITIAL_DATA)
    return mem

@pytest.fixture
def mem():
    mem = BufferMemory(ARCH_ARM)
    mem.load(SEG_NAME, SEG_ADDRESS, INITIAL_DATA)
    return mem

@pytest.fixture
def fileobj(mem):
    return mem.segments.seg.create_fileobj()

def test_read(mem):
    assert mem.segments.seg.read() == INITIAL_DATA

def test_write(mem):
    data = b'hello world'

    mem.segments.seg.write(data)
    assert mem.read(SEG_ADDRESS, len(data)) == data

def test_disasm_one(arch_mem):
    arch_mem.write_code(SEG_ADDRESS, 'nop')
    assert arch_mem.disassemble_one(SEG_ADDRESS).mnemonic.lower() == 'nop'

def test_disasm(arch_mem: Memory):
    num_nops = 3

    arch_mem.write_code(SEG_ADDRESS, 'nop;' * num_nops)
    insns = list(arch_mem.disassemble(SEG_ADDRESS, num_nops))
    assert len(insns) == num_nops
    for insn in insns:
        assert insn.mnemonic.lower() == 'nop'

def test_force_isa(mem):
    isa = ISA_X86

    mem.write_code(SEG_ADDRESS, 'nop', isa=isa)
    assert mem.disassemble_one(SEG_ADDRESS, isa=isa).mnemonic.lower() == 'nop'

def test_word(arch, arch_mem):
    word = 0xDEADBEEFBABAFAFA & arch.word_mask

    arch_mem.write_word(SEG_ADDRESS, word)
    assert arch_mem.read_word(SEG_ADDRESS) == word

def test_string(mem):
    string = 'hello world'

    mem.write_cstring(SEG_ADDRESS, string)
    assert mem.read_cstring(SEG_ADDRESS) == string

def test_cstring_max(mem):
    string = 'hello world'
    max = 5

    mem.write_cstring(SEG_ADDRESS, string)
    assert mem.read_cstring(SEG_ADDRESS, max) == string[:max]

def test_search(mem: SegmentMemory):
    search_addr = SEG_ADDRESS + 0x20
    magic = b'magic'

    mem.write(SEG_ADDRESS+1, magic)
    mem.write(search_addr, magic)
    assert mem.search_all(magic, alignment=2) == search_addr

def test_search_code(mem: SegmentMemory):
    search_addr = SEG_ADDRESS + 0x10
    mem.write_code(search_addr, 'nop')
    assert mem.search_code('nop') == search_addr

def test_bad_search(mem):
    assert mem.search_all(b'magic') is None

def test_get_item(mem):
    assert mem[SEG_ADDRESS] == ord('A')

def test_set_item(mem):
    value = 0x55

    mem[SEG_ADDRESS] = value
    assert mem[SEG_ADDRESS] == value

def test_slice(mem):
    data = b'hello'

    mem[SEG_ADDRESS : SEG_ADDRESS + len(data)] = data
    assert mem[SEG_ADDRESS : SEG_ADDRESS + len(data)] == data

def test_allocate(mem):
    data = b'test'

    seg = mem.allocate('seg2', SEG_SIZE)
    seg.write(data)
    assert mem.read(seg.address, len(data)) == data

def test_segments_len(mem):
    assert len(mem.segments) == 1

def test_segments_iter(mem):
    assert list(mem.segments) == [mem.segments.seg]

def test_unmapped(mem):
    address = 0x5
    size = 0x3

    with pytest.raises(MemoryAccessError) as info:
        mem.read(address, size)
    assert info.value.access.type == AccessType.R
    assert info.value.access.address == address
    assert info.value.access.size == 0x3
    assert info.value.access.value is None
    assert repr(info.value.access) == f'Access.read(0x{address:X}, 0x{size:X})'


def test_add_existing(mem):
    with pytest.raises(MegastoneError):
        mem.map('seg', 0x1000, 0x1000)


def test_add_overlap(mem):
    with pytest.raises(MegastoneError):
        mem.map('seg2', SEG_ADDRESS-0x10, 0x20)


def test_load_mem(mem):
    addr2 = 0x200
    data = b'hello'

    other = BufferMemory(ARCH_X86)
    other.map('seg2', addr2, 0x100)
    other.segments.seg2.write(data)
    mem.load_memory(other)
    assert mem.read(mem.segments.seg2.address, len(data)) == data


def test_adjacent(mem):
    mem.map('seg2', SEG_ADDRESS+SEG_SIZE, 0x20)
    assert mem.segments.seg.adjacent(mem.segments.seg2)
    assert mem.segments.seg2.adjacent(mem.segments.seg)

def test_seg(mem):
    assert mem.segments.seg.address == SEG_ADDRESS
    assert mem.segments.seg.size == SEG_SIZE
    assert mem.segments.seg.end == SEG_ADDRESS + SEG_SIZE

def test_seg_repr(mem):
    assert hex(SEG_ADDRESS) in repr(mem.segments.seg)

def test_fileobj(fileobj):
    assert fileobj.read() == INITIAL_DATA
    assert fileobj.get_data() == INITIAL_DATA

def test_fileobj_write(mem, fileobj):
    data = b'hello'

    fileobj.write(data)
    assert fileobj.tell() == len(data)
    assert mem.read(SEG_ADDRESS, len(data)) == data

def test_truncate(mem, fileobj):
    data = b'test'

    fileobj.write(b'a')
    fileobj.truncate()

    fileobj.seek(0)
    fileobj.write(data)
    assert mem.read(SEG_ADDRESS, len(data)) == data

def test_truncate_size(mem, fileobj):
    fileobj.truncate(7)
    assert fileobj.read() == mem.read(SEG_ADDRESS, 7)

def test_seek_end(fileobj):
    fileobj.seek(1, io.SEEK_END)
    assert fileobj.read() == b''

def test_seekable(fileobj):
    assert fileobj.seekable()

def test_seek_curr(fileobj):
    fileobj.read(1)
    fileobj.seek(3, io.SEEK_CUR)
    assert fileobj.tell() == 4

def test_write_fileobj(mem):
    data = b'deadbeef'

    fileobj = io.BytesIO(data)
    mem.write_fileobj(SEG_ADDRESS, fileobj)
    assert mem.read(SEG_ADDRESS, len(data)) == data

def test_dump_to_fileobj(mem: Memory):
    fileobj = io.BytesIO()
    mem.segments.seg.dump_to_fileobj(fileobj)
    assert fileobj.getvalue() == INITIAL_DATA

def test_write_file(mem: Memory, temp_file):
    mem.segments.seg.write_file(temp_file.name)
    assert mem.segments.seg.read() == TEMP_FILE_DATA

def test_dump(mem: Memory, temp_file):
    mem.segments.seg.dump_to_file(temp_file.name)
    assert temp_file.read() == INITIAL_DATA

def test_load_file(mem: MappableMemory, temp_file):
    mem.load_file('seg2', 0x2000, temp_file.name)
    assert mem.segments.seg2.read() == TEMP_FILE_DATA

def test_stream(mem: Memory):
    size = 5
    fileobj = mem.create_fileobj(SEG_ADDRESS)
    assert fileobj.read(size) == INITIAL_DATA[:size]

    offset = 2
    fileobj.seek(offset)
    assert fileobj.tell() == offset

def test_contains(mem):
    assert SEG_NAME in mem.segments
    assert 'asdfasdf' not in mem.segments

def test_rw_adjacent(mem: MappableMemory):
    data1 = b'data1'
    data2 = b'data2'
    data = data1 + data2
    address = SEG_ADDRESS + SEG_SIZE - len(data1)

    mem.map('seg2', SEG_ADDRESS + SEG_SIZE, 0x1000)

    mem.write(address, data1 + data2)
    assert mem.read(address, len(data1)) == data1
    assert mem.read(SEG_ADDRESS + SEG_SIZE, len(data2)) == data2
    assert mem.read(address, len(data)) == data

def test_context(mem):
    with mem as other_mem:
        assert mem is other_mem

def test_access_str(mem):
    assert str(AccessType.RW) == 'RW'

def test_seg_contains(mem):
    assert SEG_ADDRESS in mem.segments.seg
    assert SEG_ADDRESS+SEG_SIZE not in mem.segments.seg
    assert 'hello' not in mem.segments.seg

def test_seg_addresses(mem):
    assert list(mem.segments.seg.addresses(5)) == list(range(SEG_ADDRESS, SEG_ADDRESS + SEG_SIZE, 5))

@pytest.mark.parametrize(['expr'], [
    ['Access.read(0x3, 0x8)'],
    ["Access.write(0x3, b'hello')"],
    ['Access.execute(0x0)'],
    ['Access(AccessType.RW, 0x3, 0x5)'],
    ["Access(AccessType.WX, 0x3, 0x1, b'A')"]
])
def test_access_repr(expr):
    assert repr(eval(expr, globals())) == expr