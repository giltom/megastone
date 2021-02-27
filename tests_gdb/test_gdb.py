from pathlib import Path
import subprocess
import time


import pytest

import megastone as ms
import megastone.gdb as msgdb


DIR = Path(__file__).parent
ELF_DIR = DIR / '../tests/files/elfs'
MEGAEMU = DIR / '../megastone/tools/megaemu.py'
PORT = 1337


@pytest.fixture(params=[arch for arch in ms.Architecture.all() if arch.gdb_supported], ids=lambda a: a.name)
def gdb_arch(request):
    return request.param

@pytest.fixture
def exe_path(gdb_arch):
    return ELF_DIR / gdb_arch.name

@pytest.fixture
def exe(exe_path):
    return ms.load_file(exe_path)

@pytest.fixture
def process(exe_path):
    proc = subprocess.Popen(['python3', MEGAEMU, '-p', str(PORT), '-l', 'error', str(exe_path)], stdout=subprocess.DEVNULL)
    try:
        time.sleep(0.1)
        yield proc
    finally:
        retcode = proc.wait()
        if retcode != 0:
            raise ValueError('megaemu crashed')
    
@pytest.fixture
def dbg(process, gdb_arch):
    msgdb.set_endian(gdb_arch.endian)
    msgdb.execute(f'target remote tcp:localhost:{PORT}')
    try:
        yield msgdb.GDBDebugger()
    finally:
        msgdb.execute('detach')

def test_dbg(dbg, gdb_arch, exe):
    assert dbg.arch == gdb_arch
    
    assert dbg.pc == exe.symbols['_start']
    
    values = [0, gdb_arch.word_mask, 0x15, 0xbabafafa]
    for value in values:
        dbg.regs.retval = value
        assert dbg.regs.retval == value

    addr = exe.symbols['magic']
    assert dbg.mem.read_32(addr) == 0xDEADBEEF

    data = b'hihi'
    dbg.mem.write(addr, data)
    assert dbg.mem.read(addr, len(data)) == data

    dbg.step()
    assert dbg.pc == exe.symbols['_start'] + len(gdb_arch.default_isa.assemble('nop'))


    with pytest.raises(ms.MemoryReadError) as info:
        dbg.mem.read(0x123, 5)
    assert info.value.access == ms.Access.read(0x123, 5)

    with pytest.raises(ms.MemoryWriteError) as info:
        dbg.mem.write(0x15, b'hello')
    assert info.value.access == ms.Access.write(0x15, b'hello')