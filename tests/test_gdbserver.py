import subprocess
import threading
import logging
import contextlib
import functools
import socket

import pytest

import megastone as ms
from megastone.rsp.stream import SocketStream
from megastone.rsp.connection import RSPConnection


PORT = 1337
GDB_ARCHES = [arch for arch in ms.Architecture.all() if arch.gdb_supported]
CODE_ADDRESS = 0x1000
DATA_ADDRESS = 0x2000
REG_VALUE = 0xDEADBEEF
SP_VALUE = 0x3000
NUM_NOPS = 16
ARCH = ms.ARCH_ARM
ARCH_NOP = ARCH.default_isa.assemble('nop')
GDB_COMMAND = ['gdb-multiarch', '-n', '-batch']
INIT_COMMANDS = [
    'set remotetimeout 1',
    'set tcp connect-timeout 1',
    f'target remote :{PORT}'
]


def create_emu(arch):
    emu = ms.Emulator(arch)

    emu.mem.map(CODE_ADDRESS, 0x1000, 'code')
    emu.mem.map(DATA_ADDRESS, 0x1000, 'data')
    nop = arch.default_isa.assemble('nop')
    emu.mem.write(CODE_ADDRESS, nop*NUM_NOPS)
    
    emu.regs.retval = REG_VALUE
    emu.sp = SP_VALUE
    emu.jump(CODE_ADDRESS)

    return emu

@contextlib.contextmanager
def disable_logging():
    logging.disable()
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)

@contextlib.contextmanager
def server_thread(server):
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        yield thread
    finally:
        server.stop()
        thread.join()

def reduce_delay(monkeypatch):
    monkeypatch.setattr(ms.rsp.server, 'STOP_POLL_TIME', 0.01)

@contextlib.contextmanager
def create_connection():
    with socket.create_connection(('localhost', PORT)) as sock:
        yield RSPConnection(SocketStream(sock))


@pytest.fixture(params=GDB_ARCHES, ids=[arch.name for arch in GDB_ARCHES])
def gdb_arch(request):
    return request.param

@pytest.fixture
def arch_emu(gdb_arch):
    return create_emu(gdb_arch)

@pytest.fixture
def emu():
    return create_emu(ARCH)
    
@pytest.fixture
def arch_server(arch_emu, monkeypatch):
    reduce_delay(monkeypatch)
    with disable_logging():
        yield ms.GDBServer(arch_emu, port=PORT)

@pytest.fixture
def server(emu, monkeypatch):
    reduce_delay(monkeypatch)
    with disable_logging():
        yield ms.GDBServer(emu, port=PORT)

@pytest.fixture
def arch_thread(arch_server):
    with server_thread(arch_server) as thread:
        yield thread

@pytest.fixture
def thread(server):
    with server_thread(server) as thread:
        yield thread

@pytest.fixture
def conn(server, thread):
    server._listening.wait()
    with create_connection() as conn:
        yield conn


@functools.lru_cache
def gdb_installed():
    try:
        subprocess.run(GDB_COMMAND, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return True

def run_gdb(arch, *commands):
    if not gdb_installed():
        pytest.skip('gdb-multiarch is not installed')

    args = list(GDB_COMMAND)
    all_commands = [f'set endian {arch.endian.name.lower()}'] + INIT_COMMANDS + list(commands)
    for command in all_commands:
        args += ['-ex', command]
    result = subprocess.run(args, capture_output=True, check=True, text=True)
    return result.stdout


def test_basic(gdb_arch, arch_server):
    assert arch_server.dbg.arch == gdb_arch

def test_unsupported():
    emu = ms.Emulator(ms.ARCH_X86_16)
    with pytest.raises(ms.UnsupportedError):
        ms.GDBServer(emu)

def test_gdb_binary(gdb_arch, arch_thread):
    pc_name = gdb_arch.pc_reg.name
    sp_name = gdb_arch.sp_reg.name
    retval_name = gdb_arch.retval_reg.name
    new_value = 0xBABAFAFA
    reg_values = [CODE_ADDRESS, SP_VALUE, REG_VALUE, new_value]
    

    output = run_gdb(gdb_arch,
        'show arch',
        f'info reg {pc_name} {sp_name} {retval_name}',
        f'x/i 0x{CODE_ADDRESS:X}',
        f'set ${retval_name} = 0x{new_value:X}',
        f'info reg {retval_name}'
    )
    
    assert gdb_arch.gdb_name in output
    for value in reg_values:
        assert hex(value) in output
    assert f'0x{CODE_ADDRESS:x}:\tnop' in output


def test_stop_before_connect(server, thread):
    server.stop()
    thread.join()
    assert server.stop_reason == ms.ServerStopReason.STOPPED

def test_stop_after_connect(server, thread, conn):
    server.stop()
    thread.join()
    assert server.stop_reason == ms.ServerStopReason.STOPPED

def test_disconnect(thread, server, conn):
    conn.close()
    thread.join()
    assert server.stop_reason is ms.ServerStopReason.DETACHED

def test_kill(thread, server, conn):
    conn.send_packet(b'k')
    thread.join()
    assert server.stop_reason is ms.ServerStopReason.KILLED

def test_persistent(server):
    thread = threading.Thread(target=server.run, kwargs=dict(persistent=True), daemon=True)
    thread.start()
    server._listening.wait()

    for _ in range(2):
        with create_connection() as conn:
            conn.send_packet(b'?')
            assert conn.receive_packet(timeout=1) == b'T05'

    with create_connection() as conn:
        conn.send_packet(b'k')
    thread.join()
    assert server.stop_reason is ms.ServerStopReason.KILLED

def test_bad_mem_read(server):
    assert server._handle_command(b'm4000,1').startswith(b'E')

def test_mem_write(emu, server):
    assert server._handle_command(b'M1000,4:aabbccdd') == b'OK'
    assert emu.mem.read(0x1000, 4).hex() == 'aabbccdd'

def test_bad_mem_write(server):
    assert server._handle_command(b'M0,1:DD').startswith(b'E')


@pytest.mark.parametrize(['cmd'], [[b'S'], [b's'], [b'S05'], [f'S05;{CODE_ADDRESS:x}'.encode()], [f's{CODE_ADDRESS:x}'.encode()]])
def test_step_signal(cmd, emu, server):
    assert server._handle_command(cmd) == b'T05'
    assert emu.pc == CODE_ADDRESS + len(ARCH_NOP)


def test_breakpoint(emu, server):
    address1 = CODE_ADDRESS + 3 * len(ARCH_NOP)
    address2 = CODE_ADDRESS + 6 * len(ARCH_NOP)
    break_reply = b'T05hwbreak:;'
    assert server._handle_command(f'Z0,{address1:x},1'.encode()) == b'OK'
    assert server._handle_command(f'Z1,{address2:x},0'.encode()) == b'OK'

    assert server._handle_command(b'c') == break_reply
    assert emu.pc == address1

    assert server._handle_command(f'c{CODE_ADDRESS:x}'.encode()) == break_reply
    assert emu.pc == address1

    assert server._handle_command(f'z0,{address1:x},1'.encode()) == b'OK'
    assert server._handle_command(f'C05;{CODE_ADDRESS:x}'.encode()) == break_reply
    assert emu.pc == address2 


@pytest.mark.parametrize(['mnem', 'wp_type', 'reply_type'], [
    ['STR', '2', 'watch'],
    ['LDR', '3', 'rwatch'],
    ['STR', '4', 'awatch'],
    ['LDR', '4', 'awatch']
])
def test_watchpoint(emu, server, mnem, wp_type, reply_type):
    emu.mem.write_code(CODE_ADDRESS, f"""
        LDR R0, =0x{DATA_ADDRESS:X}
        {mnem} R1, [R0]
    """)

    assert server._handle_command(f'Z{wp_type},{DATA_ADDRESS:x},4'.encode()) == b'OK'
    assert server._handle_command(b'c') == f'T05{reply_type}:{DATA_ADDRESS:X};'.encode()
    assert emu.pc == CODE_ADDRESS + 4


def test_illegal_insn(emu, server):
    address = CODE_ADDRESS + 4
    emu.mem.write(address, b'\xFF\xFF\xFF\xFF')

    assert server._handle_command(b'c') == b'T04'
    assert emu.pc == address


def test_mem_fault(emu, server):
    emu.mem.write_code(CODE_ADDRESS, 'MOV R0, #0; LDR R0, [R0]')
    assert server._handle_command(b'c') == b'T0B'
    assert emu.pc == CODE_ADDRESS + 4


def test_exception(emu, server):
    address = CODE_ADDRESS + 12
    emu.mem.write_code(address, 'SVC #0')

    assert server._handle_command(b'c') == b'T06'


def test_monitor(server):
    assert server._handle_command(b'qRcmd,' + b'megastone'.hex().encode()).lower() == b'true\n'.hex().encode()

def test_help(server):
    assert 'Megastone monitor commands' in server._handle_monitor_command_string('')

def test_bad_cmd(server):
    assert 'Unknown' in server._handle_monitor_command_string('badbad')

def test_segments(emu, server):
    output = server._handle_monitor_command_string('seg')
    for seg in emu.mem.segments:
        assert seg.name in output

def test_info(server):
    assert ARCH.name in server._handle_monitor_command_string('info')

def test_error(emu, server):
    assert server._handle_monitor_command_string('error') == 'No CPU error occurred.'

    emu.mem.write_code(CODE_ADDRESS, 'LDR R0, [R0]')
    assert server._handle_command(b's') == b'T0B'
    assert 'Memory fault' in server._handle_monitor_command_string('error')