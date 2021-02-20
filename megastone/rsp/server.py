from megastone.util import round_up
import threading
import logging
import io
import enum
import dataclasses
import abc

from megastone.errors import UnsupportedError
from megastone.mem import SegmentMemory, MemoryAccessError
from megastone.debug import Debugger, StopReason, StopType, HookType, CPUError, InvalidInsnError, MemFaultError
from .connection import RSPConnection, Signal, parse_ascii, parse_hex_int, parse_hexint_list, parse_list, encode_hex, parse_hex, ParsingError
from .stream import EndOfStreamError, TCPStreamServer
from .target import load_gdb_regs


logger = logging.getLogger(__name__)


STOP_POLL_TIME = 0.25

HOOK_TYPE_TO_STOP_REASON = {
    HookType.CODE: 'hwbreak',
    HookType.WRITE: 'watch',
    HookType.READ: 'rwatch',
    HookType.ACCESS: 'awatch'
}

ERROR_RESPONSE = b'E01'
OK_RESPONSE = b'OK'

GDB_TYPE_TO_HOOK_TYPE = {
    0: HookType.CODE,
    1: HookType.CODE,
    2: HookType.WRITE,
    3: HookType.READ,
    4: HookType.ACCESS
}


class ServerStopReason(enum.Enum):
    STOPPED = enum.auto()
    KILLED = enum.auto()
    DETACHED = enum.auto()


@dataclasses.dataclass
class _MonitorCommand(abc.ABC):
    name: str
    handler: callable
    help: str


class GDBServer:
    """GDB Server implementation. Exposes a Debugger to external GDB clients."""

    def __init__(self, dbg: Debugger, port=1234, host='localhost'):
        if not dbg.arch.gdb_supported:
            raise UnsupportedError('Architecture doesn\'t support GDB')

        self.dbg = dbg
        self.stop_reason: ServerStopReason = None

        self._regs = load_gdb_regs(dbg.arch)

        self._server = TCPStreamServer(host, port)
        self._stopped = threading.Event()
        self._listening = threading.Event()
        self._cmd_stop_reason: ServerStopReason = None
        
        self._cpu_stop_reason: StopReason = None
        self._stop_exception: CPUError = None

        self._hooks = {} #HookType => address => Hook

        self._handlers = {
            b'?': self._handle_stop_reason,
            b'D': self._handle_detach,
            b'k': self._handle_kill,
            b'qAttached': self._handle_attached,
            b'qSupported': self._handle_supported,
            b'qXfer:features:read:target.xml:': self._handle_read_features,
            b'qXfer:memory-map:read::': self._handle_read_memory_map,
            b'g': self._handle_read_regs,
            b'G': self._handle_write_regs,
            b'm': self._handle_read_mem,
            b'M': self._handle_write_mem,
            b's': self._handle_step,
            b'c': self._handle_continue,
            b'S': self._handle_step_signal,
            b'C': self._handle_continue_signal,
            b'Z': self._handle_add_breakpoint,
            b'z': self._handle_remove_breakpoint,
            b'qRcmd,' : self._handle_monitor_command
        }

        self._monitor_commands = [
            _MonitorCommand('help', self._handle_help, 'Print a list of monitor commands.'),
            _MonitorCommand('megastone', self._handle_megastone, 'Check whether the server is a Megastone server.'),
            _MonitorCommand('segments', self._handle_segments, 'Print the list of Segments.')
        ]

    def run(self, *, persistent=False):
        """Run the server. Blocks until the client exists or an error occurs."""
        self._stopped.clear()
        self._server.initialize()
        self._listening.set()
        with self._server:
            self._server.set_timeout(STOP_POLL_TIME)
            while True:
                reason = self._run_once()
                if reason is ServerStopReason.STOPPED or reason is ServerStopReason.KILLED or not persistent:
                    self.stop_reason = reason
                    break
        self._listening.clear()

    def stop(self):
        """
        Stop the server.
        
        This can be safely called from a different thread than the one running the server.
        """
        self._stopped.set()

    def _run_once(self):
        conn = self._wait_for_connection()
        if conn is None:
            return ServerStopReason.STOPPED

        with conn:
            return self._main_loop(conn)

    def _wait_for_connection(self):
        logger.info('waiting for client connection')
        while True:
            try:
                stream = self._server.get_stream()
            except TimeoutError:
                if self._check_stopped():
                    return None
            else:
                return RSPConnection(stream)

    def _main_loop(self, conn: RSPConnection):
        self._cmd_stop_reason = None
        while True:
            try:
                command = conn.receive_packet(timeout=STOP_POLL_TIME)
            except EndOfStreamError:
                logger.warning('client disconnected')
                return ServerStopReason.DETACHED
            if self._check_stopped():
                return ServerStopReason.STOPPED
            if command is None:
                continue

            logger.debug(f'received packet: {command}')
            response = self._handle_command(command)
            
            if response is not None:
                logger.debug(f'sending response: {response}')
                conn.send_packet(response)

            if self._cmd_stop_reason is not None:
                return self._cmd_stop_reason

    def _handle_command(self, command):
        for prefix, handler in self._handlers.items():
            if command.startswith(prefix):
                args = command[len(prefix):]
                return handler(args)
        return b''

    def _check_stopped(self):
        if self._stopped.is_set():
            logger.info('server stopped by thread')
            return True
        return False

    def _handle_stop_reason(self, args):
        return self._get_stop_response()

    def _handle_detach(self, args):
        logger.info('client detached')
        self._cmd_stop_reason = ServerStopReason.DETACHED
        return b'OK'

    def _handle_kill(self, args):
        logger.info('killed by client')
        self._cmd_stop_reason = ServerStopReason.KILLED
        return None

    def _handle_attached(self, args):
        return b'1'

    def _handle_read_regs(self, args):
        return self._encode_regs()

    def _handle_write_regs(self, args):
        self._parse_regs(args)
        return OK_RESPONSE

    def _handle_read_mem(self, args):
        address, size = parse_hexint_list(args, 2)
        try:
            data = self.dbg.mem.read(address, size)
        except MemoryAccessError as e:
            logger.error(str(e))
            return ERROR_RESPONSE
        return encode_hex(data)

    def _handle_write_mem(self, args):
        addresses, hex_data = parse_list(args, 2, b':')
        address, _ = parse_hexint_list(addresses, 2)
        data = parse_hex(hex_data)
        logger.info(f'Write memory: 0x{address:X} +0x{len(data):X}')
        try:
            self.dbg.mem.write(address, data)
        except MemoryAccessError as e:
            logger.error(str(e))
            return ERROR_RESPONSE
        return OK_RESPONSE

    def _handle_continue(self, args):
        return self._handle_run(args, None)

    def _handle_step(self, args):
        return self._handle_run(args, 1)

    def _handle_add_breakpoint(self, args):
        type, address, size = self._parse_hook(args)
        logger.debug(f'adding hook: {type} 0x{address:X} +0x{size:X}')
        hook = self.dbg.add_breakpoint(address, size, type)
        self._add_hook(hook)
        return OK_RESPONSE

    def _handle_remove_breakpoint(self, args):
        type, address, _ = self._parse_hook(args)
        logger.debug(f'remove hook: {type} 0x{address:X}')
        hook = self._pop_hook(type, address)
        self.dbg.remove_hook(hook)
        return OK_RESPONSE

    def _handle_continue_signal(self, args):
        return self._handle_run_signal(args, None)

    def _handle_step_signal(self, args):
        return self._handle_run_signal(args, 1)

    def _handle_run_signal(self, args, count):
        _, _, address = args.partition(b';')
        return self._handle_run(address, count)

    def _handle_run(self, args, count):
        if len(args) == 0:
            address = None
        else:
            address = parse_hex_int(args)

        self._cpu_stop_reason = None
        self._stop_exception = None
        logger.debug(f'run: address={address}, count={count}')
        try:
            self._cpu_stop_reason = self.dbg.run(count=count, address=address)
        except CPUError as e:
            self._stop_exception = e
            logger.info(f'stopped: {e}')
        else:
            logger.debug(f'stopped: {self._cpu_stop_reason.type.name}')
        
        return self._get_stop_response()

    def _handle_supported(self, args):
        return b'swbreak+;hwbreak+;qXfer:features:read+;qXfer:memory-map:read+;multiprocess-'

    def _handle_read_features(self, args):
        features = f'<target version="1.0"><architecture>{self.dbg.arch.gdb_name}</architecture></target>'
        file = io.BytesIO(features.encode())
        return self._handle_xfer(file, args)

    def _handle_read_memory_map(self, args):
        file = io.BytesIO()
        if isinstance(self.dbg.mem, SegmentMemory):
            self._build_memory_map(file)
        return self._handle_xfer(file, args)

    def _build_memory_map(self, fileobj):
        assert isinstance(self.dbg.mem, SegmentMemory)

        fileobj.write(b'<memory-map>')
        for segment in self.dbg.mem.segments:
            fileobj.write(f'<memory type="ram" start="0x{segment.address:x}" length="0x{segment.size:x}"/>'.encode())
        fileobj.write(b'</memory-map>')

    def _handle_xfer(self, fileobj, args):
        offset, length = parse_hexint_list(args, 2)
        fileobj.seek(offset)
        data = fileobj.read(length)
        if len(data) < length:
            return b'l' + data
        return b'm' + data

    def _add_hook(self, hook):
        address_hooks = self._hooks.setdefault(hook.type, {})
        address_hooks[hook.address] = hook

    def _pop_hook(self, type, address):
        if type not in self._hooks or address not in self._hooks[type]:
            raise ParsingError(f'Hook of type {type} does not exist at 0x{address:X}')
        return self._hooks[type].pop(address)

    def _parse_hook(self, args):
        type, address, size = parse_hexint_list(args, 3)

        htype = GDB_TYPE_TO_HOOK_TYPE.get(type)
        if htype is None:
            raise ParsingError(f'Invalid hook type {type}')

        if size == 0:
            size = 1

        return htype, address, size
            
    def _get_stop_response(self):
        info = ''
        if self._stop_exception is None:
            signum = Signal.SIGTRAP
            if self._cpu_stop_reason is not None:
                info = self._get_stop_info(self._cpu_stop_reason)
        elif isinstance(self._stop_exception, MemFaultError):
            signum = Signal.SIGSEGV
        elif isinstance(self._stop_exception, InvalidInsnError):
            signum = Signal.SIGILL
        else:
            signum = Signal.SIGABRT
        return f'T{signum.value:02X}{info}'.encode()

    def _get_stop_info(self, reason: StopReason):
        if reason.type is not StopType.HOOK:
            return ''
        hook = reason.hook

        key = HOOK_TYPE_TO_STOP_REASON.get(hook.type)
        if key is None:
            return ''
        
        if hook.type.is_data:
            value = f'{hook.address:X}'
        else:
            value = ''
        return f'{key}:{value};'

    def _encode_reg(self, gdb_reg):
        if gdb_reg.is_dummy:
            value = 0
        else:
            value = self.dbg.regs[gdb_reg.name]
        return self.dbg.arch.endian.encode_int(value, gdb_reg.size)

    def _parse_reg(self, data):
        return self.dbg.arch.endian.decode_int(data)

    def _encode_regs(self):
        reg_data = b''.join(self._encode_reg(reg) for reg in self._regs)
        return encode_hex(reg_data)

    def _parse_regs(self, data):
        stream = io.BytesIO(parse_hex(data))
        for reg in self._regs:
            reg_data = stream.read(reg.size)
            if len(reg_data) < reg.size:
                raise ParsingError('Received register packet is too short')
            
            if reg.is_dummy:
                continue

            value = self._parse_reg(reg_data)
            if value != self.dbg.regs[reg.name]:
                logger.debug(f'Setting register {reg.name} to 0x{value:X}')
                self.dbg.regs[reg.name] = value

    def _handle_monitor_command(self, args):
        cmd = parse_ascii(parse_hex(args))
        response = self._handle_monitor_command_string(cmd) + '\n'
        return encode_hex(response.encode())

    def _handle_monitor_command_string(self, s):
        if s == '':
            s = 'help'
            
        commands = [cmd for cmd in self._monitor_commands if cmd.name.startswith(s)]
        if len(commands) == 0:
            return f'Unknown monitor command {s}. Type "monitor help" for a list of commands.'
        elif len(commands) > 1:
            names = ', '.join(cmd.name for cmd in commands)
            return f'Ambiguous monitor command {s}: could be {names}.'
        else:
            logger.debug(f'monitor command: {commands[0].name}')
            return commands[0].handler()

    def _handle_help(self):
        lines = ['Megastone monitor commands:']
        for command in self._monitor_commands:
            lines.append(f'{command.name} - {command.help}')
        return '\n'.join(lines)

    def _handle_megastone(self):
        return 'true'

    def _handle_segments(self):
        if not isinstance(self.dbg.mem, SegmentMemory):
            return 'Current Memory doesn\'t support segments.'
        
        segs = sorted(self.dbg.mem.segments, key=lambda s: s.start)
        if len(segs) == 0:
            return 'No segments information is available.'

        addr_width = _get_field_width((seg.address for seg in segs), 'Address')
        size_width = _get_field_width((seg.size for seg in segs), 'Size')
        lines = [f'{"Address":{addr_width}}  {"Size":{size_width}}  Perms  Name']
        for seg in segs:
            lines.append(f'{seg.address:#{addr_width}x}  {seg.size:#{size_width}x}  {seg.perms:<5}  {seg.name}')
        return '\n'.join(lines)

def _get_field_width(values, title):
    max_value = max(values)
    max_size = round_up(max_value.bit_length(), 4) // 4
    return max(len(title), max_size + 2)