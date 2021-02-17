from xml.etree.ElementTree import parse
from megastone.debug.errors import CPUError, InvalidInsnError, MemFaultError
import threading
import logging
import io

from megastone.mem import AccessType, SegmentMemory, MemoryAccessError
from megastone.debug import Debugger, StopReason, StopType, HookType
from .connection import RSPConnection, Signal, parse_hex_int, parse_list, encode_hex, parse_hex, ParsingError
from .stream import EndOfStreamError, Stream
from .regs import load_gdb_regs


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


class GDBServer:
    """GDB Server implementation. Exposes a Debugger to external GDB clients."""

    def __init__(self, stream: Stream, dbg: Debugger):
        self.dbg = dbg
        self._conn = RSPConnection(stream)
        self._regs = load_gdb_regs(dbg.arch)
        self._stopped = threading.Event()
        
        self._stop_reason: StopReason = None
        self._stop_exception: CPUError = None

        self._handlers = {
            b'?': self._handle_stop_reason,
            b'D': self._handle_detach,
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
            b'C': self._handle_continue_signal
        }
        
    def stop(self):
        """
        Stop the server.
        
        This can be safely called from a different thread than the one running the server.
        """
        self._stopped.set()

    def start_thread(self):
        """Start the server in a new thread. Returns the created Thread."""
        thread = threading.Thread(self.run, daemon=True)
        thread.start()
        return thread

    def run(self):
        """Run the server. Blocks until the client exists or an error occurs."""

        while True:
            try:
                command = self._conn.receive_packet(timeout=STOP_POLL_TIME)
            except EndOfStreamError:
                logger.warning('client disconnected')
                break

            if command is not None:
                self._handle_command(command)

            if self._stopped.is_set():
                logger.info('stopping server')
                break

    def _handle_command(self, command):
        logger.debug(f'received packet: {command}')
        for prefix, handler in self._handlers.items():
            if command.startswith(prefix):
                args = command[len(prefix):]
                response = handler(args)
                logger.debug(f'sending response: {response}')
                break
        else: #no break
            response = b''
        self._conn.send_packet(response)

    def _handle_stop_reason(self, args):
        return self._get_stop_response()

    def _handle_detach(self, args):
        logger.info('client detached')
        self.stop()
        return b'OK'

    def _handle_attached(self, args):
        return b'1'

    def _handle_read_regs(self, args):
        return self._encode_regs()

    def _handle_write_regs(self, args):
        self._parse_regs(args)
        return OK_RESPONSE

    def _handle_read_mem(self, args):
        address, size = self._parse_address_range(args)
        try:
            data = self.dbg.mem.read(address, size)
        except MemoryAccessError as e:
            logger.error(str(e))
            return ERROR_RESPONSE
        return encode_hex(data)

    def _handle_write_mem(self, args):
        addresses, hex_data = parse_list(args, 2, b':')
        address, _ = self._parse_address_range(addresses)
        data = parse_hex(hex_data)
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

        self._stop_reason = None
        self._stop_exception = None
        logger.debug(f'run: address={address}, count={count}')
        try:
            self._stop_reason = self.dbg.run(count=count, address=address)
        except CPUError as e:
            self._stop_exception = e
            logger.info(f'stopped: {e}')
        else:
            logger.debug(f'stopped: {self._stop_reason.type.name}')
        
        return self._get_stop_response()

    def _handle_supported(self, args):
        return b'hwbreak+;qXfer:features:read+;qXfer:memory-map:read+'

    def _handle_read_features(self, args):
        file = io.BytesIO(b'<target version="1.0"><architecture>i386:x86-64</architecture></target>')
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
        offset, length = self._parse_address_range(args)
        fileobj.seek(offset)
        data = fileobj.read(length)
        if len(data) < length:
            return b'l' + data
        return b'm' + data
        
    def _parse_address_range(self, args):
        start, size = parse_list(args, 2)
        return parse_hex_int(start), parse_hex_int(size)

    def _get_stop_response(self):
        info = ''
        if self._stop_exception is None:
            signum = Signal.SIGTRAP
            if self._stop_reason is not None:
                info = self._get_stop_info(self._stop_reason)
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
        return f'{key}:{value}'

    def _encode_reg(self, value, size):
        return self.dbg.arch.endian.encode_int(value, size)

    def _parse_reg(self, data):
        return self.dbg.arch.endian.decode_int(data)

    def _encode_regs(self):
        reg_data = b''.join(self._encode_reg(self.dbg.regs[reg.name], reg.size) for reg in self._regs)
        return encode_hex(reg_data)

    def _parse_regs(self, data):
        stream = io.BytesIO(parse_hex(data))
        for reg in self._regs:
            reg_data = stream.read(reg.size)
            if len(reg_data) < reg.size:
                raise ParsingError('Received register packet is too short')

            value = self._parse_reg(reg_data)
            if value != self.dbg.regs[reg.name]:
                logger.debug(f'Setting register {reg.name} to 0x{value:X}')
                self.dbg.regs[reg.name] = value