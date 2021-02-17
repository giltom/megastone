import logging
import enum

from .stream import Stream


logger = logging.getLogger(__name__)


START_BYTE = ord('$')
END_BYTE = ord('#')
ESCAPE_BYTE = ord('}')
ACK_BYTE = ord('+')
ESCAPED_BYTES = [START_BYTE, END_BYTE, ESCAPE_BYTE, ord('*')]
ESCAPE_XOR_VALUE = 0x20
CHECKSUM_SIZE = 2
DATA_TIMEOUT = 10


class Signal(enum.IntEnum):
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6
    SIGSEGV = 11


class ParsingError(IOError):
    pass


def parse_decimal_int(value):
    try:
        return int(value)
    except ValueError as e:
        raise ParsingError(f'Invalid decimal int: {value}') from e

def parse_hex_int(value):
    try:
        return int(value, 16)
    except ValueError as e:
        raise ParsingError(f'Invalid hex int: {value}') from e

def parse_ascii(value):
    try:
        return value.decode('ASCII')
    except UnicodeDecodeError as e:
        raise ParsingError(f'Invalid ASCII string: {value}') from e

def parse_list(value, count, sep=b','):
    parts = value.split(sep)
    if len(parts) != count:
        raise ParsingError(f'Invalid list length: expected {count} items, got {len(parts)}')
    return parts

def parse_hex(value):
    value = parse_ascii(value)
    try:
        return bytes.fromhex(value)
    except ValueError as e:
        raise ParsingError(f'Invalid hex value: {value}') from e

def parse_hexint_list(value, count, sep=b','):
    return [parse_hex_int(elem) for elem in parse_list(value, count, sep)]

def encode_hex(data):
    return data.hex().upper().encode()

def _get_checksum(data):
    return sum(data) & 0xFF


def _encode_checksum(checksum):
    return f'{checksum:02X}'.encode()


def _escape_data(data):
    result = bytearray()
    for byte in data:
        if byte in ESCAPED_BYTES:
            result.append(ESCAPE_BYTE)
            result.append(byte ^ ESCAPE_XOR_VALUE)
        else:
            result.append(byte)
    return bytes(result)

def _unescape_data(data):
    result = bytearray()
    escaped = False
    for byte in data:
        if byte == ESCAPE_BYTE:
            escaped = True
        elif byte in ESCAPED_BYTES:
            raise ParsingError(f'Invalid byte in data: 0x{byte:02X}')
        elif escaped:
            result.append(byte ^ ESCAPE_XOR_VALUE)
            escaped = False
        else:
            result.append(byte)
    return bytes(result)

def _encode_packet(data):
    escaped = _escape_data(data)
    checksum = _get_checksum(escaped)
    return bytes([START_BYTE]) + escaped + bytes([END_BYTE]) + _encode_checksum(checksum)


class RSPConnection:
    def __init__(self, stream: Stream):
        self._stream = stream

    def send_packet(self, data):
        """Send the packet with the given data or raise IOError."""
        self._stream.set_timeout(DATA_TIMEOUT)
        packet = _encode_packet(data)
        self._stream.write_all(packet)
        self._receive_ack()

    def receive_packet(self, timeout=None):
        """
        Receive a single packet and return its data, or raise EndOfStreamError/IOError.

        If the timeout occurs before the start byte, will return None.
        """
        self._stream.set_timeout(timeout)
        started = self._wait_for_start()
        if not started:
            return None

        self._stream.set_timeout(DATA_TIMEOUT)
        data = self._receive_data()
        recv_checksum = self._receive_checksum()

        real_checksum = _get_checksum(data)
        if recv_checksum != real_checksum:
            raise ParsingError(f'Invalid checksum: expected {real_checksum:02X}, got {recv_checksum:02X}')

        unescaped = _unescape_data(data)
        self._send_ack()
        return unescaped

    def _wait_for_start(self):
        try:
            start = self._stream.read_one()
        except TimeoutError:
            return False
        if start == START_BYTE:
            return True
        if start != ACK_BYTE:
            logger.warning(f'Dropping unexpected byte: {start:02X}')
        return False

    def _receive_data(self):
        return bytes(iter(self._stream.read_one, END_BYTE))

    def _receive_checksum(self):
        return parse_hex_int(self._stream.read_all(2))

    def _receive_ack(self):
        ack = self._stream.read_one()
        if ack != ACK_BYTE:
            raise ParsingError(f'Invalid ack byte: {ack:#x}')

    def _send_ack(self):
        self._stream.write(bytes([ACK_BYTE]))