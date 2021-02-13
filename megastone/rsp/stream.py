import abc
import socket
import selectors
import os
import platform
import logging

import serial


from megastone.util import Closeable


logger = logging.getLogger(__name__)


class EndOfStreamError(IOError):
    pass


class Stream(Closeable):
    """Abstract Stream class for input/output streams."""

    @abc.abstractmethod
    def set_timeout(self, timeout):
        """Set the timeout in seconds, or None for no timeout."""

    @abc.abstractmethod
    def read(self, size) -> bytes:
        """
        Read up to size bytes from the stream or raise TimeoutError/IOError.
        
        Return 0 bytes on EOF.
        """

    @abc.abstractmethod
    def write(self, data) -> int:
        """Write data and return the number of bytes written or raise IOError."""

    def read_all(self, size):
        """Read exactly size bytes or raise TimeoutError/EndOfStreamError/IOError."""
        data = bytearray()
        while len(data) < size:
            chunk = self.read(size - len(data))
            if len(chunk) == 0:
                raise EndOfStreamError('Read: peer disconnected')
            data += chunk
        return bytes(data)

    def read_one(self):
        """Read one byte or raise TimeoutError/EndOfStreamError/IOError."""
        return self.read_all(1)[0]

    def write_all(self, data):
        """Write all of data or raise IOError"""
        offset = 0
        while offset < len(data):
            num_written = self.write(data[offset:])
            if num_written == 0:
                raise IOError('Write: peer disconnected')
            offset += num_written


class SocketStream(Stream):
    """Stream that uses a socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    @classmethod
    def connect(cls, host, port):
        """Create a SocketStream by connecting to the given host/port."""
        logger.info(f'connecting to {host}:{port}')
        sock = socket.create_connection((host, port))
        return cls(sock)

    @classmethod
    def accept(cls, port, interface='0.0.0.0'):
        """Create a SocketStream by listening for one connection to the given port."""
        logger.info(f'waiting for connection to {interface}:{port}')
        reuse = platform.system() != 'Windows'
        with socket.create_server((interface, port), reuse_port=reuse) as server:
            sock, client = server.accept()
            logger.info(f'client connected from {client}')
            return cls(sock)

    def set_timeout(self, timeout):
        self.sock.settimeout(timeout)

    def read(self, size):
        try:
            return self.sock.recv(size)
        except socket.timeout as e:
            raise TimeoutError(str(e)) from e

    def write(self, data):
        return self.sock.send(data)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except IOError:
            pass
        self.sock.close()


def _get_pipe():
    rfd, wfd = os.pipe()
    rfile = os.fdopen(rfd, 'rb', buffering=0)
    wfile = os.fdopen(wfd, 'wb', buffering=0)
    return rfile, wfile


class PipeStream(Stream):
    """Stream that communicates via a pair of OS pipes."""

    def __init__(self, read_file, write_file):
        self._read_file = read_file
        self._write_file = write_file
        self._timeout = None

        self._selector = selectors.DefaultSelector()
        self._selector.register(self._read_file, selectors.EVENT_READ)

    def set_timeout(self, timeout):
        self._timeout = timeout

    def read(self, size):
        events = self._selector.select(timeout=self._timeout)
        if len(events) == 0:
            raise TimeoutError('Read timed out')

        return self._read_file.read(size)

    def write(self, data):
        return self._write_file.write(data)

    def close(self):
        self._read_file.close()
        self._write_file.close()
        self._selector.close()


class PipeStreamPair(Closeable):
    """Pair of pipe streams."""

    def __init__(self):
        rfile1, wfile1 = _get_pipe()
        rfile2, wfile2 = _get_pipe()
        self.stream1 = PipeStream(rfile1, wfile2)
        self.stream2 = PipeStream(rfile2, wfile1)

    def close(self):
        self.stream1.close()
        self.stream2.close()


class SerialStream(Stream):
    """Stream over a serial port."""

    def __init__(self, port: serial.Serial):
        self.port = port
        self.timeout = None

    def set_timeout(self, timeout):
        self.port.timeout = timeout

    def read(self, size):
        data = self.port.read(size)
        if len(data) < size:
            raise TimeoutError('Read timed out')
        return data
    
    def write(self, data):
        return self.port.write(data)

    def close(self):
        self.port.close()