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


class StreamServer(Closeable):
    """Server for generating Streams."""

    def initialize(self):
        """Initialize the server."""
        pass

    @abc.abstractmethod
    def get_stream(self, timeout=None) -> Stream:
        """Return the next Stream."""
        pass

    @abc.abstractmethod
    def set_timeout(self, timeout=None):
        pass


class SocketStream(Stream):
    """Stream that uses a socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

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


def _get_server_sock(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if platform.system() != 'Windows':
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
    except:
        server.close()
        raise
    return server


class TCPStreamServer(StreamServer):
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.server = None 
    
    def initialize(self):
        self.close()
        logger.info(f'listening on {self.host}:{self.port}')
        self.server = _get_server_sock(self.host, self.port)

    def close(self):
        if self.server is not None:
            self.server.close()
            self.server = None

    def set_timeout(self, timeout=None):
        self.server.settimeout(timeout)
    
    def get_stream(self):
        try:
            sock, client = self.server.accept()
        except socket.timeout as e:
            raise TimeoutError(str(e)) from e
        logger.info(f'client connected from {client}')
        return SocketStream(sock)