from __future__ import annotations

import io
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .memory import Memory

class BaseMemoryIO(io.RawIOBase):
    """Base class for Memory-based file objects."""

    def __init__(self, mem : Memory, start):
        self._mem = mem
        self._start = start
        self._offset = 0

    def seekable(self):
        return True
    
    def tell(self):
        return self._offset

    def _get_seek_offset(self, offset, whence):
        if whence == io.SEEK_SET:
            return offset
        if whence == io.SEEK_CUR:
            return self._offset + offset
        raise ValueError('Invalid seek type')

    def _set_offset(self, offset):
        if offset < 0:
            raise ValueError('Invalid seek offset')
        self._offset = offset

    def _read(self, size):
        data = self._mem.read(self._start + self._offset, size)
        self._offset += size
        return data

    def _write(self, data):
        self._mem.write(self._start + self._offset, data)
        self._offset += len(data)
        return len(data)


class StreamMemoryIO(BaseMemoryIO):
    """RawIOBase implementation that exposes memory as a stream-like file object with unlimited size."""

    def seek(self, offset, whence=io.SEEK_SET):
        self._set_offset(self._get_seek_offset(offset, whence))
    
    def read(self, size):
        return self._read(size)

    def write(self, data):
        return self._write(data)


class MemoryIO(BaseMemoryIO):
    """RawIOBase implementation that exposes a specific memory region as a file object."""

    def __init__(self, mem : Memory, start, size):
        super().__init__(mem, start)
        self._size = size

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_END:
            new_offset = self._size + offset
        else:
            new_offset = self._get_seek_offset(offset, whence)
        self._set_offset(new_offset)

    def truncate(self, size=None):
        if size is None:
            size = self._offset
        self._size = size

    def read(self, size=-1):
        if self._offset >= self._size:
            return b''

        if size == -1 or self._offset + size > self._size:
            size = self._size - self._offset

        return self._read(size)
    
    def write(self, data):
        end_offset = self._offset + len(data)
        if end_offset > self._size:
            self._size = end_offset

        return self._write(data)

    def get_data(self):
        """Return the entire data covered by the file"""
        return self._mem.read(self._start, self._size)