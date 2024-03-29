from megastone.errors import MegastoneError
from .segments import MappableMemory, SplittingSegmentMemory, Segment
from .access import AccessType


class BufferSegment(Segment):
    """Segment subclass that also contains an internal buffer for storing the data."""
    def __init__(self, name, start, size, perms, mem):
        super().__init__(name, start, size, perms, mem)
        self._data = bytearray(size)
        

class BufferMemory(MappableMemory, SplittingSegmentMemory):
    """
    Simple Memory implementation backed by host memory buffers.

    Allows arbitrary data to be loaded to arbitrary addresses.
    Useful for analyzing or patching firmwares.
    """
    def __init__(self, arch):
        super().__init__(arch)
        self.locked = False

    def _create_segment(self, name, start, size, perms):
        if self.locked:
            raise MegastoneError('Segment mapping can\'t be changed for this memory; copy it first')
        return BufferSegment(name, start, size, perms, self)

    def _read_segment(self, segment: BufferSegment, offset, size):
        return segment._data[offset : offset + size]

    def _write_segment(self, segment: BufferSegment, offset, data):
        segment._data[offset : offset + len(data)] = data

    def lock(self):
        self.locked = True