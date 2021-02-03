from .memory import MappableMemory, Segment
from .access import AccessType, Access
from .errors import MemoryAccessError


class BufferSegment(Segment):
    """Segment subclass that also contains an internal buffer for storing the data."""
    def __init__(self, name, start, size, perms, mem):
        super().__init__(name, start, size, perms, mem)
        self._data = bytearray(size)
        

class BufferMemory(MappableMemory):
    """
    Simple Memory implementation backed by host memory buffers.

    Allows arbitrary data to be loaded to arbitrary addresses.
    Useful for analyzing or patching firmwares.
    """
    
    def map(self, name, start, size, perms=AccessType.RWX):
        return self._add_segment(BufferSegment(name, start, size, perms, self))

    def write_data(self, address, data):
        offset = 0
        offsets = self._get_data_offsets(address, len(data), AccessType.W)
        for seg, start, end in list(offsets): #we call list() to detect any errors before starting to write
            chunk_size = end - start
            seg._data[start : end] = data[offset : offset + chunk_size]
            offset += chunk_size

    def read_data(self, address, size):
        offsets = self._get_data_offsets(address, size, AccessType.R)
        return b''.join(seg._data[start : end] for seg, start, end in offsets)

    def _get_data_offsets(self, address, size, atype):
        #We need to deal with the case of a read/write that spans two adjacent segments
        #This function yields segment, start_offset, end_offset containing given address range
        curr_address = address
        end_address = address + size

        while curr_address < end_address:
            try:
                seg = self.segments.by_address(curr_address)
            except KeyError as e:
                raise MemoryAccessError(Access(atype, address, size), 'unmapped')

            start_offset = curr_address - seg.start
            end_offset = min(end_address - seg.start, seg.size)
            yield seg, start_offset, end_offset

            curr_address = seg.start + end_offset