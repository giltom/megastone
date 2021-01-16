from pathlib import Path
from dataclasses import dataclass

from .memory import MappableMemory


@dataclass
class Segment:
    start: int
    data: bytearray

    @property
    def size(self):
        return len(self.data)

    @property
    def end(self):
        return self.start + self.size

    def overlaps(self, other):
        return self.start <= other.end and other.start <= self.end #Returns True if the segments are directly adjacent even if they don't overlap

    def merge(self, other):
        """Merge this segment with other. `other`'s data overrides this segment's data where they overlap."""
        new_start = min(self.start, other.start)
        new_end = max(self.end, other.end)
        new_size = new_end - new_start
        new_data = bytearray(new_size)

        data_offset = self.start - new_start
        new_data[data_offset : data_offset + len(self.data)] = self.data

        other_data_offset = other.start - new_start
        new_data[other_data_offset : other_data_offset + len(other.data)] = other.data

        self.start = new_start
        self.data = new_data
        

class BufferMemory(MappableMemory):
    """
    Simple Memory implementation backed by host memory buffers.

    Allows arbitrary data to be loaded to arbitrary addresses.
    Useful for analyzing or patching firmwares.
    """
    def __init__(self, arch, *, verbose=False):
        super().__init__(arch, verbose=verbose)
        self._segments = [] #List maintained in sorted order. We always merge segments so that there are always gaps between segments

    def segments(self):
        """Return an iterable of currently mapped Segments, sorted by start address"""
        yield from self._segments

    def read_segment(self, address):
        """Return the entire data of the segment containing the given address."""
        seg = self._find_segment(address, 1)
        return bytes(seg.data)
    
    def map(self, address, size):
        """Map memory at the given address. New memory is initialized to 0."""
        new_seg = Segment(address, bytearray(size))
        new_segments = [new_seg]
        for segment in self._segments:
            if new_seg.overlaps(segment):
                new_seg.merge(segment)
            else:
                new_segments.append(segment)

        new_segments.sort(key=lambda seg: seg.start)
        self._segments = new_segments

    def write_data(self, address, data):
        seg = self._find_segment(address, len(data))
        offset = address - seg.start
        seg.data[offset : offset + len(data)] = data

    def read_data(self, address, size):
        seg = self._find_segment(address, size)
        offset = address - seg.start
        return seg.data[offset : offset + size]

    def _find_segment(self, address, size):
        for seg in self._segments:
            if seg.start <= address and address + size <= seg.end:
                return seg
        raise ValueError(f'Access unmapped memory: 0x{address:X}-0x{address+size:X}')


class BinaryImage(BufferMemory):
    """
    Simplest Memory implementation that exposes a single binary blob.
    
    Useful for analyzing/patching firmwares.
    """

    def __init__(self, arch, data, address=0, *, verbose=False):
        """
        Initialize a new BinaryImage.

        `arch` - Architecture.
        `data` - Image data.
        `address` - Base address of data.
        `verbose` - If True, will print information about any writes performed.
        """
        super().__init__(arch, verbose=verbose)
        self.address = address
        self.load(address, data)
    
    @classmethod
    def from_file(cls, arch, path, address=0, *, verbose=False):
        """Initialize a new firmware with data loaded from the given path."""
        data = Path(path).read_bytes()
        return cls(arch, data, address, verbose=verbose)
        
    def get_bytes(self):
        """Return the patched bytes"""
        return self.read_segment(self.address)

    def write_to_file(self, path):
        """Write the patched bytes to the given path"""
        Path(path).write_bytes(self.get_bytes())