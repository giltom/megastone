from __future__ import annotations

import abc
from collections.abc import Iterable
import io
from megastone.mem.errors import MemoryReadError, MemoryWriteError

from megastone.arch import Architecture
from megastone.util import round_down, round_up, NamespaceMapping
from megastone.errors import MegastoneError
from .memory import Memory
from .access import AccessType
from .address_range import AddressRange


MIN_ALLOC_ADDRESS = 0x1000
ALLOC_ROUND_SIZE = 0x1000


class Segment(AddressRange):
    """Represents an area of memory."""

    name: str
    perms: AccessType
    mem: Memory

    def __init__(self, name, start, size, perms, mem):
        super().__init__(start, size)
        self.name = name
        self.perms = perms
        self.mem = mem
    
    def __repr__(self):
        return f"<Segment '{self.name}' at 0x{self.start:X}-0x{self.end:X}, {self.perms}>"

    def __eq__(self, other):
        return (
            isinstance(other, Segment) and
            other.size == self.size and
            other.start == self.start and
            other.name == self.name and
            other.perms == self.perms and 
            other.mem == self.mem
        )

    def read(self):
        """Read and return the entire segment data."""
        return self.mem.read(self.start, self.size)

    def write(self, data):
        """Write the given data to the start of the segment."""
        self.mem.write(self.start, data) 

    def write_file(self, path):
        """Write the file at the given path to the segment."""
        return self.mem.write_file(self.start, path)

    def dump_to_file(self, path):
        """Dump the entire segment to the given path."""
        return self.mem.dump_to_file(self.start, self.size, path)

    def dump_to_fileobj(self, fileobj):
        """Dump the entire segment to the given file object."""
        return self.mem.dump_to_fileobj(self.start, self.size, fileobj)

    def create_fileobj(self):
        """Get a virtual file object exposing the segment as a file."""
        return self.mem.create_fileobj(self.start, self.size)

    def search(self, value, *, alignment=1):
        """Search the segment for bytes, returning the found address or None if not found."""
        return self.mem.search(self.start, self.size, value, alignment=alignment)


class SegmentMemory(Memory):
    """
    Memory that supports Segments.

    Each Segment is a named range of memory with access its own permissions
    (names and/or permissions may be meaningless in some contexes).
    Segments are not allowed to overlap.
    """

    def __init__(self, arch: Architecture):
        super().__init__(arch)
        self.segments = SegmentMapping(self)

    def search_all(self, value, *, alignment=1, perms=AccessType.NONE):
        """
        Search all segments for bytes, returning the found address or None if not found.
        
        If perms is given, search only segments with the given permissions.
        """
        for seg in self.segments.with_perms(perms):
            result = seg.search(value, alignment=alignment)
            if result is not None:
                return result
        return None

    def search_code(self, assembly, isa=None):
        """Search for the given assembly instructions in all executable segments."""
        isa = self._fix_isa(isa)

        code = isa.assemble(assembly)
        return self.search_all(code, alignment=isa.insn_alignment, perms=AccessType.X)

    def is_mapped(self, address, size=1):
        """True if the given range is mapped in a single segment."""
        try:
            seg = self.segments.by_address(address)
        except KeyError:
            return False
        return seg.contains(address + size - 1)

    @abc.abstractmethod
    def _get_all_segments(self) -> Iterable[Segment]:
        #Return an iterable of all segments
        pass

    def _num_segments(self):
        #Override if more efficient implementation is available
        return sum(1 for _ in self._get_all_segments())

    def _get_segment_by_name(self, name):
        #Override if more efficient implementation is available
        for seg in self._get_all_segments():
            if seg.name == name:
                return seg
        raise KeyError(f'No such segment "{name}"')

    def _get_segment_by_address(self, address):
        #Override if more efficient implementation is available
        for seg in self._get_all_segments():
            if seg.contains(address):
                return seg
        raise KeyError(f'No segment contains address 0x{address:X}')

    def _get_max_read_size(self, address):
        try:
            seg = self._get_segment_by_address(address)
        except KeyError:
            return None
        return seg.end - address


class SegmentMapping(NamespaceMapping[Segment]):
    """Helper class used to access segments."""

    def __init__(self, mem: SegmentMemory):
        self._mem = mem

    def __getitem__(self, key):
        return self._mem._get_segment_by_name(key)

    def by_address(self, address):
        """Return the segment that contains the given address."""
        return self._mem._get_segment_by_address(address)

    def __iter__(self):
        yield from self._mem._get_all_segments()
    
    def with_perms(self, perms):
        """Return an iterable of all segments that contain the given AccessType."""
        for seg in self:
            if seg.perms.contains(perms):
                yield seg

    def __len__(self):
        return self._mem._num_segments()

    def __contains__(self, name):
        try:
            self._mem._get_segment_by_name(name)
        except KeyError:
            return False
        return True


class DictSegmentMemory(SegmentMemory):
    """Subclass of SegmentMemory that stores segments in a dict."""

    def __init__(self, arch: Architecture):
        super().__init__(arch)
        self._segments: dict[str, Segment] = {}

    def _get_all_segments(self):
        return self._segments.values()

    def _num_segments(self):
        return len(self._segments)

    def _get_segment_by_name(self, name):
        return self._segments[name]

    def _check_segment(self, seg: Segment):
        #Can be called to verify a segment before processing it
        if seg.name in self._segments:
            raise MegastoneError(f'Segment with name "{seg.name}" already exists')

        for old_seg in self.segments:
            if old_seg.overlaps(seg):
                raise MegastoneError('Segment overlap')

    def _add_segment(self, seg: Segment):
        #Call in a subclass to initialize segments
        self._check_segment(seg)
        self._segments[seg.name] = seg
        return seg


class MappableMemory(DictSegmentMemory):
    """Abstract SegmentMemory subclass that supports allocating new segments at arbitrary addresses."""

    def map(self, address, size, name=None, perms=AccessType.RWX):
        """
        Allocate a new Segment, initialized to 0, at the given address range.
        
        Returns the new Segment.
        """
        if name is None:
            name = f'anon_{address:x}'
        elif not isinstance(name, str):
            raise ValueError('Segment name must be a string')
        
        seg = self._create_segment(name, address, size, perms)
        self._check_segment(seg)
        self._handle_new_segment(seg)
        self._add_segment(seg)
        return seg

    def load(self, address, data, name=None, perms=AccessType.RWX):
        """Shorthand for map() followed by write()."""
        seg = self.map(address, len(data), name=name, perms=perms)
        seg.write(data)
        return seg
    
    def load_file(self, address, path, name=None, perms=AccessType.RWX):
        """Load the file at the given path."""
        with open(path, 'rb') as file:
            file.seek(0, io.SEEK_END)
            size = file.tell()
            self.map(address, size, name=name, perms=perms)
            file.seek(0)
            self.write_fileobj(address, file)

    def load_memory(self, mem: SegmentMemory):
        """Copy all segments from the given SegmentMemory into this memory."""
        for seg in mem.segments:
            self.load(seg.start, seg.read(), name=seg.name, perms=seg.perms)

    def allocate(self, size, name=None, perms=AccessType.RWX):
        """Automatically allocate a new segment in an unused region."""
        address = self._allocate_address(size)
        return self.map(address, size, name=name, perms=perms)

    def _handle_new_segment(self, seg: Segment):
        """Handle a newly created segment after it has been verified but before it has been added."""
        pass

    def _create_segment(self, name, start, size, perms) -> Segment:
        """Can override in subclass to customize segment creation."""
        return Segment(name, start, size, perms, self)

    def _allocate_address(self, size):
        segs = sorted(self.segments, key=lambda seg: seg.start)

        if len(segs) == 0:
            return MIN_ALLOC_ADDRESS

        address = self._allocate_in_range(MIN_ALLOC_ADDRESS, segs[0].start, size)
        if address is not None:
            return address

        for i, seg in enumerate(segs[:-1]):
            address = self._allocate_in_range(seg.end, segs[i+1].start, size)
            if address is not None:
                return address

        address = self._allocate_in_range(segs[-1].end, self.arch.max_mem_size, size)
        if address is not None:
            return address
        
        raise MegastoneError(f'No address of size 0x{size:X} is available')

    def _allocate_in_range(self, start, end, size):
        start = round_up(start, ALLOC_ROUND_SIZE)
        end = round_down(end, ALLOC_ROUND_SIZE)
        if end - start >= size:
            return start
        return None


class SplittingSegmentMemory(SegmentMemory):
    """
    SegmentMemory abstract subclass that assumes that only one segment can be written at a time.

    It splits each read/write into multiple operations if it overlaps multiple adjacent segments.
    Can be mixed in with other SegmentMemory subclasses.
    """


    @abc.abstractmethod
    def _read_segment(self, segment: Segment, offset, size):
        """Read data from the given segment at the given offset"""

    @abc.abstractmethod
    def _write_segment(self, segment: Segment, offset, data):
        """Write data to the given segment at the given offset"""

    def _read(self, address, size):
        try:
            offsets = list(self._get_data_offsets(address, size))
        except KeyError as e:
            raise MemoryReadError(address, size, 'unmapped') from e
        return b''.join(self._read_segment(seg, start, size) for seg, start, size in offsets)

    def _write(self, address, data):
        offset = 0
        #we call list() to detect any errors before starting to write
        try:
            offsets = list(self._get_data_offsets(address, len(data)))
        except KeyError as e:
            raise MemoryWriteError(address, data, 'unmapped') from e
        for seg, start, size in offsets: 
            self._write_segment(seg, start, data[offset : offset + size])
            offset += size

    def _get_data_offsets(self, address, size):
        #We need to deal with the case of a read/write that spans two adjacent segments
        #This function yields segment, start_offset, size containing given address range
        curr_address = address
        end_address = address + size

        while curr_address < end_address:
            seg = self.segments.by_address(curr_address)
            start_offset = curr_address - seg.start
            end_offset = min(end_address - seg.start, seg.size)
            yield seg, start_offset, end_offset - start_offset

            curr_address = seg.start + end_offset