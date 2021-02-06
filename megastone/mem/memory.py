import abc
from megastone.errors import MegastoneError
from megastone.arch.isa import InstructionSet
from megastone.util import NamespaceMapping, round_up
from pathlib import Path
from dataclasses import dataclass
import io
import shutil

from megastone.arch import Architecture
from megastone.util import NamespaceMapping
from .access import AccessType, Access
from .errors import MemoryAccessError


MIN_ALLOC_ADDRESS = 0x1000
ALLOC_ROUND_SIZE = 0x1000


class Memory(abc.ABC):
    """Abstract class representing a memory space."""

    def __init__(self, arch: Architecture):
        self.arch = arch
        self.default_isa = arch.default_isa
        self.verbose = False

    @abc.abstractmethod
    def write_data(self, address, data):
        """
        Write bytes at the given address.
        
        Override in a subclass - don't call this directly.
        """
        pass

    @abc.abstractmethod
    def read_data(self, address, size) -> bytes:
        """
        Read bytes from the given address.
        
        Override in a subclass - don't call this directly.
        """
        pass

    def write(self, address, data):
        if self.verbose:
            print(f'Write 0x{len(data):X} bytes to 0x{address:X}')
        self.write_data(address, data)
    
    def read(self, address, size):
        return self.read_data(address, size)

    def read_int(self, address, size, *, signed=False):
        """Read an integer from the given address."""
        data = self.read(address, size)
        return self.arch.endian.decode_int(data, signed=signed)

    def write_int(self, address, value, size):
        """Write an integer to the given address."""
        data = self.arch.endian.encode_int(value, size)
        self.write(address, data)

    def read_word(self, address, *, signed=False):
        """Read an arch-word from the given address."""
        return self.read_int(address, self.arch.word_size, signed=signed)
    
    def write_word(self, address, value):
        """Write an arch-word to the given address."""
        self.write_int(address, value, self.arch.word_size)
    
    def read_byte(self, address):
        return self.read_int(address, 1)
    
    def write_byte(self, address, value):
        self.write_int(address, value, 1)

    def read_16(self, address):
        return self.read_int(address, 2)
    
    def write_16(self, address, value):
        self.write_int(address, value, 2)
    
    def read_32(self, address):
        return self.read_int(address, 4)
    
    def write_32(self, address, value):
        self.write_int(address, value, 4)

    def read_64(self, address):
        return self.read_int(address, 8)
    
    def write_64(self, address, value):
        self.write_int(address, value, 8)

    def read_cstring_bytes(self, address, max_size=0x10000):
        """
        Read a C-string from the given address and return the raw bytes.
        
        It might be a good idea to override this in a subclass if there is a faster implementation.
        """
        result = bytearray()
        while len(result) < max_size:
            byte = self.read_byte(address + len(result))
            if byte == 0:
                break
            result.append(byte)
        return bytes(result)

    def read_cstring(self, address, max_size=0x10000):
        """Read a C-string from the given address and return a str."""
        return self.read_cstring_bytes(address, max_size).decode('UTF-8')

    def write_cstring(self, address, string):
        """Write a C-string to the given address."""
        self.write(address, string.encode('UTF-8') + b'\0')
    
    def write_code(self, address, assembly, isa=None):
        """Assemble the given instructions and write them to the address."""
        isa = self._fix_isa(isa)

        code = isa.assemble(assembly, address)
        if self.verbose:
            print(f'Assemble "{assembly}" => {code.hex().upper()}')
        self.write(address, code)
    
    def disassemble_one(self, address, isa=None):
        """Disassemble the instruction at the given address and return it."""
        isa = self._fix_isa(isa)

        code = self.read(address, isa.max_insn_size)
        return isa.disassemble_one(code, address)
    
    def disassemble(self, address, count, isa=None):
        """Disassemble `count` instructions at the given address and return an iterator over the disassembled instructions."""
        for _ in range(count):
            inst = self.disassemble_one(address, isa)
            yield inst
            address += inst.size

    def create_fileobj(self, address, size=None):
        """
        Get a virtual file object exposing a memory range.
        
        If `size` is not None, a file object of the given size is created.
        The file will return EOF after `size` bytes are read.
        If `size` is None, a "stream" file with unlimited size is created.
        Calling read() with no arguments isn't supported.
        """
        if size is None:
            return StreamMemoryIO(self, address)
        return MemoryIO(self, address, size)

    def write_fileobj(self, address, fileobj):
        """Write data from the file object to the given address."""
        dest = self.create_fileobj(address)
        shutil.copyfileobj(fileobj, dest)

    def write_file(self, address, path):
        """Write the file at the given path to memory."""
        with Path(path).open('rb') as fileobj:
            self.write_fileobj(address, fileobj)

    def dump_to_fileobj(self, address, size, fileobj):
        """Write data from memory to a file object."""
        src = self.create_fileobj(address, size)
        shutil.copyfileobj(src, fileobj)

    def dump_to_file(self, address, size, path):
        """Dump bytes at the given area to the given path."""
        with Path(path).open('wb') as fileobj:
            self.dump_to_fileobj(address, size, fileobj)

    def search(self, start, size, value, *, alignment=1):
        """
        Search a memory range for the given value and return the address it was found at, or None if not found.

        It might be a good idea to override this in a subclass if a more efficient implementation is available.
        """
        #In the future it may be needed to improve performance by reading in chunks
        data = self.read(start, size)
        search_start = 0
        while True:
            offset = data.find(value, search_start)
            if offset == -1:
                return None
            address = start + offset
            if address % alignment == 0:
                return address
            search_start = offset + 1


    def __getitem__(self, key):
        #Expose memory as a bytes-like object, so we can write e.g. memory[0x4:0x8]
        if isinstance(key, int):
            return self.read_byte(key)
        self._check_slice(key)
        
        size = key.stop - key.start
        if size <= 0:
            return b''
        return self.read(key.start, size)
    
    def __setitem__(self, key, value):
        if isinstance(key, int):
            return self.write_byte(key, value)
        self._check_slice(key)

        size = key.stop - key.start
        if size != len(value):
            raise ValueError('Unexpected data length for slice write')
        self.write(key.start, value)

    def _check_slice(self, key):
        if not isinstance(key, slice):
            raise TypeError('Invalid key type')
        if key.step is not None and key.step != 1:
            raise ValueError('Slice stepping is not supported for Memory objects')
        if key.start is None or key.stop is None:
            raise ValueError('Slice start and end must be specified for memory objects')

    def _fix_isa(self, isa) -> InstructionSet:
        if isa is None:
            return self.default_isa
        return isa



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
        

@dataclass(frozen=True, repr=False)
class Segment:
    """Represents an area of memory."""

    name: str
    start: int
    size: int
    perms: AccessType
    mem: Memory

    @property
    def end(self):
        return self.start + self.size

    @property
    def address(self):
        """Alias of `start`."""
        return self.start
    
    def __repr__(self):
        return f"<Segment '{self.name}' at 0x{self.start:X}-0x{self.end:X}, {self.perms}>"

    def overlaps(self, other):
        """Return True if this segment overlaps other."""
        return self.start < other.end and other.start < self.end

    def adjacent(self, other):
        """Return True if this segment overlaps other or is immediately next to it (with no gap)."""
        return self.start <= other.end and other.start <= self.end

    def contains_address(self, address):
        return self.start <= address < self.end

    def get_start(self):
        return self.start
    
    def get_size(self):
        return self.size
    
    def get_end(self):
        return self.end

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

    @abc.abstractmethod
    def _get_all_segments(self):
        #Return an iterable of all segments
        pass

    @abc.abstractmethod
    def _num_segments(self):
        pass

    def _get_segment_by_name(self, name):
        #Override if more efficient implementation is available
        for seg in self._get_all_segments():
            if seg.name == name:
                return seg
        raise KeyError(f'No such segment "{name}"')

    def _get_segment_by_address(self, address):
        #Override if more efficient implementation is available
        for seg in self._get_all_segments():
            if seg.contains_address(address):
                return seg
        raise KeyError(f'No segment contains address 0x{address:X}')


class SegmentMapping(NamespaceMapping):
    """Helper class used to access segments."""

    def __init__(self, mem: SegmentMemory):
        self._mem = mem

    def __getitem__(self, key) -> Segment:
        return self._mem._get_segment_by_name(key)

    def by_address(self, address) -> Segment:
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


class MappableMemory(SegmentMemory):
    """Abstract SegmentMemory subclass that supports allocating new segments at arbitrary addresses."""

    def __init__(self, arch: Architecture):
        super().__init__(arch)
        self.locked = False
        self._segments = {} #name => Segment. Subclass should call _add_segment to initialize this

    @abc.abstractmethod
    def map(self, name, start, size, perms=AccessType.RWX) -> Segment:
        """
        Allocate a new Segment, initialized to 0, at the given address range.
        
        Returns the new Segment.
        """
        #Implementation should call _add_segment() and also do any other needed maintenance....

    def load(self, name, address, data, perms=AccessType.RWX) -> Segment:
        """Shorthand for map() followed by write()."""
        seg = self.map(name, address, len(data), perms)
        seg.write(data)
        return seg
    
    def load_file(self, name, address, path, perms=AccessType.RWX) -> Segment:
        """Load the file at the given path."""
        #Currently we read the entire file at once bc we need to know the file size in advance
        #If performance becomes a problem this can be improved by using seek() and write_fileobj()
        data = Path(path).read_bytes() 
        return self.load(name, address, data, perms)

    def load_memory(self, mem: SegmentMemory):
        """Copy all segments from the given SegmentMemory into this memory."""
        for seg in mem.segments:
            self.load(seg.name, seg.start, seg.read(), seg.perms)

    def allocate(self, name, size, perms=AccessType.RWX) -> Segment:
        """Automatically allocate a new segment in an unused region."""
        address = max([*(seg.end for seg in self.segments), MIN_ALLOC_ADDRESS])
        address = round_up(address, ALLOC_ROUND_SIZE)
        return self.map(name, address, size, perms)
        
    def _get_all_segments(self):
        return self._segments.values()

    def _num_segments(self):
        return len(self._segments)

    def _get_segment_by_name(self, name):
        return self._segments[name]

    def _add_segment(self, seg):
        #Call in a subclass to initialize segments
        if self.locked:
            raise MegastoneError(f'Can\'t map more segments to this Memory; copy it with load_memory()')

        if seg.name in self._segments:
            raise MegastoneError(f'Segment with name "{seg.name}" already exists')

        for old_seg in self.segments:
            if old_seg.overlaps(seg):
                raise MegastoneError('Segment overlap')

        self._segments[seg.name] = seg
        return seg

    def lock(self):
        """Lock the memory so no new Segments can be mapped."""
        self.locked = True


class SimpleMappableMemory(MappableMemory):
    """MappableMemory abstract subclass that assumes that only one segment can be written at a time."""


    @abc.abstractmethod
    def _read_segment(self, segment: Segment, offset, size):
        """Read data from the given segment at the given offset"""

    @abc.abstractmethod
    def _write_segment(self, segment: Segment, offset, data):
        """Write data to the given segment at the given offset"""

    def read_data(self, address, size):
        return b''.join(
            self._read_segment(seg, start, size)
            for seg, start, size in
            self._get_data_offsets(address, size, AccessType.R)
        )

    def write_data(self, address, data):
        offset = 0
        offsets = self._get_data_offsets(address, len(data), AccessType.W, data)
        for seg, start, size in list(offsets): #we call list() to detect any errors before starting to write
            self._write_segment(seg, start, data[offset : offset + size])
            offset += size

    def _get_data_offsets(self, address, size, atype, avalue=None):
        #We need to deal with the case of a read/write that spans two adjacent segments
        #This function yields segment, start_offset, size containing given address range
        curr_address = address
        end_address = address + size

        while curr_address < end_address:
            try:
                seg = self.segments.by_address(curr_address)
            except KeyError as e:
                raise MemoryAccessError(Access(atype, address, size, avalue), 'unmapped') from e

            start_offset = curr_address - seg.start
            end_offset = min(end_address - seg.start, seg.size)
            yield seg, start_offset, end_offset - start_offset

            curr_address = seg.start + end_offset