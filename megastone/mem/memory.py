from __future__ import annotations

import abc
from pathlib import Path
import shutil

from megastone.arch import Architecture, InstructionSet, DisassemblyError
from .errors import MemoryAccessError
from .memory_io import StreamMemoryIO, MemoryIO
from .access import AccessType, Access


class Memory(abc.ABC):
    """Abstract class representing a memory space."""

    DISASSEMBLY_CHUNK_SIZE = 0x400

    def __init__(self, arch: Architecture):
        self.arch = arch
        self.default_isa: InstructionSet = arch.default_isa
        self.verbose = False

    @abc.abstractmethod
    def _write(self, address, data):
        """
        Write bytes at the given address.
        
        Override in a subclass - don't call this directly.
        """
        pass

    @abc.abstractmethod
    def _read(self, address, size) -> bytes:
        """
        Read bytes from the given address.
        
        Override in a subclass - don't call this directly.
        """
        pass

    def read(self, address, size):
        return self._read(address, size)

    def write(self, address, data):
        if self.verbose:
            print(f'Write 0x{len(data):X} bytes to 0x{address:X}')
        self._write(address, data)

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
        """Assemble the given instructions and write them to the address. Return the code size."""
        isa = self._fix_isa(isa)

        code = isa.assemble(assembly, address)
        if self.verbose:
            print(f'Assemble "{assembly}" => {code.hex().upper()}')
        self.write(address, code)
        return len(code)

    def disassemble_one(self, address, isa=None):
        """Disassemble the instruction at the given address and return it."""
        return self.disassemble_n(address, 1, isa=isa)[0]

    def disassemble_n(self, address, num, isa=None):
        """
        Disassemble and return a list of exactly `num` instructions at `address`.
        
        Raise a DisassemblyError if there are less valid instructions available.
        """
        insns = list(self.disassemble(address, max_num=num, isa=isa))
        if len(insns) != num:
            if len(insns) == 0:
                last = address
            else:
                last = insns[-1].address + insns[-1].size
            raise DisassemblyError(f'Invalid instruction at 0x{last:X}')
        return insns

    def disassemble(self, address, max_num=None, isa=None):
        """
        Disassemble at the given address and yield the disassembled instructions, until an invalid instruction is reached.

        if `count` is not None, it specifies the maximum number of instructions to disassemble.
        """
        isa = self._fix_isa(isa)
        max_size = self._get_max_read_size(address)

        if max_size is None:
            yield from self._disassemble_unknown_size(address, max_num, isa)
        else:
            yield from self._disassemble_known_size(address, max_size, max_num, isa)

    def _disassemble_known_size(self, address, max_size, max_num, isa: InstructionSet):
        if max_num is None:
            insn_limit = float('inf')
        else:
            insn_limit = max_num

        count = 0
        offset = 0
        while count < insn_limit and offset <= max_size - isa.min_insn_size:
            insns_remaining = insn_limit - count
            size_remaining = max_size - offset
            curr_address = address + offset

            read_size = min(size_remaining, insns_remaining * isa.max_insn_size, self.DISASSEMBLY_CHUNK_SIZE)
            chunk = self.read(curr_address, read_size)

            total_size = 0
            if max_num is None:
                curr_max = None
            else:
                curr_max = insns_remaining
            for insn in isa.disassemble(chunk, curr_address, count=curr_max):
                yield insn
                total_size += insn.size
                count += 1

            if read_size == size_remaining or read_size - total_size >= isa.max_insn_size:
                #too many bytes remain - we must have hit an invalid instruction
                break

            offset += total_size

    def _disassemble_unknown_size(self, address, max_num, isa):
        count = 0
        while max_num is None or count < max_num:
            try:
                insn = self._disassemble_one_unknown_size(address, isa)
            except DisassemblyError:
                break
            except MemoryAccessError:
                if count == 0:
                    raise
                break

            yield insn
            address += insn.size
            count += 1

    def _disassemble_one_unknown_size(self, address, isa: InstructionSet):
        for size in reversed(isa.insn_sizes):
            try:
                data = self.read(address, size)
            except MemoryAccessError:
                if size == isa.min_insn_size:
                    raise
            else:
                return isa.disassemble_one(data, address)
        assert False      

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

    def search(self, start: int, size, value, *, alignment=1):
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

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        """Perform any neede cleanup."""
        pass

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

    def _get_max_read_size(self, address):
        #Return maximum amount of bytes that can be read from address, or None if not known
        return None
    
    def _raise_read_error(self, address, size, reason):
        raise MemoryAccessError(Access(AccessType.R, address, size), reason) from None

    def _raise_write_error(self, address, data, reason):
        raise MemoryAccessError(Access(AccessType.W, address, len(data), data), reason) from None