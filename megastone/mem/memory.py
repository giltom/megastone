import abc
from pathlib import Path

from megastone import Architecture, Assembler, Disassembler


class Memory(abc.ABC):
    """Abstract class representing a memory space."""

    def __init__(self, arch: Architecture, *, verbose=False):
        self.arch = arch
        self._assembler = Assembler(arch)
        self._disassembler = Disassembler(arch)
        self.verbose = verbose

    @abc.abstractmethod
    def write_data(self, address, data):
        """
        Write bytes at the given address. Raise NotImplemented if the memory is read-only.
        
        Override in a subclass - don't call this directly.
        """
        pass

    @abc.abstractmethod
    def read_data(self, address, size):
        """
        Read bytes from the given address.
        
        Override in a subclass - don't call this directly.
        """
        pass

    def log(self, s):
        """Log a message if in verbose mode"""
        if self.verbose:
            print(f'[+] {s}')

    def write(self, address, data):
        self.log(f'Write 0x{len(data):X} bytes to 0x{address:X}')
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
    
    def write_code(self, address, assembly):
        """Assemble the given instructions and write them to the address."""
        code = self._assembler.assemble(assembly, address)
        self.log(f'Assemble "{assembly}" => {code.hex().upper()}')
        self.write(address, code)
    
    def disassemble_one(self, address):
        """Disassemble the instruction at the given address and return it."""
        code = self.read(address, self.arch.max_insn_size)
        return self._disassembler.disassemble_one(code, address)
    
    def disassemble(self, address, count):
        """Disassemble `count` instructions at the given address and return an iterator over the disassembled instructions."""
        for _ in range(count):
            inst = self.disassemble_one(address)
            yield inst
            address += inst.size

    def write_file(self, address, path):
        """Write the file at the given path to memory."""
        data = Path(path).read_bytes()
        self.write(address, data)

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


class MappableMemory(Memory):
    """Abstract Memory subclass that supports allocating memory at arbitrary addresses."""

    @abc.abstractmethod
    def map(self, address, size):
        """Allocate new memory, initialized to 0, at the given address range."""
        pass

    def load(self, address, data):
        """Shorthand for map() followed by write()."""
        self.map(address, len(data))
        self.write(address, data)
    
    def load_file(self, address, path):
        """Load the file at the given path."""
        data = Path(path).read_bytes()
        self.load(address, data)