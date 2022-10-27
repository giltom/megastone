from __future__ import annotations

import abc
from dataclasses import dataclass
import dataclasses
from typing import Generator, overload, Optional, Generic, TypeVar, Iterable
import itertools

import more_itertools

from megastone.arch import Endian, InstructionSet, Architecture
from megastone.util import size_to_mask

from .address_range import AddressRange
from .access import AccessType
from .data_types import NativeType
import data_types


T = TypeVar('T')


@dataclass(frozen=True)
class MemoryRegion(AddressRange):
    permissions: AccessType | None = None
    name: str | None = None


class MemoryMap(abc.ABC):
    @abc.abstractmethod
    def __iter__(self) -> Generator[MemoryRegion]:
        """Yield all memory regions in this map *sorted by address*."""

    def find_by_name(self, name: str) -> Generator[MemoryRegion]:
        """
        Yield all regions with the given name.
        
        The default implementation iterates over all regions.
        """
        for region in self:
            if region.name == name:
                yield region

    def __getitem__(self, name: str) -> MemoryRegion:
        """
        Return a region by name.
        
        Raises KeyError if multiple regions have the name.
        The default implementation iterates over all regions.
        """
        return more_itertools.one(
            self.find_by_name(name),
            KeyError('Region not found'),
            KeyError('Multiple regions with given name found')
        )

    def find_by_address(self, address: int | AddressRange) -> MemoryRegion | None:
        """
        Return the region containing the given address or range, or None if not found.
        
        The default implementation iterates over all regions.
        """
        for region in self:
            if region.contains(address):
                return region
            if region.start > address:
                break
        return None
    
    def by_address(self, address: int | AddressRange) -> MemoryRegion:
        """Return the return containing the given address or range. Raise KeyError if not found."""
        result = self.find_by_address(address)
        if result is None:
            raise KeyError('Memory region not found')
        return result


@dataclasses.dataclass(frozen=True)
class MemorySettings:
    """Default settings for reading and writing to memory."""

    endian: Optional[Endian] = None
    word_size: Optional[int] = None
    isa: Optional[InstructionSet] = None

    @classmethod
    def from_arch(cls, arch: Architecture, isa: Optional[InstructionSet] = None):
        """
        Configure memory settings according from the given architecture.
        
        if isa is not given, the architecture's default instruction set is used.
        """
        return cls(endian=arch.endian, word_size=arch.word_size, isa=isa or arch.default_isa)

    def get_endian(self, override: Endian = None) -> Endian:
        if override is not None:
            return override
        if self.endian is None:
            raise ValueError('No default endian is set')
        return self.endian

    def get_word_size(self, override: int = None) -> int:
        if override is not None:
            return override
        if self.word_size is None:
            raise ValueError('No default word size is set')
        return self.word_size

    def get_isa(self, override: InstructionSet = None) -> InstructionSet:
        if override is not None:
            return override
        if self.isa is None:
            raise ValueError('No default instruction set is set')
        return self.isa

    def get_int_type(self, size: int, endian: Endian = None, *, signed=False) -> data_types.IntType:
        return data_types.IntType(size, self.get_endian(endian), signed=signed)

    def get_word_type(self, *, signed=False) -> data_types.IntType:
        return self.get_int_type(self.get_word_size(), signed=signed)
    
    @property
    def word_type(self):
        return self.get_word_type()

    @property
    def sword_type(self):
        return self.get_word_type(signed=True)


class Memory(abc.ABC):
    """
    Abstract base class representing a memory.
    
    Instances of Memory may or may not support reading, writing, region information and creating additional regions.
    Unsupported operations should raise NotImplementedError.
    """

    @abc.abstractmethod
    def read(self, address: int, size: int) -> bytes:
        """Read bytes from memory."""
        pass

    @abc.abstractmethod
    def write(self, address: int, data: bytes):
        """Write bytes to memory."""
        pass

    @property
    def regions(self) -> MemoryMap | None:
        """
        Return this memory's map, or None if not supported.
        
        The default implementation returns None.
        """
        return None

    def map_region(self, region: MemoryRegion):
        """
        Create a new memory area according to the given MemoryRegion object.

        The default implementation raises NotImplementedError.
        """
        raise NotImplementedError

    @property
    def settings(self) -> MemorySettings:
        """
        Return the MemorySettings containing the default settings for reading and writing memory.
        
        The default implementation returns an empty MemorySettings, meaning there are no defaults.
        """
        return MemorySettings()


    def read_range(self, range: AddressRange) -> bytes:
        """Read all data in an AddressRange."""
        return self.read(range.start, range.size)

    @property
    def word_type(self):
        return self.settings.word_type

    @property
    def sword_type(self):
        return self.settings.sword_type

    def __getitem__(self, address: int | Pointer) -> Pointer:
        """Get an untyped pointer to this memory."""
        return Pointer(self, int(address))

    @property
    def pointer_type(self) -> PointerType:
        """The NativeType that represents pointers to this memory."""
        return PointerType(self)




TPointer = TypeVar('TPointer', bound='Pointer')

class Pointer:
    """Base pointer class, used to read and write memory."""
    def __init__(self, memory: Memory, address: int):
        self.memory = memory
        self.address = address

    def __repr__(self):
        return f'<{self.__class__.__name__} {self}>'

    def __str__(self):
        return f'0x{self.address:X}'

    def __int__(self):
        """Convert the pointer to an int address."""
        return self.address

    def __add__(self: TPointer, offset: int) -> TPointer:
        """
        Add an offset to a pointer.
        
        Note that this always adds in bytes regardless of the pointer type.
        """
        if not isinstance(offset, int):
            return NotImplemented
        return self.with_address(self.address + offset)

    def with_address(self: TPointer, address: int) -> TPointer:
        """
        Return a pointer of the same type, but with a different address.
        """
        return self.__class__(self.memory, address)

    def __radd__(self: TPointer, offset: int) -> TPointer:
        return self + offset

    @overload
    def __sub__(self: TPointer, offset: int) -> TPointer: ...
    @overload
    def __sub__(self, other: Pointer) -> int: ...
    def __sub__(self, value):
        """Subtract an int or pointer from a pointer."""
        if isinstance(value, int):
            return self + (-value)
        if isinstance(value, Pointer):
            return self.address - value.address
        return NotImplemented

    @property
    def _settings(self):
        return self.memory.settings

    def read_bytes(self, size: int) -> bytes:
        """Read bytes from the pointer regardless of its type."""
        return self.memory.read(self.address, size)

    def write_bytes(self, data: bytes):
        """Write bytes to the pointer regardless of its type."""
        return self.memory.write(self.address, data)


    def cast(self, type: NativeType[T]) -> FixedSizePointer[T]:
        """Cast this pointer to a fixed size pointer of the given type."""
        return FixedSizePointer(self.memory, self.address, type)

    def int(self, size: int, endian: Endian = None, *, signed = False):
        """Cast this pointer to an int pointer."""
        return self.cast(self._settings.get_int_type(size, endian, signed=signed))

    def float(self, size: int, endian: Endian = None):
        """Cast this pointer to a float pointer."""
        return self.cast(data_types.FloatType(size, self._settings.get_endian(endian)))

    def struct(self, *subtypes: NativeType):
        """Cast this pointer to a struct pointer."""
        return self.cast(data_types.StructType(*subtypes))


    @property
    def u8(self):
        return self.cast(data_types.U8)

    @property
    def s8(self):
        return self.cast(data_types.S8)


    @property
    def u16(self):
        return self.int(2)

    @property
    def u16l(self):
        return self.cast(data_types.U16L)

    @property
    def u16b(self):
        return self.cast(data_types.U16B)

    @property
    def s16(self):
        return self.int(2, signed=True)

    @property
    def s16l(self):
        return self.cast(data_types.S16L)

    @property
    def s16b(self):
        return self.cast(data_types.S16B)


    @property
    def u32(self):
        return self.int(4)

    @property
    def u32l(self):
        return self.cast(data_types.U32L)

    @property
    def u32b(self):
        return self.cast(data_types.U32B)

    @property
    def s32(self):
        return self.int(4, signed=True)

    @property
    def s32l(self):
        return self.cast(data_types.S32L)

    @property
    def s32b(self):
        return self.cast(data_types.S32B)


    @property
    def u64(self):
        return self.int(8)

    @property
    def u64l(self):
        return self.cast(data_types.U64L)

    @property
    def u64b(self):
        return self.cast(data_types.U64B)

    @property
    def s64(self):
        return self.int(8, signed=True)

    @property
    def s64l(self):
        return self.cast(data_types.S64L)

    @property
    def s64b(self):
        return self.cast(data_types.S64B)


    @property
    def f32(self):
        return self.float(4)

    @property
    def f32l(self):
        return self.cast(data_types.F32L)

    @property
    def f32b(self):
        return self.cast(data_types.F32B)


    @property
    def f64(self):
        return self.float(8)

    @property
    def f64l(self):
        return self.cast(data_types.F64L)

    @property
    def f64b(self):
        return self.cast(data_types.F64B)


    @property
    def bool(self):
        return self.cast(data_types.BOOL)


    def bytes(self, size: int):
        """Cast this pointer to a fixed-size bytes pointer."""
        return self.cast(data_types.BytesType(size))


    @property
    def word(self):
        """Cast this pointer to a word pointer."""
        return self.cast(self.memory.word_type)

    @property
    def sword(self):
        """Cast this pointer to a signed word pointer."""
        return self.cast(self.memory.sword_type)

    @property
    def pointer(self):
        """Cast this pointer to an untyped-pointer pointer."""
        return self.cast(self.memory.pointer_type)

    
    @property
    def char(self):
        return self.cast(data_types.CHAR)

    @property
    def wchar(self):
        return self.cast(data_types.FixedStringType.wchar(self._settings.get_endian()))

    @property
    def wcharl(self):
        return self.cast(data_types.WCHARL)

    @property
    def wcharb(self):
        return self.cast(data_types.WCHARB)


class SimplePointer(Pointer, Generic[T], metaclass=abc.ABCMeta):
    """
    A SimplePointer is a pointer that can be dereferenced to and from a Python type without additional information.
    
    The generic argument T is the Python type this type dereferences to.
    """
    @abc.abstractmethod
    def __call__(self) -> T:
        """Read from the pointer."""

    @abc.abstractmethod
    def write(self, value: T):
        """Write a value to the pointer."""
        pass

    def __getitem__(self, index: int) -> T:
        """
        For compatibility between pointer types, ptr[0] is equivalent to ptr() for all SimplePointers.
        
        ptr[n], ptr[n:m], etc. can only be used on fixed-size pointers.
        """
        self._check_index(index)
        return self()

    def __setitem__(self, index: int, value: T):
        """
        For compatibility between pointer types, ptr[0] = x is equivalent to ptr.write(x) for all SimplePointers.
        
        ptr[n], ptr[n:m], etc. can only be used on fixed-size pointers.
        """
        self._check_index(index)
        self.write(value)

    def _check_index(self, index):
        if index != 0:
            raise ValueError('Pointer to variable size type can only be accessed at index 0')



TFixedSizePointer = TypeVar('TFixedSizePointer', bound='FixedSizePointer')

class FixedSizePointer(SimplePointer[T]):
    """A pointer to a fixed-size type."""

    def __init__(self, memory: Memory, address: int, type: NativeType[T]):
        """Create a FixedSizePointer with the given type."""
        super().__init__(memory, address)
        self.type = type

    def with_address(self: TFixedSizePointer, address: int) -> TFixedSizePointer:
        return self.__class__(self.memory, address, self.type)

    @property
    def value_size(self) -> int:
        """The size of the pointed-to value"""
        return self.type.size

    def __call__(self) -> T:
        data = self.read_bytes(self.value_size)
        return self.type.parse(data)

    def write(self, value: T):
        data = self.type.build(value)
        self.write_bytes(data)

    def __matmul__(self: TFixedSizePointer, index: int) -> TFixedSizePointer:
        """Get a pointer to the value at the nth index of the array, e.g. address + index * value_size"""
        if not isinstance(index, int):
            return NotImplemented
        return self + (index * self.value_size)

    def _get_slice_ptr(self, s: slice):
        start = s.start if s.start is not None else 0
        if s.start is None:
            start = 0
        elif isinstance(s.start, int):
            start = s.start
        else:
            raise ValueError('Pointer slice indexes must be ints')
        
        stop = s.stop
        if stop is None:
            raise ValueError('Pointer slice must have an end index')
        if not isinstance(stop, int):
            raise ValueError('Pointer slice indexes must be ints')

        if s.step is not None and s.step != 1:
            raise ValueError('Step other than 1 is not supported')

        if stop < start:
            stop = start

        return (self @ start).array(stop - start)

    @overload
    def __getitem__(self, index: int) -> T: ...
    @overload
    def __getitem__(self, index: slice[int]) -> list[T]: ...
    def __getitem__(self, index):
        if isinstance(index, int):
            return (self @ index)()

        if isinstance(index, slice):
            return self._get_slice_ptr(index)()

        raise ValueError('Invalid pointer index')

    @overload
    def __setitem__(self, index: int, value: T): ...
    @overload
    def __setitem__(self, index: slice[int], value: Iterable[T]): ...
    def __setitem__(self, index, value):
        if isinstance(index, int):
            return (self @ index).write(value)

        if isinstance(index, slice):
            self._get_slice_ptr(index).write(value)

        raise ValueError('Invalid pointer index')

    def __str__(self):
        return f'{self.type}:0x{self.address:X}'

    def array(self, length: int):
        """Cast this pointer to a fixed-length array pointer whose elements have the type of self."""
        return self.cast(data_types.ArrayType(self.type, length))


class BasePointerType(NativeType[TPointer]):
    def __init__(self, memory: Memory):
        self.memory = memory

    @property
    def size(self):
        return self.memory.settings.get_word_size()

    @abc.abstractmethod
    def int_to_pointer(self, value: int) -> TPointer:
        """Convert an int to a pointer of this type."""
        pass

    def parse(self, data: bytes) -> TPointer:
        value = self.memory.word_type.parse(data)
        return self.int_to_pointer(value)

    def build(self, value: TPointer) -> bytes:
        return self.memory.word_type.build(int(value))

    def __call__(self, deref_type: NativeType[T]) -> FixedSizePointerType[T]:
        """Get a pointer type casted to a different deref type."""
        return FixedSizePointerType(self.memory, deref_type)


class PointerType(BasePointerType[Pointer]):
    @property
    def name(self) -> str:
        return 'pointer'
    
    def int_to_pointer(self, value: int) -> Pointer:
        return self.memory[value]


class FixedSizePointerType(BasePointerType[FixedSizePointer[T]]):
    def __init__(self, memory: Memory, deref_type: NativeType[T]):
        super().__init__(memory)
        self.deref_type = deref_type

    @property
    def name(self) -> str:
        return f'pointer({self.deref_type})'

    def int_to_pointer(self, value: int) -> FixedSizePointer[T]:
        return self.memory[value].cast(self.deref_type)