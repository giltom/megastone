from __future__ import annotations

import abc
from typing import Generic, TypeVar, Iterable, Type
import struct
import enum

from megastone.arch.architecture import Architecture
from megastone.arch.endian import Endian


T = TypeVar('T')


class NativeType(Generic[T]):
    """
    A fixed-size native type that can be used converted to and from bytes.
    
    The generic argument T is the corresponding Python type.
    """
    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The name of the type."""

    @property
    @abc.abstractmethod
    def size(self) -> int:
        """The size of the encoded value in bytes."""

    @abc.abstractmethod
    def parse(self, data: bytes) -> T:
        """
        Parse bytes into a Python value.
        
        It is guaranteed that len(data) == size
        """

    @abc.abstractmethod
    def build(self, value: T) -> bytes:
        """
        Build a python value into bytes.

        It is required that the length of the return value is self.size.
        """

    def __str__(self):
        return self.name

    def __repr__(self):
        return f'<NativeType {self.name}>'

    def __getitem__(self, length: int) -> ArrayType[T]:
        """Get an array type with the given length"""
        if not isinstance(length, int):
            raise ValueError('Type index should be an int')
        return ArrayType(self, length)

    def __or__(self, other: NativeType) -> StructType:
        """Create a struct with another type."""
        if not isinstance(other, NativeType):
            return NotImplemented
        return StructType(self, other)

    def __add__(self, other: NativeType) -> StructType:
        """Add a field to a struct. If the left hand side isn\'t a struct, a struct with to fields is returned."""
        return self | other


class VoidType(NativeType[None]):
    """Empty type that parses 0 bytes and returns None."""

    def name(self) -> str:
        return 'void'

    @property
    @abc.abstractmethod
    def size(self) -> int:
        return 0

    def parse(self, data: bytes):
        return None

    def build(self, value: None) -> bytes:
        return b''


VOID = VoidType()


class IntType(NativeType[int]):
    """NativeType subclass representing an integer."""

    def __init__(self, size: int, endian: Endian, *, signed: bool = False):
        self._size = size
        self.endian = endian
        self.signed = signed

    @classmethod
    def arch_word(cls, arch: Architecture):
        """Return the word type for the given architecture."""
        return cls(arch.word_size, arch.endian)

    @property
    def name(self):
        sign = 's' if self.signed else 'u'
        bits = self.size * 8
        if self.size == 1:
            endian = ''
        else:
            endian = self.endian.type_suffix
        return f'{sign}{bits}{endian}'

    @property
    def size(self):
        return self._size

    def parse(self, data: bytes):
        return self.endian.decode_int(data, signed=self.signed)

    def build(self, value: int):
        return self.endian.encode_int(value, self.size)


U8 = IntType(1, Endian.LITTLE)
S8 = IntType(1, Endian.LITTLE, signed=True)

U16L = IntType(2, Endian.LITTLE)
S16L = IntType(2, Endian.LITTLE, signed=True)
U16B = IntType(2, Endian.BIG)
S16B = IntType(2, Endian.BIG, signed=True)

U32L = IntType(4, Endian.LITTLE)
S32L = IntType(4, Endian.LITTLE, signed=True)
U32B = IntType(4, Endian.BIG)
S32B = IntType(4, Endian.BIG, signed=True)

U64L = IntType(8, Endian.LITTLE)
S64L = IntType(8, Endian.LITTLE, signed=True)
U64B = IntType(8, Endian.BIG)
S64B = IntType(8, Endian.BIG, signed=True)


class BoolType(NativeType[bool]):
    """1-byte value representing a boolean."""

    @property
    def name(self):
        return 'bool'

    @property
    def size(self):
        return 1
    
    @property
    def parse(self, data: bytes):
        return data[0] != 0
    
    @property
    def build(self, value: bool):
        return bytes([int(value)])


BOOL = BoolType()


class BytesType(NativeType[bytes]):
    """NativeType representing a fixed amount of bytes."""

    def __init__(self, size: int):
        self._size = size

    @property
    def name(self):
        return f'bytes[0x{self.size:X}]'

    @property
    def size(self):
        return self._size

    @property
    def parse(self, data: bytes):
        return data
    
    @property
    def build(self, value: bytes):
        if len(value) != self.size:
            raise ValueError('Incorrect value size for fixed bytes type')
        return value


class BaseStringType(NativeType[str]):
    """Base string type ABC."""

    def __init__(self, size: int, encoding: str):
        self._size = size
        self.encoding = encoding

    @property
    def name(self):
        return f'string-fixed-{self.encoding.lower()}[0x{self.size:X}]'

    @property
    def size(self):
        return self._size

    @classmethod
    def ascii(cls, size: int):
        return cls(size, 'ASCII')

    @classmethod
    def utf8(cls, size: int):
        return cls(size, 'UTF-8')

    @classmethod
    def utf16(cls, size: int, endian: Endian):
        if endian is Endian.LITTLE:
            return cls.utf16l(size)
        return cls.utf16b(size)

    @classmethod
    def utf16l(cls, size: int):
        return cls(size, 'UTF-16-LE')

    @classmethod
    def utf16b(cls, size: int):
        return cls(size, 'UTF-16-BE')


class FixedStringType(BaseStringType):
    """NativeType representing a string with a fixed size in bytes."""

    @property
    def name(self):
        return f'string-fixed-{self.encoding.lower()}[0x{self.size:X}]'

    def parse(self, data: bytes) -> str:
        return data.decode(self.encoding)

    def build(self, value: str) -> bytes:
        result = value.encode(self.encoding)
        if len(result) != self.size:
            raise ValueError('Encoded string has incorrect length')
        return result

    @classmethod
    def wchar(cls, endian: Endian):
        return cls.utf16(2, endian)


CHAR = FixedStringType.ascii(1)
WCHARL = FixedStringType.utf16l(2)
WCHARB = FixedStringType.utf16b(2)


_FLOAT_SIZE_TO_FORMAT = {
    4: 'f',
    8: 'd'
}


class FloatType(NativeType[float]):
    def __init__(self, size: int, endian: Endian):
        letter = _FLOAT_SIZE_TO_FORMAT.get(size)
        if letter is None:
            raise ValueError(f'Invalid size for float type: {size}')
        self.endian = endian
        self.struct = struct.Struct(f'{endian.struct_char}{letter}')

    @property
    def size(self):
        return self.struct.size

    @property
    def name(self):
        return f'f{self.size * 8}{self.endian.type_suffix}'

    def parse(self, data: bytes) -> float:
        return self.struct.unpack(data)[0]

    def build(self, value: float) -> bytes:
        return self.struct.pack(value)


F32L = FloatType(4, Endian.LITTLE)
F32B = FloatType(4, Endian.BIG)
F64L = FloatType(8, Endian.LITTLE)
F64B = FloatType(8, Endian.BIG)


class ArrayType(NativeType['list[T]']):
    def __init__(self, subtype: NativeType[T], length: int):
        self.subtype = subtype
        self.length = length

    @property
    def name(self) -> str:
        return f'{self.subtype}[0x{self.length:X}]'

    @property
    def size(self) -> int:
        return self.length * self.subtype.size
    
    def parse(self, data: bytes) -> list[T]:
        results = []
        for i in range(0, len(data), self.size):
            results.append(self.subtype.parse(data[i : i + self.size]))
        return results

    def build(self, values: Iterable[T]) -> bytes:
        result = bytearray()
        for value in values:
            result += self.build(value)
            
        if len(result) != self.size:
            raise ValueError('Incorrect sequence length')
        return bytes(result)


class StructType(NativeType[tuple]):
    def __init__(self, *subtypes: NativeType):
        self.subtypes = subtypes
        self._size = sum(st.size for st in self.subtypes)

    @property
    def name(self) -> str:
        types = ','.join(str(st) for st in self.subtypes)
        return f'({types})'

    @property
    def size(self) -> int:
        return self._size

    def parse(self, data: bytes) -> tuple:
        offset = 0
        results = []
        for st in self.subtypes:
            chunk = data[offset : offset + st.size]
            results.append(st.parse(chunk))
        return tuple(results)

    def build(self, value: tuple) -> bytes:
        if len(value) != len(self.subtypes):
            raise ValueError('Incorrect tuple length for struct')

        result = bytearray()
        for st, val in zip(self.subtypes, value):
            result += st.build(val)

        return bytes(result)

    def __add__(self, other: NativeType) -> StructType:
        """Add a field to a struct. If the left hand side isn\'t a struct, a struct with to fields is returned."""
        if not isinstance(other, NativeType):
            return NotImplemented
        return StructType(*self.subtypes, other)


TIntEnum = TypeVar('TIntEnum', bound='enum.IntEnum')


class EnumType(NativeType[TIntEnum]):
    def __init__(self, enum_class: Type[TIntEnum], value_type: NativeType[int]):
        self.enum_class = enum_class
        self.value_type = value_type

    def name(self) -> str:
        return f'enum-{self.enum_class.__name__}-{self.value_type}'

    def size(self) -> int:
        return self.value_type.size

    def build(self, value: TIntEnum) -> bytes:
        self.value_type.build(int(value))

    def parse(self, data: bytes) -> TIntEnum:
        return self.enum_class(self.value_type.parse(data))