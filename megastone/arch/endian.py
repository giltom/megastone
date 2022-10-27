import enum

import unicorn
import keystone
import capstone

from megastone.util import size_to_mask


class Endian(enum.Enum):
    LITTLE = 'little'
    BIG = 'big'

    def decode_int(self, data, *, signed=False):
        """Convert bytes to int in this endian"""
        return int.from_bytes(data, self.value, signed=signed)
    
    def encode_int(self, value: int, size):
        """Convert int to bytes in this endian"""
        if value < 0:
            value = value & size_to_mask(size)
        return value.to_bytes(size, self.value)

    @property
    def ks_endian(self):
        return ENDIAN_TO_KS[self]

    @property
    def cs_endian(self):
        return ENDIAN_TO_CS[self]

    @property
    def uc_endian(self):
        return ENDIAN_TO_UC[self]

    @property
    def struct_char(self) -> str:
        return ENDIAN_TO_STRUCT_CHAR[self]

    @property
    def type_suffix(self) -> str:
        return self.name[0].lower()


ENDIAN_TO_KS = {
    Endian.LITTLE: keystone.KS_MODE_LITTLE_ENDIAN,
    Endian.BIG: keystone.KS_MODE_BIG_ENDIAN
}

ENDIAN_TO_CS = {
    Endian.LITTLE: capstone.CS_MODE_LITTLE_ENDIAN,
    Endian.BIG: capstone.CS_MODE_BIG_ENDIAN
}

ENDIAN_TO_UC = {
    Endian.LITTLE: unicorn.UC_MODE_LITTLE_ENDIAN,
    Endian.BIG: unicorn.UC_MODE_BIG_ENDIAN
}

ENDIAN_TO_STRUCT_CHAR = {
    Endian.LITTLE: '<',
    Endian.BIG: '>'
}