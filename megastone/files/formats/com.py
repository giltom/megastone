from megastone.files import ExecFormat
from megastone.arch import ARCH_X86_16
from .binary import BinaryFormat


class COMFormat(BinaryFormat):
    base_address = 0x100

    def parse_fileobj(self, fileobj, **kwargs):
        return super().parse_fileobj(fileobj, arch=ARCH_X86_16, base=self.base_address)

FORMAT_COM = COMFormat(
    name='com',
    alt_names=['dos']
)
ExecFormat.register(FORMAT_COM)