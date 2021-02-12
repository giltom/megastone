import bincopy

from ..execfile import ExecFile
from ..format import ExecFormat
from megastone.mem import BufferMemory


class IHEXFile(ExecFile):
    def build_fileobj(self, fileobj):
        binfile = bincopy.BinFile()
        for segment in self.mem.segments:
            binfile.add_binary(segment.read(), segment.address)
        fileobj.write(binfile.as_ihex().encode('UTF-8'))


class IHEXFormat(ExecFormat):
    """
    Raw binary file.

    Arguments:
    arch - Architecture.
    entry - entry address (default - first address).
    """
    def parse_fileobj(self, fileobj, *, arch, entry=None, **kwargs):
        binfile = bincopy.BinFile()
        binfile.add_ihex(fileobj.read().decode('UTF-8'))

        if entry is None:
            entry = binfile.minimum_address or 0

        mem = BufferMemory(arch)
        for segment in binfile.segments:
            mem.load(segment.address, segment.data)

        return IHEXFile(self, mem, entry)


FORMAT_IHEX = IHEXFormat(
    name = 'ihex',
    alt_names=['intel-hex'],
    magic = b':10',
    extensions=['.hex', '.ihex', '.h86']
)
ExecFormat.register(FORMAT_IHEX)