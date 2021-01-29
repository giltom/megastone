from megastone.arch.architecture import Architecture
from .execfile import ExecFile
from .format import ExecFormat
from megastone.mem import BufferMemory
from megastone.arch import Architecture


SEGMENT_NAME = 'binary'


class BinaryFile(ExecFile):
    @property
    def seg(self):
        """The (only) segment in the binary file."""
        return self.mem.segments[SEGMENT_NAME]

    def build_fileobj(self, fileobj):
        self.seg.dump_to_fileobj(fileobj)


class BinaryFormat(ExecFormat):
    """
    Raw binary file.

    Arguments:
    arch - Architecture instance or name (required).
    base - base address (default 0).
    entry - entry address (default - base address).
    """
    def parse_fileobj(self, fileobj, *, arch, base=0, entry=None, **kwargs) -> BinaryFile:
        if isinstance(arch, str):
            arch = Architecture.by_name(arch)
        if entry is None:
            entry = base

        data = fileobj.read()
        mem = BufferMemory(arch)
        mem.load(SEGMENT_NAME, base, data)
        return BinaryFile(mem, entry)


FORMAT_BINARY = BinaryFormat(
    name='binary',
    alt_names=['bin', 'raw', 'shellcode']
)