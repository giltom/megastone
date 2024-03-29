from ..execfile import ExecFile
from ..format import ExecFormat
from megastone.mem import BufferMemory


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
    arch - Architecture.
    base - base address (default 0).
    entry - entry address (default - base address).
    """
    def parse_fileobj(self, fileobj, *, arch, base=0, entry=None, **kwargs):
        if entry is None:
            entry = base

        data = fileobj.read()
        mem = BufferMemory(arch)
        mem.load(base, data, name=SEGMENT_NAME)
        mem.lock()
        return BinaryFile(self, mem, entry)


FORMAT_BINARY = BinaryFormat(
    name='binary',
    alt_names=['bin', 'raw', 'shellcode'],
    extensions=['.bin', '.dat']
)