from ..format import ExecFormat
from ..execfile import ExecFile
from .binary import FORMAT_BINARY
from megastone.util import warning


MAX_MAGIC_SIZE = 0x10


class AutoFormat(ExecFormat):
    """Meta ExecFormat that automatically determines type by magic."""

    def parse_fileobj(self, fileobj, **kwargs) -> ExecFile:
        fileobj.seek(0)
        magic = fileobj.read(MAX_MAGIC_SIZE)
        fmt = ExecFormat.by_magic(magic)
        if fmt is None:
            warning('Assuming raw binary file')
            fmt = FORMAT_BINARY

        fileobj.seek(0)
        return fmt.parse_fileobj(fileobj, **kwargs)


FORMAT_AUTO = AutoFormat(name='auto')
ExecFormat.register(FORMAT_AUTO)