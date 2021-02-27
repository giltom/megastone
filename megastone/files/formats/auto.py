from pathlib import Path

from ..format import ExecFormat
from ..execfile import ExecFile
from .binary import FORMAT_BINARY
from megastone.errors import warning


MAX_MAGIC_SIZE = 0x10


class AutoFormat(ExecFormat):
    """Meta ExecFormat that automatically determines type by magic or file suffix."""

    def parse_fileobj(self, fileobj, **kwargs) -> ExecFile:
        fileobj.seek(0)
        fmt = self._format_from_fileobj(fileobj)
        fmt = self._fix_format(fmt)
        fileobj.seek(0)
        return fmt.parse_fileobj(fileobj, **kwargs)

    def parse_file(self, path, **kwargs):
        path = Path(path)
        
        with path.open('rb') as fileobj:
            fmt = self._format_from_fileobj(fileobj)
        if fmt is None:
            fmt = ExecFormat.by_extension(path.suffix)
        fmt = self._fix_format(fmt)
        return fmt.parse_file(path, **kwargs)
        
    def _format_from_fileobj(self, fileobj):
        magic = fileobj.read(MAX_MAGIC_SIZE)
        return ExecFormat.by_magic(magic)

    def _fix_format(self, fmt: ExecFormat) -> ExecFormat:
        if fmt is None:
            warning('Assuming raw binary file')
            return FORMAT_BINARY
        return fmt


FORMAT_AUTO = AutoFormat(name='auto')