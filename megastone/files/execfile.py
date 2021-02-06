import io
from megastone.errors import UnsupportedError
from pathlib import Path


from megastone.mem import SegmentMemory


class ExecFile:
    """Base class for executable files."""

    def __init__(self, mem: SegmentMemory, entry: int, symbols=None):
        """
        Do not call directly - use ExecFormat.parse_xxx() methods.

        mem - SegmentMemory containing file contents.
        entry - Entry address
        symbols - Symbol dictionary, if any.
        """
        self.mem = mem
        self.arch = self.mem.arch
        self.entry = entry
        self.symbols = dict(symbols) if symbols is not None else {}

    def build_fileobj(self, fileobj):
        """Write the patched file to a file object. Not supported by all implementations."""
        raise NotImplementedError('Building is not supported for this format')

    def build_file(self, path):
        """Write the patches file to the given path. Not supported by all implementations."""
        with Path(path).open('wb') as fileobj:
            self.build_fileobj(fileobj)

    def build_bytes(self):
        """Build the file and return the built bytes. Not supported by all implementations."""
        fileobj = io.BytesIO()
        self.build_fileobj(fileobj)
        return fileobj.getvalue()