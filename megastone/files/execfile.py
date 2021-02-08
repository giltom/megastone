from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

from megastone.mem import SegmentMemory

if TYPE_CHECKING:
    from .format import ExecFormat


class ExecFile:
    """Base class for executable files."""

    def __init__(self, format: ExecFormat, mem: SegmentMemory, entry: int, symbols=None):
        """
        Do not call directly - use ExecFormat.parse_xxx() methods.

        format - ExecFormat this file was created from.
        mem - SegmentMemory containing file contents.
        entry - Entry address
        symbols - Symbol dictionary, if any.
        """
        self.format = format
        self.mem = mem
        self.arch = self.mem.arch
        self.entry = entry
        self.symbols: dict[str, int] = dict(symbols) if symbols is not None else {}

    def build_fileobj(self, fileobj):
        """Write the patched file to a file object. Not supported by all implementations."""
        raise NotImplementedError('Building is not supported for this format')

    def build_file(self, path):
        """Write the patches file to the given path. Not supported by all implementations."""
        with Path(path).open('wb') as fileobj:
            self.build_fileobj(fileobj)

    def build_bytes(self) -> bytes:
        """Build the file and return the built bytes. Not supported by all implementations."""
        fileobj = io.BytesIO()
        self.build_fileobj(fileobj)
        return fileobj.getvalue()