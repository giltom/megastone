from pathlib import Path
import io
import abc

from megastone.db import DatabaseEntry
from .execfile import ExecFile


class ExecFormat(DatabaseEntry, metaclass=abc.ABCMeta):
    """Represents an executable file format."""

    def __init__(self, *, 
        name: str,
        alt_names: tuple = (),
        magic: bytes = None, #Magic bytes for autodetection. If None, won't be autodetected.
        extensions: tuple = () #list of file extensions including '.'
    ):
        super().__init__(name, alt_names)
        self.magic = magic
        self.extensions = list(extensions)

    @abc.abstractmethod
    def parse_fileobj(self, fileobj, **kwargs) -> ExecFile:
        """Parse a file object and return an ExecFile."""
        pass

    def parse_file(self, path, **kwargs):
        """Parse the file at the given path and return an ExecFile."""
        with Path(path).open('rb') as fileobj:
            return self.parse_fileobj(fileobj, **kwargs)

    def parse_bytes(self, data, **kwargs):
        """Parse the given bytes and return an ExecFile."""
        return self.parse_fileobj(io.BytesIO(data), **kwargs)

    @staticmethod
    def by_magic(magic):
        """Return the ExecFormat with the given magic bytes, or None if not found."""
        for instance in ExecFormat.all():
            if instance.magic is not None and magic.startswith(instance.magic):
                return instance
        return None

    @staticmethod
    def by_extension(extension):
        """Return the ExecFormat with the given file extension (including the .), or None if not found."""
        extension = extension.lower()
        for instance in ExecFormat.all():
            if extension in instance.extensions:
                return instance
        return None