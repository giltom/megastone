from elftools.elf import elffile

from ..execfile import ExecFile
from ..format import ExecFormat
from megastone.mem import BufferMemory


class ELFFormat(ExecFormat):
    def parse_fileobj(self, fileobj, **kwargs) -> ExecFile:
        """Parse a file object and return an ExecFile."""
        pass

class ELFFile(ExecFile):
    pass