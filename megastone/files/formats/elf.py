import abc

from elftools.elf import elffile
from elftools.elf.constants import P_FLAGS, SH_FLAGS

from ..execfile import ExecFile
from ..format import ExecFormat
from megastone.mem import Access, AccessType, Segment, SimpleSegmentMemory, DictSegmentMemory, MemoryAccessError
from megastone.arch import Architecture
from megastone.errors import UnsupportedError


SEGMENT_FLAG_TO_ACCESS_TYPE = {
    P_FLAGS.PF_R: AccessType.R,
    P_FLAGS.PF_W: AccessType.W,
    P_FLAGS.PF_X: AccessType.X
}

SECTION_FLAG_TO_ACCESS_TYPE = {
    SH_FLAGS.SHF_ALLOC: AccessType.R,
    SH_FLAGS.SHF_WRITE: AccessType.W,
    SH_FLAGS.SHF_EXECINSTR: AccessType.X
}


class BaseELFSegment(Segment, metaclass=abc.ABCMeta):
    """Base class for ELF segments."""

    @property
    @abc.abstractmethod
    def file_offset(self):
        """Offset of the segment in the file."""
        pass

    @property
    @abc.abstractmethod
    def file_size(self):
        """Size of the segment in the file. The segment is padded with 0s in memory up to its memory size."""
        pass


class ELFSectionSegment(BaseELFSegment):
    def __init__(self, mem, section: elffile.Section):
        if section.compressed:
            raise UnsupportedError('ELF compression is not supported')

        perms = convert_flags(SECTION_FLAG_TO_ACCESS_TYPE, section['sh_flags'])
        super().__init__(section.name, section['sh_addr'], section.data_size, perms, mem)

        self._section = section

    @property
    def file_offset(self):
        return self._section['sh_offset']

    @property
    def file_size(self):
        if self._section['sh_type'] == 'SHT_NOBITS':
            return 0
        return self.size


class ELFSegmentSegment(BaseELFSegment):
    def __init__(self, name, mem, elf_segment: elffile.Segment):
        perms = convert_flags(SEGMENT_FLAG_TO_ACCESS_TYPE, elf_segment['p_flags'])
        super().__init__(name, elf_segment['p_vaddr'], elf_segment['p_memsz'], perms, mem)

        self._segment = elf_segment

    @property
    def file_offset(self):
        return self._segment['p_offset']

    @property
    def file_size(self):
        return self._segment['p_filesz']


class BaseELFMemory(DictSegmentMemory, SimpleSegmentMemory):
    def __init__(self, elf: elffile.ELFFile):
        super().__init__(Architecture.by_name(elf.get_machine_arch()))

        for segment in self._parse_segments(elf):
            self._add_segment(segment)

        elf.stream.seek(0)
        self._buffer = bytearray(elf.stream.read())
        
    @abc.abstractmethod
    def _parse_segments(self, elf: elffile.ELFFile):
        pass

    def _read_segment(self, segment: BaseELFSegment, offset, size):
        data = b''
        end_offset = offset + size

        if offset < segment.file_size:
            data_end_offset = min(end_offset, segment.file_size)
            data += self._buffer[segment.file_offset + offset : segment.file_offset + data_end_offset]
        
        if end_offset > segment.file_size:
            data += bytes(end_offset - segment.file_size)

        return data

    def _write_segment(self, segment: BaseELFSegment, offset, data):
        end_offset = offset + len(data)
        if end_offset > segment.file_size:
            error_size = end_offset - segment.file_size
            raise MemoryAccessError(
                Access(
                    type=AccessType.W,
                    address=segment.address + segment.file_size,
                    size=error_size,
                    value=data[-error_size:]
                ),
                'memory region is not in the physical ELF file'
            )

        self._buffer[segment.file_offset + offset : segment.file_offset + end_offset] = data


class SectionELFMemory(BaseELFMemory):
    def _parse_segments(self, elf: elffile.ELFFile):
        for section in elf.iter_sections():
            if section['sh_flags'] & SH_FLAGS.SHF_ALLOC:
                yield ELFSectionSegment(self, section)


class SegmentELFMemory(BaseELFMemory):
    def _parse_segments(self, elf: elffile.ELFFile):
        for i, segment in enumerate(elf.iter_segments()):
            if segment['p_type'] == 'PT_LOAD':
                yield ELFSegmentSegment(f'seg{i}', self, segment)


def convert_flags(mapping, flags):
    result = AccessType.NONE
    for key, value in mapping.items():
        if flags & key:
            result |= value
    return result


def get_symtab_section(elf: elffile.ELFFile):
    for section in elf.iter_sections():
        if isinstance(section, elffile.SymbolTableSection):
            return section
    return None


def parse_elf_symbols(elf: elffile.ELFFile):
    section = get_symtab_section(elf)
    if section is None:
        return {}
    return {sym.name: sym['st_value'] for sym in section.iter_symbols() if sym.name is not None}


class ELFFormat(ExecFormat):
    def parse_fileobj(self, fileobj, *, use_segments=False, **kwargs) -> ExecFile:
        elf = elffile.ELFFile(fileobj)
        entry = elf['e_entry']
        symbols = parse_elf_symbols(elf)
        if use_segments:
            mem = SegmentELFMemory(elf)
        else:
            mem = SectionELFMemory(elf)
        return ELFFile(self, mem, entry, symbols)


class ELFFile(ExecFile):
    def build_fileobj(self, fileobj):
        fileobj.write(self.mem._buffer)


FORMAT_ELF = ELFFormat(
    name='elf',
    magic=b'\x7fELF',
    extensions=['.elf', '.o']
)
ExecFormat.register(FORMAT_ELF)