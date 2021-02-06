from elftools.elf import elffile
from elftools.elf.constants import P_FLAGS, SH_FLAGS

from ..execfile import ExecFile
from ..format import ExecFormat
from megastone.mem import BufferMemory, AccessType, MappableMemory
from megastone.arch import Architecture
from megastone.util import round_up, round_down


SEGMENT_FLAG_TO_ACCESS_TYPE = {
    P_FLAGS.PF_R: AccessType.R,
    P_FLAGS.PF_W: AccessType.W,
    P_FLAGS.PF_X: AccessType.X
}

SECTION_FLAGS_TO_ACCESS_TYPE = {
    SH_FLAGS.SHF_ALLOC: AccessType.R,
    SH_FLAGS.SHF_WRITE: AccessType.W,
    SH_FLAGS.SHF_EXECINSTR: AccessType.X
}
PAGE_SIZE = 0x1000


def convert_flags(mapping, flags):
    result = AccessType.NONE
    for key, value in mapping.items():
        if flags & key:
            result |= value
    return result


def load_elf_segments(mem: MappableMemory, elf: elffile.ELFFile):
    for i, segment in enumerate(elf.iter_segments()):
        if segment['p_type'] != 'PT_LOAD':
            continue

        start = segment['p_vaddr']
        end = start + segment['p_memsz']

        start = round_down(start, PAGE_SIZE)
        end = round_up(end, PAGE_SIZE)
        perms = convert_flags(SEGMENT_FLAG_TO_ACCESS_TYPE, segment['p_flags'])
        mem.map(f'seg{i}', start, end - start, perms)
        mem.write(start, segment.data())


def load_elf_sections(mem: MappableMemory, elf: elffile.ELFFile):
    for section in elf.iter_sections():
        flags = section['sh_flags']
        if not flags & SH_FLAGS.SHF_ALLOC:
            continue

        perms = convert_flags(SECTION_FLAGS_TO_ACCESS_TYPE, flags)
        mem.load(section.name, section['sh_addr'], section.data(), perms)


def get_symtab_section(elf: elffile.ELFFile):
    for section in elf.iter_sections():
        if isinstance(section, elffile.SymbolTableSection):
            return section
    return None


def load_elf_symbols(elf: elffile.ELFFile):
    section = get_symtab_section(elf)
    if section is None:
        return {}
    return {sym.name: sym['st_value'] for sym in section.iter_symbols() if sym.name is not None}


class ELFFormat(ExecFormat):
    def parse_fileobj(self, fileobj, *, use_segments=False, **kwargs) -> ExecFile:
        elf = elffile.ELFFile(fileobj)
        arch = Architecture.by_name(elf.get_machine_arch())
        mem = BufferMemory(arch)

        if use_segments:
            load_elf_segments(mem, elf)
        else:
            load_elf_sections(mem, elf)
        mem.lock()

        symbols = load_elf_symbols(elf)

        return ELFFile(mem, elf['e_entry'], symbols)


#We create use class just so users can check if they got an elf
class ELFFile(ExecFile):
    pass


FORMAT_ELF = ELFFormat(
    name='elf',
    magic=b'\x7fELF',
    extensions=['elf', 'o']
)
ExecFormat.register(FORMAT_ELF)