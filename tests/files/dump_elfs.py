from elftools.elf import elffile
from pathlib import Path


for path in sorted(Path('elfs').iterdir()):
    print(path)
    with path.open('rb') as file:
        elf = elffile.ELFFile(file)
        print(f'Endian: {elf.little_endian}')
        print(f'e_machine: {elf["e_machine"]!r}')
        print(f'arch: {elf.get_machine_arch()}')
        print(f'class: {elf.elfclass}')
    print()