from megastone import Architecture

NUM_REGS = 40

def yes_no(val):
    return 'yes' if val else 'no'

def alt_list(alts):
    if len(alts) > 0:
        return ' (' + ', '.join(alts) + ')'
    return ''

def main():
    print('Supported Architectures:\n')
    for arch in Architecture.all():
        print(f'{arch.name}{alt_list(arch.alt_names)}')
        print(f'    bits: {arch.bits}  endian: {arch.endian.name.lower()}')
        print(f'    UC: {yes_no(arch.uc_supported)}  GDB: {yes_no(arch.gdb_supported)}  ELF: {yes_no(arch.elf_supported)}')
        print(f'    instruction sets:')
        for isa in arch.isas:
            print(f'        {isa.name}{alt_list(isa.alt_names)}:  KS: {yes_no(isa.ks_supported)}  CS: {yes_no(isa.cs_supported)}')
        print()


if __name__ == '__main__':
    main()