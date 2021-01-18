import argparse
import sys

from megastone import Architecture

NUM_REGS = 40

def yes_no(val):
    return 'yes' if val else 'no'

def main():
    print(f'Native: {Architecture.native().name}')
    print('Supported:\n')
    for arch in Architecture.all():
        alt_names = ', '.join(arch.alt_names)
        print(f'{arch.name} ({alt_names})')
        print(f'    bits: {arch.bits}  endian: {arch.endian.name.lower()}  registers: {len(arch.regs)}')
        print(f'    instruction sets:')
        for isa in arch.isas:
            alt_names = ', '.join(isa.alt_names)
            print(f'        {isa.name} ({alt_names}):  KS: {yes_no(isa.ks_supported)}  CS: {yes_no(isa.cs_supported)}  UC: {yes_no(isa.uc_supported)}')
        print()


if __name__ == '__main__':
    main()