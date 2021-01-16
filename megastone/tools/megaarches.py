import argparse
import sys

from megastone import Architecture

def yes_no(val):
    return 'yes' if val else 'no'

def main():
    print(f'Native: {Architecture.native().name}')
    print('Supported:')
    for arch in Architecture.all():
        alt_names = ', '.join(arch.alt_names)
        print(f'{arch.name} ({alt_names})')
        print(f'    bits: {arch.bits} endian: {arch.endian.name.lower()}')
        print(f'    KS: {yes_no(arch.ks_supported)}  CS: {yes_no(arch.cs_supported)}  UC: {yes_no(arch.uc_supported)}')


if __name__ == '__main__':
    main()