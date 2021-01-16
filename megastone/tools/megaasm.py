import argparse
import sys

from megastone import Architecture
from .util import parse_hex_int, hex_spaces

def main():
    parser = argparse.ArgumentParser(description='Quickly assemble code')
    parser.add_argument('-a', '--address', type=parse_hex_int, default=0, help='Base address (hex)')
    parser.add_argument('-b', '--binary', action='store_true', help='Output binary instead of hex')
    parser.add_argument('arch', type=Architecture.by_name, help='Architecture')
    parser.add_argument('assembly', nargs='*', help='Assemble given instructions from command line instead of stdin')
    args = parser.parse_args()
    
    if len(args.assembly) > 0:
        assembly = ' '.join(args.assembly)
    else:
        assembly = sys.stdin.read()
    code = args.arch.assemble(assembly, address=args.address)
    if not args.binary:
        code = hex_spaces(code).encode() + b'\n'
    sys.stdout.buffer.write(code)

if __name__ == '__main__':
    main()