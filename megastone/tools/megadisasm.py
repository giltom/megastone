import argparse
import sys

from megastone import Architecture
from .util import parse_hex_int

def main():
    parser = argparse.ArgumentParser(description='Quickly disassemble code')
    parser.add_argument('-a', '--address', type=parse_hex_int, default=0, help='Base address (hex)')
    parser.add_argument('-b', '--binary', action='store_true', help='Input is binary instead of hex')
    parser.add_argument('arch', type=Architecture.by_name, help='Architecture')
    parser.add_argument('code', nargs='*', help='Disassemble given hex from command line instead of stdin')
    args = parser.parse_args()
    
    if len(args.code) > 0:
        code = ''.join(args.code).encode()
    else:
        code = sys.stdin.buffer.read()
    if not args.binary:
        code = bytes.fromhex(code.decode())
    for insn in args.arch.disassemble(code, address=args.address):
        print(f'{insn.address=} {insn.size=} {insn.bytes=} {insn.mnemonic=} {insn.op_str=} {insn.operands=}')
        for op in insn.operands:
            print(f'{op.type=} {op.value=}')

if __name__ == '__main__':
    main()