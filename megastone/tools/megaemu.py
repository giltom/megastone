import argparse
import logging

import megastone as ms


def main():
    parser = argparse.ArgumentParser(description='Start a GDBServer for emulating an executable')
    parser.add_argument('-f', '--format', default='auto', help='exec format (default auto. run megaformats for list)')
    parser.add_argument('-a', '--arch', type=ms.Architecture.by_name, help='Architecture for binary files')
    parser.add_argument('-b', '--base', type=int, default=0, help='Base address for binary files (default 0)')
    parser.add_argument('-e', '--entry', type=int, help='Entry address for binary files (default=base)')
    parser.add_argument('-p', '--port', type=int, default=1234, help='Port (default 1234)')
    parser.add_argument('-i', '--interface', default='localhost', help='Listen interface (default localhost)')
    parser.add_argument('-l', '--loglevel', default='info', help='Log level (default info)')
    parser.add_argument('--persistent', action='store_true', help='Persistent server (dont exit on detach)')
    parser.add_argument('file', help='file to load')
    args = parser.parse_args()

    level = getattr(logging, args.loglevel.upper())
    ms.logger.setLevel(level)
    
    file = ms.load_file(args.file, format=args.format, arch=args.arch, base=args.base, entry=args.entry, use_segments=True)
    emu = ms.Emulator.from_execfile(file)
    server = ms.GDBServer(emu, port=args.port, host=args.interface)
    try:
        server.run(persistent=args.persistent)
    except KeyboardInterrupt:
        print('Exiting')


if __name__ == '__main__':
    main()