import gdb


from megastone.errors import UnsupportedError, MegastoneError
from megastone.arch import Architecture, RegisterState, Endian
from megastone.mem import Memory, MemoryReadError, MemoryWriteError
from megastone.debug import Debugger


def execute(cmd) -> str:
    return gdb.execute(cmd, to_string=True, from_tty=False)


def get_symbol(sym):
    return int(gdb.parse_and_eval(f'&{sym}'))


def get_endian():
    result = execute('show endian')
    if 'little endian' in result:
        return Endian.LITTLE
    if 'big endian' in result:
        return Endian.BIG
    raise MegastoneError(f'Invalid GDB endian: {result}') #pragma: no cover


def set_endian(endian):
    execute(f'set endian {endian.name.lower()}')


def get_arch():
    name = gdb.selected_inferior().architecture().name()
    endian = get_endian()
    #Need to sort by length bc the GDB name of some arches is a prefix of another name
    arches = sorted([arch for arch in Architecture.all() if arch.gdb_supported], 
        key=lambda arch: len(arch.gdb_name), reverse=True)
    for arch in arches:
        if arch.endian == endian and name.startswith(arch.gdb_name):
            return arch
    raise UnsupportedError(f'Unsupported GDB architecture: {name}, endian={endian.name}')


def is_megastone_server():
    return 'true' in execute('monitor megastone')


def auto_config_endian():
    endian_name = execute('monitor endian').strip()
    try:
        endian = Endian[endian_name]
    except KeyError:
        raise MegastoneError('Server isn\'t a Megastone server') from None
    set_endian(endian)
    return endian


class GDBRegisterState(RegisterState):
    def __init__(self):
        super().__init__(get_arch())

    def read(self, reg) -> int:
        return int(gdb.parse_and_eval(f'${reg.name}')) & self._arch.word_mask

    def write(self, reg, value):
        value &= self._arch.word_mask
        execute(f'set ${reg.name} = (unsigned long)0x{value:X}L')


class GDBMemory(Memory):
    def __init__(self):
        super().__init__(get_arch())

    def _read(self, address, size):
        try:
            return bytes(gdb.selected_inferior().read_memory(address, size))
        except gdb.MemoryError as e:
            raise MemoryReadError(address, size, str(e)) from e
    
    def _write(self, address, data):
        try:
            gdb.selected_inferior().write_memory(address, data)
        except gdb.MemoryError as e:
            raise MemoryWriteError(address, data, str(e)) from e


class GDBDebugger(Debugger):
    def __init__(self):
        super().__init__(GDBMemory(), GDBRegisterState())

    def _run(self, count=None):
        if count is None:
            execute('continue')
        else:
            execute(f'stepi 0d{count}')

    def _add_hook(self, hook):
        raise UnsupportedError('Hooks aren\'t currently supported for GDB')

    def remove_hook(self, hook):
        raise UnsupportedError('Hooks aren\'t currently supported for GDB')