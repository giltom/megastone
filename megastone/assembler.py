import keystone

from megastone.arch import InstructionSet
from megastone.errors import MegastoneError, UnsupportedError


class AssemblyError(MegastoneError):
    pass


class UndefinedSymbolError(AssemblyError):
    def __init__(self, symbol):
        super().__init__(f'Symbol not defined: {symbol}')
        self.symbol = symbol


class Assembler:
    """
    Main assembler class used to assemble code.
    
    The `symbols` property is a dictionary of external symbols.
    You can modify this dict to change the Assembler's symbols.
    """

    def __init__(self, isa: InstructionSet, symbols=None):
        """
        Create an assembler.

        `isa` - InstructionSet.
        `symbols` - Dictionary of external symbols.
        """
        if not isa.ks_supported:
            raise UnsupportedError('ISA is not supported by keystone')

        self.isa = isa
        self.symbols = {} if symbols is None else dict(symbols)

        self._ks = keystone.Ks(isa.ks_arch, isa.ks_mode)
        #self._ks.sym_resolver = self._sym_resolver
        self._missing_symbol = None

    def assemble(self, assembly, address=0) -> bytes:
        """
        Assemble the given instructions and return the assembled bytes.

        `address`, if given, is the base address of the instructions.
        """
        try:
            data, _ = self._ks.asm(assembly, addr=address, as_bytes=True)
        except keystone.KsError as e:
            self._handle_ks_error(e)
        if data is None:
            raise AssemblyError('Invalid assembly')
        return data

    def _sym_resolver(self, symbol, value):
        print('resolver')
        try:
            symbol = symbol.decode()
        except UnicodeDecodeError:
            self._missing_symbol = None
            return False

        if symbol not in self.symbols:
            self._missing_symbol = symbol
            return False

        value.contents.value = self.symbols[symbol]
        return True

    def _handle_ks_error(self, e):
        if e.errno == keystone.KS_ERR_ASM_SYMBOL_MISSING:
            raise UndefinedSymbolError(self._missing_symbol)
        raise AssemblyError(f'Failed to assemble: {str(e)}')


def assemble(isa, assembly, address=0):
    """
    Convenience assembly function.

    Slower than using the Assembler class.
    """
    return Assembler(isa).assemble(assembly, address)