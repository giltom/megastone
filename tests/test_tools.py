import sys
import io

from megastone.tools import megaarches, megaasm, megadisasm, megaformats
from megastone.util import hex_spaces


class Mock:
    pass

def set_stdin(monkeypatch, data):
    monkeypatch.setattr(sys, 'stdin', io.StringIO(data))

def set_stdin_bin(monkeypatch, data):
    monkeypatch.setattr(sys, 'stdin', Mock())
    sys.stdin.buffer = io.BytesIO(data)

def set_argv(monkeypatch, *args):
    monkeypatch.setattr(sys, 'argv', ['test.py', *args])


def test_megaarches(capfd):
    megaarches.main()
    output = capfd.readouterr()
    assert len(output.out) > 0
    assert len(output.err) == 0


def test_megaformats(capfd):
    megaformats.main()
    output = capfd.readouterr()
    assert len(output.out) > 0
    assert len(output.err) == 0


def test_megaasm(isa, nop, capfd, monkeypatch):
    set_stdin(monkeypatch, 'nop')
    set_argv(monkeypatch, isa.name)

    megaasm.main()
    out, err = capfd.readouterr()
    assert err == ''
    assert out.strip() == hex_spaces(nop)

def check_megaasm(capfdbinary, nop):
    megaasm.main()
    out, err = capfdbinary.readouterr()
    assert err == b''
    assert out == nop

def test_megaasm_bin(isa, nop, capfdbinary, monkeypatch):
    set_stdin(monkeypatch, 'nop')
    set_argv(monkeypatch, '-b', isa.name)
    check_megaasm(capfdbinary, nop)
    
def test_magaasm_cmdline(isa, nop, capfdbinary, monkeypatch):
    set_argv(monkeypatch, '-b', isa.name, 'nop')
    check_megaasm(capfdbinary, nop)


def check_megadisasm(capfd):
    megadisasm.main()
    out, err = capfd.readouterr()
    assert err == ''
    assert 'nop' in out.lower()

def test_megadisasm(isa, nop, capfd, monkeypatch):
    set_stdin_bin(monkeypatch, hex_spaces(nop).encode())
    set_argv(monkeypatch, isa.name)
    check_megadisasm(capfd)

def test_megadisasm_bin(isa, nop, capfd, monkeypatch):
    set_stdin_bin(monkeypatch, nop)
    set_argv(monkeypatch, '-b', isa.name)
    check_megadisasm(capfd)

def test_megadisasm_bin(isa, nop, capfd, monkeypatch):
    set_argv(monkeypatch, isa.name, hex_spaces(nop))
    check_megadisasm(capfd)