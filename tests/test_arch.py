import platform
import pytest

from megastone import Architecture, ARCH_ARM


def test_native():
    arch = Architecture.native()
    assert platform.machine() in [arch.name, *arch.alt_names]

def test_neg_word(arch):
    assert arch.encode_word(-1) == b'\xFF' * arch.word_size

def test_decode_word(arch):
    assert arch.decode_word(b'\xFF' * arch.word_size, signed=True) == -1

def test_all_names():
    assert 'x86' in Architecture.all_names()

def test_repr():
    assert 'Architecture' in repr(ARCH_ARM)

def test_reg_names(arch):
    assert arch.regs.has_reg_name(arch.pc_reg.name)

def test_regs(arch):
    assert len(arch.regs) == len(list(arch.regs))

def test_reg_name(arch):
    assert arch.retval_reg.name in repr(arch.retval_reg)