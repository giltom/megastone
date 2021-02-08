from __future__ import annotations
import typing

import keystone
import capstone

from megastone.db import DatabaseEntry
from megastone.errors import MegastoneError


if typing.TYPE_CHECKING:
    from .architecture import Architecture


class AssemblyError(MegastoneError):
    pass


class DisassemblyError(MegastoneError):
    pass


class InstructionSet(DatabaseEntry):
    """
    Represents an instruction set for assembling/disassembling instructions.

    Most architectures have exactly one instruction set, but some have more (e.g. ARM/THUMB)
    """

    def __init__(self, *,
        name: str,               #Name of architecture. Should be lowercase.
        alt_names: tuple = (),   #List of alternate names recognized by by_name().
        insn_alignment: int,     #Required alignment of instructions
        min_insn_size: int,      #Size of smallest instruction
        max_insn_size: int,      #Size of largest instruction
        ks_arch: int = None,     #Keystone arch ID, None if keystone isn't supported
        ks_mode: int = 0,        #Keystone mode ID
        cs_arch: int = None,     #Capstone arch ID, None if capstone isn't supported
        cs_mode: int = 0        #Capstone mode ID
    ):
        super().__init__(name, alt_names)
        self.insn_alignment = insn_alignment
        self.min_insn_size = min_insn_size
        self.max_insn_size = max_insn_size
        self.ks_arch = ks_arch
        self.ks_mode = ks_mode
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        self.arch: Architecture = None #Will be set by Architecture when added

        self._ks = None
        if self.ks_supported:
            self._ks = keystone.Ks(self.ks_arch, self.ks_mode)
        
        if self.cs_supported:
            self._cs = capstone.Cs(self.cs_arch, self.cs_mode)
            self._cs.detail = True

    @property
    def ks_supported(self):
        return self.ks_arch is not None

    @property
    def cs_supported(self):
        return self.cs_arch is not None

    def assemble(self, assembly, address=0) -> bytes:
        """
        Assemble the given instructions and return the assembled bytes.

        `address`, if given, is the base address of the instructions.
        Raise an `AssemblyError` if the assembly is invalid.
        """
        try:
            data, _ = self._ks.asm(assembly, addr=address, as_bytes=True)
        except keystone.KsError as e:
            raise AssemblyError(f'Assembly failed: {str(e)}') from e
        if data is None:
            raise AssemblyError('Invalid assembly')
        return data

    def disassemble(self, code, address=0, *, count=0):
        """
        Disassemble the given machine code and yield assembly instructions.
        Assembly will stop at an invalid instruction.

        `address` - The base address of the code.
        `count` - Maximum number of instructions to disassemble (if not given - unlimited).
        """
        try:
            yield from self._cs.disasm(code, offset=address, count=count)
        except capstone.CsError as e:
            raise DisassemblyError(f'Failed to disassemble: {str(e)}') from e

    def disassemble_one(self, code, address=0):
        """
        Disassemble and return the first instruction in the given code.
        
        Raise a `DisassemblyError` if the instruction is invalid.
        """
        result = list(self.disassemble(code, address=address, count=1))
        if len(result) == 0:
            raise DisassemblyError('Invalid instruction')
        return result[0]

    def address_to_pointer(self, address):
        """Convert a code address to a pointer (relevant for thumb)."""
        return address