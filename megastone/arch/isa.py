from __future__ import annotations

from collections.abc import Iterable

import keystone
import capstone

from megastone.db import DatabaseEntry
from megastone.errors import MegastoneError
from .disasm import Instruction
from .endian import Endian


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
        alt_names: Iterable[str] = (),   #List of alternate names recognized by by_name().
        insn_alignment: int,     #Required alignment of instructions
        insn_sizes: Iterable[int],
        ks_arch: int = None,     #Keystone arch ID, None if keystone isn't supported
        ks_mode: int = 0,        #Keystone mode ID
        cs_arch: int = None,     #Capstone arch ID, None if capstone isn't supported
        cs_mode: int = 0,        #Capstone mode ID
        endian: Endian = None    #endian for automatic mode flags
    ):
        super().__init__(name, alt_names)
        self.insn_alignment = insn_alignment
        self.insn_sizes = sorted(set(insn_sizes))
        self.min_insn_size = min(self.insn_sizes)
        self.max_insn_size = max(self.insn_sizes)
        self.ks_arch = ks_arch
        self.ks_mode = ks_mode
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        if endian is not None:
            self.ks_mode |= endian.ks_endian
            self.cs_mode |= endian.cs_endian

        self.ks_supported = self.ks_arch is not None
        if self.ks_supported:
            self._ks = keystone.Ks(self.ks_arch, self.ks_mode)
        else:
            self._ks = None
        
        self.cs_supported = self.cs_arch is not None
        if self.cs_supported:
            self._cs = capstone.Cs(self.cs_arch, self.cs_mode)
            self._cs.detail = True
        else:
            self._cs = None

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

    def disassemble(self, code, address=0, *, count=None):
        """
        Disassemble the given machine code and yield assembly instructions.
        Assembly will stop at an invalid instruction.

        `address` - The base address of the code.
        `count` - Maximum number of instructions to disassemble (if not given - unlimited).
        """
        if count == 0:
            return
        if count is None:
            count = 0
        try:
            for insn in self._cs.disasm(code, offset=address, count=count):
                yield Instruction(insn)
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

    def parse_instruction(self, string, address=0):
        """Parse an instruction from a string and return an Instruction."""
        code = self.assemble(string, address)
        return self.disassemble_one(code, address)

    def address_to_pointer(self, address):
        """Convert a code address to a pointer (relevant for thumb)."""
        return address