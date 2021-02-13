from __future__ import annotations

from xml.etree import ElementTree
from pathlib import Path
import dataclasses
import functools
import io
import logging


from megastone.arch import Architecture, BaseRegisterState
from .connection import ParsingError, parse_hex, encode_hex


PATH = Path(__file__).parent

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class GDBRegister:
    name: str
    number: int
    size: int


@functools.lru_cache()
def load_gdb_regs(arch: Architecture):
    """Load the GDB registers for the given architecture and return a list of GDBRegister objects."""
    xml_path = PATH / 'xml' / f'{arch.name}.xml'
    logger.debug(f'loading register definitions from {xml_path}')
    doc = ElementTree.parse(xml_path)

    regs = []
    next_regnum = 0
    for elem in doc.findall('reg'):
        name = elem.attrib['name']
        bitsize = int(elem.attrib['bitsize'])
        regnum = int(elem.attrib.get('regnum', next_regnum))
        regs.append(GDBRegister(name, regnum, bitsize//8))
        next_regnum = regnum + 1

    logger.debug(f'loaded {len(regs)} registers')
    return regs