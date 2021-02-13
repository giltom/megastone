import logging

from .arch import *
from .mem import *
from .files import *
from .debug import *
from .emulator import Emulator
from .errors import MegastoneError, UnsupportedError, MegastoneWarning, disable_warnings, NotFoundError
from .process import ProcessMemory
from .device import Device, DeviceError, DeviceFaultError, RegisterDevice


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(name)s: %(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)