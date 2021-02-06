import warnings



class MegastoneError(Exception):
    """Base class for all custom exceptions."""
    pass

class UnsupportedError(MegastoneError):
    pass

class NotFoundError(MegastoneError):
    pass

class ParsingError(MegastoneError):
    pass

class BuildingError(MegastoneError):
    pass

class MegastoneWarning(Warning):
    """Base class for all custom warnings."""
    pass

def disable_warnings():
    """Disable all megastone warnings."""
    warnings.simplefilter('ignore', MegastoneWarning)


def warning(s):
    warnings.warn(s, MegastoneWarning, stacklevel=2)