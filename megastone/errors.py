import warnings



class MegastoneError(Exception):
    """Base class for all custom exceptions."""
    pass

class UnsupportedError(MegastoneError):
    """Exception for unsupported features."""
    pass

class MegastoneWarning(Warning):
    """Base class for all custom warnings."""
    pass

def disable_warnings():
    """Disable all megastone warnings."""
    warnings.simplefilter('ignore', MegastoneWarning)


def warning(s):
    warnings.warn(s, MegastoneWarning, stacklevel=2)