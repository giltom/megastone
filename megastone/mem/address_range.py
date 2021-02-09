from dataclasses import dataclass


@dataclass(frozen=True)
class AddressRange:
    """Represents a range of addresses"""

    start: int
    size: int

    @property
    def end(self):
        return self.start + self.size

    @property
    def address(self):
        """Alias of `start`."""
        return self.start

    def overlaps(self, other):
        """Return True if this segment overlaps other."""
        return self.start < other.end and other.start < self.end

    def adjacent(self, other):
        """Return True if this segment overlaps other or is immediately next to it (with no gap)."""
        return self.start <= other.end and other.start <= self.end

    def __contains__(self, address):
        if not isinstance(address, int):
            return False
        return self.start <= address < self.end

    def addresses(self, step=1):
        """Return a sequence of addresses with the given step size."""
        return range(self.start, self.end, step)