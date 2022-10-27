from __future__ import annotations

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

    @staticmethod
    def _convert_int(address: int | AddressRange):
        if isinstance(address, AddressRange):
            return address
        return AddressRange(address, 1)
        
    def overlaps(self, other: int | AddressRange):
        """Return True if this segment overlaps other."""
        other = self._convert_int(other)
        return self.start < other.end and other.start < self.end

    def adjacent(self, other: int | AddressRange):
        """Return True if this segment overlaps other or is immediately next to it (with no gap)."""
        other = self._convert_int(other)
        return self.start <= other.end and other.start <= self.end

    def contains(self, other: int | AddressRange):
        """Return true if the given address or AddressRange is entirely contained in this range."""
        other = self._convert_int(other)
        return self.start <= other.start and other.end <= self.end

    def addresses(self, step=1):
        """Return a sequence of addresses with the given step size."""
        return range(self.start, self.end, step)