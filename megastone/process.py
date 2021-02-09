from pathlib import Path

from megastone.mem import Segment, SegmentMemory, AccessType
from megastone.arch import Architecture
        

class ProcessMemory(SegmentMemory):
    def __init__(self, pid: int):
        super().__init__(Architecture.native())
        self.pid = pid

        base_path = Path(f'/proc/{self.pid}')
        self.mem_file = (base_path / 'mem').open('w+b')
        self.maps_file = (base_path / 'maps').open('r')

    def _read(self, address, size):
        self.mem_file.seek(address)
        try:
            data = self.mem_file.read(size)
            if len(data) != size:
                raise OSError(f'Expected {size} bytes, got {len(data)}')
        except OSError as e:
            self._raise_read_error(address, size, str(e))
        return data

    def _write(self, address, data):
        self.mem_file.seek(address)
        try:
            self.mem_file.write(data)
        except OSError as e:
            self._raise_write_error(address, data, str(e))

    def _get_all_segments(self):
        self.maps_file.seek(0)
        for line in self.maps_file:
            yield self._parse_proc_maps_line(line)

    def close(self):
        self.mem_file.close()
        self.maps_file.close()

    def _parse_proc_maps_line(self, line: str):
        parts = line.split()
        address_range = parts[0]
        perms = parts[1]
        if len(parts) == 6:
            path = parts[5]
        else:
            path = '[unnamed]'

        start, _, end = address_range.partition('-')
        start = int(start, 16)
        end = int(end, 16)
        perms = AccessType.parse(perms)

        return Segment(path, start, end - start, perms, self)