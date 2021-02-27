from __future__ import annotations

from collections.abc import Iterable, Generator
from dataclasses import dataclass
from typing import TypeVar, Type, Generic

from megastone.errors import NotFoundError


T = TypeVar('T', bound='DatabaseEntry')


class Database(Generic[T]):
    def __init__(self, parent: Database[T] = None):
        self._entries: list[T] = []
        self._mapping: dict[str, T] = {}
        self._parent = parent

    def register(self, entry: T):
        if entry in self._entries:
            raise RuntimeError('Instance is already registered')
        for name in entry.all_names:
            if name in self._mapping:
                raise RuntimeError(f'Duplicate entry name: {name}')

        self._entries.append(entry)
        self._entries.sort(key=lambda e: e.name)
        for name in entry.all_names:
            self._mapping[name] = entry

        if self._parent is not None:
            self._parent.register(entry)

    def get(self, name: str):
        return self._mapping.get(name.lower())

    def all(self):
        yield from self._entries


class DatabaseEntry:
    """
    Generic class representing an entry in an information database.
    
    Each subclass of DatabaseEntry represents a database that can be searched.
    """

    _db: Database

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        base = cls.__bases__[0]
        if base is DatabaseEntry:
            cls._db = Database()
        else:
            cls._db = Database(base._db)

    @classmethod
    def by_name(cls: Type[T], name) -> T:
        """Return the instance with the given name or alt name."""
        instance = cls._db.get(name)
        if instance is None:
            raise NotFoundError(f'Unknown {cls.__name__} "{name}"') from None
        return instance

    @classmethod
    def all(cls: Type[T]) -> Generator[T]:
        """Return an iterable of all registered instances."""
        return cls._db.all()

    def __init__(self, name: str, alt_names: Iterable[str] = ()):
        self.name = name.lower()
        alt_names = set(name.lower() for name in alt_names)
        self.alt_names = sorted(alt_names - {self.name})
        self.all_names = sorted(alt_names | {self.name})

        self._db.register(self)
        
    def __repr__(self):
        return f"<{self.__class__.__name__} '{self.name}'>"