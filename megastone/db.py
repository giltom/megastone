from __future__ import annotations

from collections.abc import Iterable, Generator
from typing import TypeVar, Type

from megastone.errors import NotFoundError


T = TypeVar('T', bound='DatabaseEntry')


class DatabaseEntry:
    """
    Generic class representing an entry in an information database.
    
    Each subclass of DatabaseEntry represents a database that can be searched.
    """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._instances = []

    @classmethod
    def register(cls, instance):
        """Register a new instance of this class in the database."""
        if instance in cls._instances:
            raise RuntimeError('Instance is already registered')
        cls._instances.append(instance)
        cls._instances.sort(key=lambda i: i.name)

    @classmethod
    def by_name(cls: Type[T], name) -> T:
        """Return the instance with the given name or alt name."""
        name = name.lower()
        for instance in cls._instances:
            if instance.name == name or name in instance.alt_names:
                return instance
        raise NotFoundError(f'Unknown {cls.__name__} "{name}"')

    @classmethod
    def all(cls: Type[T]) -> Generator[T]:
        """Return an iterable of all registered instances."""
        yield from cls._instances

    def __init__(self, name: str, alt_names: Iterable[str] = ()):
        self.name = name
        self.alt_names = sorted(set(alt_names) - {name})
        
    def __repr__(self):
        return f"<{self.__class__.__name__} '{self.name}'>"