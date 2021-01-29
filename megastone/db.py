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
        cls._instances.append(instance)

    @classmethod
    def by_name(cls, name):
        """Return the instance with the given name or alt name."""
        name = name.lower()
        for instance in cls._instances:
            if instance.name == name or name in instance.alt_names:
                return instance
        raise ValueError(f'Unknown {cls.__name__} "{name}"')

    @classmethod
    def all(cls):
        """Return an iterable of all registered instances."""
        yield from cls._instances
    
    @classmethod
    def all_names(cls):
        """Return an interable of all names of registered instances."""
        for instance in cls.all():
            yield instance.name

    def __init__(self, name, alt_names=()):
        self.name = name
        self.alt_names = list(alt_names)
        
    def __repr__(self):
        return f"<{self.__class__.__name__} '{self.name}'>"