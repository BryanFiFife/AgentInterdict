class MemoryGuardError(Exception):
    """Base class for expected MemoryGuard failures."""


class ValidationError(MemoryGuardError, ValueError):
    """Caller supplied semantically invalid input."""


class ConflictError(MemoryGuardError):
    """Requested state transition conflicts with existing state."""


class StorageError(MemoryGuardError):
    pass


class StorageBusyError(StorageError):
    pass


class StorageCorruptionError(StorageError):
    pass


class IntegrityError(MemoryGuardError):
    pass
