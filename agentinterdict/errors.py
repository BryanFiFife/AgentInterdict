class AgentInterdictError(Exception):
    """Base class for expected AgentInterdict failures."""


class ValidationError(AgentInterdictError, ValueError):
    """Caller supplied semantically invalid input."""


class ConflictError(AgentInterdictError):
    """Requested state transition conflicts with existing state."""


class StorageError(AgentInterdictError):
    pass


class StorageBusyError(StorageError):
    pass


class StorageCorruptionError(StorageError):
    pass


class IntegrityError(AgentInterdictError):
    pass
