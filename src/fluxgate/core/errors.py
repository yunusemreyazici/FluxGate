"""Application exceptions safe to present at the CLI boundary."""


class FluxGateError(Exception):
    """Base class for expected FluxGate failures."""


class ConfigError(FluxGateError):
    """Configuration could not be loaded or validated."""


class StateError(FluxGateError):
    """Persistent state is invalid or cannot be safely changed."""


class ProviderError(FluxGateError):
    """A provider operation failed."""


class UnsupportedProviderError(ProviderError):
    """A provider exists but does not implement the requested operation."""


class CommandError(FluxGateError):
    """A system command returned an unsuccessful result."""
