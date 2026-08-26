"""Application exceptions safe to present at the CLI boundary."""


class FluxGateError(Exception):
    """Base class for expected FluxGate failures."""


class ConfigError(FluxGateError):
    """Configuration could not be loaded or validated."""


class StateError(FluxGateError):
    """Persistent state is invalid or cannot be safely changed."""


class IdentityError(FluxGateError):
    """The managed server signing identity is unsafe or invalid."""


class VerificationError(FluxGateError):
    """A signed artifact or bootstrap bundle failed verification."""


class PathfinderError(FluxGateError):
    """Pathfinder could not safely plan or evaluate candidates."""


class PathfinderAuthorizationError(PathfinderError):
    """An active probe target is outside the authorized candidate inventory."""


class ProviderError(FluxGateError):
    """A provider operation failed."""


class UnsupportedProviderError(ProviderError):
    """A provider exists but does not implement the requested operation."""


class CommandError(FluxGateError):
    """A system command returned an unsuccessful result."""
