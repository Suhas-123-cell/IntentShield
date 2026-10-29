"""IntentShield: deterministic authorization for agent tool calls."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("intentshield-mcp")
except PackageNotFoundError:  # a source checkout that is not installed
    __version__ = "0.0.0+unknown"
