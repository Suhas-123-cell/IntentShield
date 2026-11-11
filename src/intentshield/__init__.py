"""IntentShield: deterministic authorization for agent tool calls."""


def __getattr__(name: str) -> str:
    """``__version__``, read from the installed package's metadata the first time it is asked for: every hook imports this
    package, and reading the metadata costs about 10 ms that a hook never needs."""
    if name == "__version__":
        from importlib.metadata import PackageNotFoundError, version

        try:
            found = version("intentshield-mcp")
        except PackageNotFoundError:  # a source checkout that is not installed
            found = "0.0.0+unknown"
        globals()["__version__"] = found
        return found
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
