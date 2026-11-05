"""Keep DHCP/route helpers independent from the HTTP server imports."""


def __getattr__(name):
    if name == "create_app":
        from .app import create_app
        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["create_app"]
