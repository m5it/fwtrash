"""Optional web dashboard and API."""

try:
    from fwtrash.api.server import create_app, set_pipeline_state, broadcast_stats
    __all__ = ["create_app", "set_pipeline_state", "broadcast_stats"]
except ImportError:
    # Dashboard dependencies not installed
    __all__ = []
