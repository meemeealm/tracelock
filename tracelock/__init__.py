"""TraceLock: tamper-evident accountability layer for AI agents.

Quick start::

    import tracelock
    tl = tracelock.setup("tracelock_data", witness_url="http://witness-host:8800")
    tracer = tl.tracer()
    ...                      # your agent emits gen_ai.* spans through `tracer`
    out = tl.export()        # ends the session, writes trace.jsonl, fetches witnessed STHs
    tl.close()

``setup`` / ``init_keys`` / ``TraceLock`` are loaded lazily so that ``import tracelock``
(and the ``tracelock-verify`` command) never imports OpenTelemetry.
"""

__version__ = "0.1.0"

_LAZY = ("setup", "init_keys", "TraceLock")
__all__ = [*_LAZY, "__version__"]


def __getattr__(name: str):  # PEP 562
    if name in _LAZY:
        from . import integration

        return getattr(integration, name)
    raise AttributeError(f"module 'tracelock' has no attribute {name!r}")
