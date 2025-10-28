from __future__ import annotations
import logging
import time
from typing import Any, Callable

_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "apikey", "api_key"}


def _short(obj: Any) -> str:
    try:
        if obj is None or isinstance(obj, (int, float, bool, str)):
            s = repr(obj)
            return s if len(s) <= 64 else s[:61] + "..."
        # Prefer id/name hints if present
        for attr in ("id", "node_id", "name"):
            if hasattr(obj, attr):
                try:
                    val = getattr(obj, attr)
                    return f"<{obj.__class__.__name__} {attr}={val}>"
                except Exception:
                    continue
        return f"<{obj.__class__.__name__}>"
    except Exception:
        try:
            return f"<{type(obj).__name__}>"
        except Exception:
            return "<obj>"


def _short_kwargs(kwargs: dict[str, Any]) -> str:
    parts: list[str] = []
    for k, v in kwargs.items():
        if k.lower() in _SENSITIVE_KEYS:
            parts.append(f"{k}=<redacted>")
        else:
            parts.append(f"{k}={_short(v)}")
    return ", ".join(parts)


class _LoggingProxy:
    """Generic transparent proxy that logs callable attribute usage.

    - Logs at INFO: [grpc] Class.method() took X ms
    - Logs at DEBUG: arguments and return type summaries
    - Recursively wraps returned objects so nested calls (e.g., session.add_node, services.add) are traced too.
    """

    def __init__(self, target: Any, logger: logging.Logger | None = None):
        super().__setattr__("_target", target)
        super().__setattr__("_logger", logger or logging.getLogger("core_topo_gen.grpc"))

    def __repr__(self) -> str:  # pragma: no cover - best-effort repr
        t = super().__getattribute__("_target")
        return f"<_LoggingProxy for {t!r}>"

    def __getattr__(self, name: str) -> Any:
        t = super().__getattribute__("_target")
        logger: logging.Logger = super().__getattribute__("_logger")
        attr = getattr(t, name)

        if callable(attr):
            def _callable_wrapper(*args: Any, **kwargs: Any):
                cls_name = type(t).__name__
                start = time.perf_counter()
                try:
                    if logger.isEnabledFor(logging.DEBUG):
                        args_s = ", ".join(_short(a) for a in args)
                        kwargs_s = _short_kwargs(kwargs)
                        joined = ", ".join(x for x in (args_s, kwargs_s) if x)
                        logger.debug("[grpc] %s.%s(%s) -> calling", cls_name, name, joined)
                    else:
                        logger.info("[grpc] %s.%s() -> calling", cls_name, name)
                    result = attr(*args, **kwargs)
                    took_ms = (time.perf_counter() - start) * 1000.0
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("[grpc] %s.%s() ok in %.1f ms -> %s", cls_name, name, took_ms, _short(result))
                    else:
                        logger.info("[grpc] %s.%s() ok in %.1f ms", cls_name, name, took_ms)
                    return wrap_object(result, logger)
                except Exception as e:
                    took_ms = (time.perf_counter() - start) * 1000.0
                    logger.warning("[grpc] %s.%s() failed in %.1f ms: %s", cls_name, name, took_ms, e)
                    raise
            # Preserve metadata for introspection if needed
            try:
                _callable_wrapper.__name__ = getattr(attr, "__name__", name)
            except Exception:
                pass
            return _callable_wrapper

        # Non-callable attribute; wrap nested objects to trace their calls as well
        return wrap_object(attr, logger)

    # Ensure attribute setting delegates properly
    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"_target", "_logger"}:
            super().__setattr__(name, value)
            return
        setattr(super().__getattribute__("_target"), name, value)


def wrap_object(obj: Any, logger: logging.Logger | None = None) -> Any:
    """Wrap object in logging proxy when it is likely a CORE gRPC object.

    We heuristically wrap any object that is not a basic builtin type.
    """
    if obj is None or isinstance(obj, (int, float, bool, str, bytes, bytearray, tuple, list, dict, set)):
        return obj
    # Avoid double-wrapping
    if isinstance(obj, _LoggingProxy):
        return obj
    try:
        # Don't wrap modules or classes
        import types
        if isinstance(obj, (types.ModuleType, type)):
            return obj
    except Exception:
        pass
    # Don't wrap protobuf messages (google.protobuf.message.Message). Wrapping them breaks request construction.
    try:
        from google.protobuf.message import Message as _PBMessage  # type: ignore
        if isinstance(obj, _PBMessage):
            return obj
    except Exception:
        pass
    return _LoggingProxy(obj, logger)


def wrap_core_client(core_client: Any, logger: logging.Logger | None = None) -> Any:
    """Return a logging proxy over a CoreGrpcClient instance.

    Use this to ensure all subsequent gRPC calls (including nested session/service calls) are logged.
    """
    return wrap_object(core_client, logger)
