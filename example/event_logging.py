"""Run-time visibility for pydantic-ai agent runs: tool events go to the log,
the final response to stdout."""

import logging
from collections.abc import AsyncIterable, Awaitable, Callable
from typing import Any

logger = logging.getLogger("read_write_shell_agent.tools")

EventStreamHandler = Callable[[Any, AsyncIterable[Any]], Awaitable[None]]


def make_event_stream_printer() -> EventStreamHandler:
    """Return an event_stream_handler that logs tool calls and results as they happen."""

    async def log_events(_ctx: Any, stream: AsyncIterable[Any]) -> None:
        async for event in stream:
            _log_event(event)

    return log_events


def _log_event(event: Any) -> None:
    part = getattr(event, "part", None)
    tool_name = getattr(part, "tool_name", None) or getattr(event, "tool_name", None)
    if tool_name is None:
        return
    if hasattr(event, "result"):
        logger.info("tool done: %s", tool_name)
    else:
        args = getattr(part, "args", None)
        logger.info("tool call: %s(%s)", tool_name, "" if args is None else args)


def print_response(output: Any) -> None:
    print("\n=== response ===")
    print(output)
