"""Console printing for pydantic-ai agent runs: tool-call events and the final response."""

from collections.abc import AsyncIterable, Awaitable, Callable
from typing import Any

EventStreamHandler = Callable[[Any, AsyncIterable[Any]], Awaitable[None]]


def make_event_stream_printer() -> EventStreamHandler:
    """Return an event_stream_handler that prints tool calls and results as they happen."""

    async def print_events(_ctx: Any, stream: AsyncIterable[Any]) -> None:
        async for event in stream:
            _print_event(event)

    return print_events


def _print_event(event: Any) -> None:
    part = getattr(event, "part", None)
    tool_name = getattr(part, "tool_name", None) or getattr(event, "tool_name", None)
    if tool_name is None:
        return
    if hasattr(event, "result"):
        print(f"[tool done] {tool_name}")
    else:
        args = getattr(part, "args", None)
        print(f"[tool call] {tool_name}({args if args is not None else ''})")


def print_response(output: Any) -> None:
    print("\n=== response ===")
    print(output)
