"""Shared pytest wiring and fixtures.

Live log verbosity follows LOG_LEVEL from .env / .env.local; an explicit
``--log-cli-level=...`` on the command line still wins.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from config import Config
from ovid_identity import OvidCli, OvidCliError, RegisteredAgent

EXAMPLE_DIR = Path(__file__).resolve().parent
SCRIPT = EXAMPLE_DIR / "pydantic-ai-read-write-edit.py"


def pytest_configure(config: pytest.Config) -> None:
    if config.option.log_cli_level is None:
        config.option.log_cli_level = Config.from_env().log_level


def load_example_module():
    """Import the hyphen-named example script as a module."""
    spec = importlib.util.spec_from_file_location("pydantic_ai_read_write_edit", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeRegistry:
    """In-memory Registry: same contract as OnePasswordRegistry, no 1Password."""

    def __init__(self) -> None:
        self.items: dict[str, RegisteredAgent] = {}

    def find(self, unique_name: str) -> RegisteredAgent | None:
        return self.items.get(unique_name)

    def create(self, agent: RegisteredAgent) -> None:
        if agent.unique_name in self.items:
            raise AssertionError(f"duplicate registration: {agent.unique_name}")
        self.items[agent.unique_name] = agent

    def delete(self, unique_name: str) -> None:
        del self.items[unique_name]


@pytest.fixture(scope="session")
def cli() -> OvidCli:
    try:
        return OvidCli.locate()
    except OvidCliError as error:
        pytest.skip(str(error))


@pytest.fixture
def registry() -> FakeRegistry:
    return FakeRegistry()
