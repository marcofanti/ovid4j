"""Pytest wiring: live log verbosity follows LOG_LEVEL from .env / .env.local.

An explicit ``--log-cli-level=...`` on the command line still wins.
"""

import pytest

from config import Config


def pytest_configure(config: pytest.Config) -> None:
    if config.option.log_cli_level is None:
        config.option.log_cli_level = Config.from_env().log_level
