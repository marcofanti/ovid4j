"""Central configuration for the example.

All knobs are environment variables, loaded from two dotenv files:

1. ``../.env`` (repo root) — shared defaults and secrets
2. ``.env.local`` (this directory) — machine-local overrides, wins over ``.env``

Both are gitignored; ``.env.local.example`` is the committed template.
Secrets (ANTHROPIC_API_KEY, OP_SERVICE_ACCOUNT_TOKEN) stay in the process
environment and are read where they are used, never held on this object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

EXAMPLE_DIR = Path(__file__).resolve().parent


def load_env() -> None:
    load_dotenv(EXAMPLE_DIR.parent / ".env")
    load_dotenv(EXAMPLE_DIR / ".env.local", override=True)


@dataclass(frozen=True)
class Config:
    log_level: str
    agent_model: str
    vault_title: str
    ttl_seconds: int

    @classmethod
    def from_env(cls) -> Config:
        load_env()
        ttl_raw = os.environ.get("OVID_TTL_SECONDS", "1800")
        try:
            ttl_seconds = int(ttl_raw)
        except ValueError as error:
            raise ValueError(
                f"OVID_TTL_SECONDS must be an integer number of seconds, got {ttl_raw!r} "
                "— fix it in .env or .env.local"
            ) from error
        if ttl_seconds <= 0:
            raise ValueError(f"OVID_TTL_SECONDS must be positive, got {ttl_seconds}")
        return cls(
            log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
            agent_model=os.environ.get("AGENT_MODEL", "anthropic:claude-haiku-4-5"),
            vault_title=os.environ.get("OVID_VAULT_TITLE", "OVID Agents"),
            ttl_seconds=ttl_seconds,
        )
