# OVID root identity for a Python agent

A [pydantic-ai](https://ai.pydantic.dev) agent that treats **this file on this
machine** as a cryptographic identity: on every run it loads (or creates) its
Ed25519 keypair from 1Password, infers a Cedar mandate from the tools it
registers, and mints a self-verified OVID root token via the ovid4j CLI jar —
before a single model call happens.

## How identity works here

| Concept | Realization |
|---|---|
| Unique name | `user@machine:path-under-home` of the script (moving the file = a new agent) |
| Key storage | One 1Password item per agent; item title = the unique name; private key is a concealed field. **1Password is the registry** — there is no second store. |
| Mandate | Inferred from the agent's registered tools: `read_file` → `read`, `write_file` → `write` (both scoped `resource.path like "scratch_space/*"`), `run_command` → `exec` on `Ovid::Shell::"sh"`. Unknown tools fail registration loudly. |
| Minting | `bootstrap_root_identity()` shells out to `../target/ovid4j-*-cli.jar` (`keygen`/`create`/`verify`), so the wire format stays byte-exact with the Java and TypeScript libraries. |
| Drift | The mandate is re-inferred every run (code is the source of truth); if it no longer matches what was registered, a warning is logged. |

Private keys exist only in 1Password and process memory — never on disk, never
in logs (the CLI wrapper logs command + timing only, by design).

## Files

- [`pydantic-ai-read-write-edit.py`](pydantic-ai-read-write-edit.py) — the agent (`build_agent()`) and the entrypoint that bootstraps identity before running
- [`ovid_identity.py`](ovid_identity.py) — name derivation, policy inference, the `OvidCli` subprocess bridge, the `Registry` protocol + `OnePasswordRegistry`, and `bootstrap_root_identity()`
- [`config.py`](config.py) — env-driven `Config`; loads `../.env` then `.env.local` (override)
- [`event_logging.py`](event_logging.py) — tool events to the log, final response to stdout
- [`test_ovid_identity.py`](test_ovid_identity.py) / [`conftest.py`](conftest.py) — tests (below) and pytest live-log wiring
- [`.env.local.example`](.env.local.example) — configuration template

## Setup

1. Build the CLI jar: `mvn package` (repo root). Requires Java 26.
2. `uv sync` in this directory (Python 3.13).
3. For the registry: create a **1Password vault** (default name `OVID Agents`)
   and a **service account** with *read and write* access to it (service
   accounts cannot create vaults, and read-only manifests as
   `not sufficient permissions` on registration). Put the token in `../.env`:
   `OP_SERVICE_ACCOUNT_TOKEN=ops_...`
4. To run the agent itself: `ANTHROPIC_API_KEY` in `../.env`.
5. Optional overrides: `cp .env.local.example .env.local` and edit.

## Configuration

All knobs are environment variables (`config.py`); precedence:
process env / `.env.local` > `../.env` > defaults.

| Variable | Default | Purpose |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Program **and** pytest live-log verbosity; `DEBUG` adds CLI timings, the inferred mandate, vault resolution |
| `AGENT_MODEL` | `anthropic:claude-haiku-4-5` | pydantic-ai model string |
| `OVID_VAULT_TITLE` | `OVID Agents` | 1Password vault holding the agent items |
| `OVID_TTL_SECONDS` | `1800` | Lifetime of each minted root token |

## Running

```bash
uv run pydantic-ai-read-write-edit.py
# 18:49:17 INFO  ovid_identity: bootstrapping OVID root identity "mfanti@M5-Max:…"
# 18:49:17 INFO  ovid_identity: minted and self-verified root token (ttl 1800s, …)
# Prompt: create hello.txt containing "hi"
```

The agent's file/shell tools are sandboxed to `../scratch_space/` (gitignored),
matching the scope of its mandate.

## Tests

```bash
uv run pytest -m "not integration"   # unit tier — no LLM, no network, no 1Password
uv run pytest -m integration         # real 1Password (auto-skips without the token)
```

The unit tier uses a `FakeRegistry`, the **real CLI jar**, and pydantic-ai's
`TestModel`. It covers: name derivation, mandate inference (including the
Java-side Cedar validation round-trip), first-run registration, key reuse,
policy drift, foreign-root rejection, corrupt-key failure, and config parsing.
The integration tier registers a throwaway `test/ovid4j-example/<uuid>` item in
the real vault, bootstraps twice, and cleans up in teardown.

One property worth knowing: two mints of identical claims in the same second
produce byte-identical JWTs (Ed25519 signing is deterministic) — tests that
need "a different token" vary the TTL instead.
