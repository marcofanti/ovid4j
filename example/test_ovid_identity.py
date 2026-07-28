"""Tests for the OVID root-identity bootstrap.

Unit tier: fake registry, real ovid4j CLI jar (build with ``mvn package``),
pydantic-ai TestModel — no network, no LLM, no 1Password.
Integration tier (``-m integration``): real 1Password via OP_SERVICE_ACCOUNT_TOKEN.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from pydantic_ai.models.test import TestModel

from config import Config, load_env
from conftest import SCRIPT, FakeRegistry, load_example_module
from ovid_identity import (
    KeyPair,
    OnePasswordRegistry,
    OvidCli,
    OvidCliError,
    PolicyInferenceError,
    RegisteredAgent,
    agent_tool_names,
    agent_unique_name,
    bootstrap_root_identity,
    infer_policy_set,
)

load_env()

EXAMPLE_TOOLS = ("read_file", "run_command", "write_file")


# ── configuration ─────────────────────────────────────────────────────────


@pytest.fixture
def bare_env(monkeypatch):
    """No dotenv files, no config env vars: from_env sees only explicit values."""
    monkeypatch.setattr("config.load_dotenv", lambda *_a, **_k: None)
    for var in ("LOG_LEVEL", "AGENT_MODEL", "OVID_VAULT_TITLE", "OVID_TTL_SECONDS"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_config_defaults(bare_env):
    assert Config.from_env() == Config(
        log_level="INFO",
        agent_model="anthropic:claude-haiku-4-5",
        vault_title="OVID Agents",
        ttl_seconds=1800,
    )


def test_config_reads_overrides_and_normalizes_level(bare_env):
    bare_env.setenv("LOG_LEVEL", "debug")
    bare_env.setenv("AGENT_MODEL", "anthropic:claude-sonnet-5")
    bare_env.setenv("OVID_VAULT_TITLE", "Agents Test")
    bare_env.setenv("OVID_TTL_SECONDS", "600")
    config = Config.from_env()
    assert config.log_level == "DEBUG"
    assert config.agent_model == "anthropic:claude-sonnet-5"
    assert config.vault_title == "Agents Test"
    assert config.ttl_seconds == 600


def test_config_rejects_bad_ttl(bare_env):
    bare_env.setenv("OVID_TTL_SECONDS", "half an hour")
    with pytest.raises(ValueError, match="OVID_TTL_SECONDS"):
        Config.from_env()
    bare_env.setenv("OVID_TTL_SECONDS", "-5")
    with pytest.raises(ValueError, match="positive"):
        Config.from_env()


# ── unique name derivation ────────────────────────────────────────────────


def test_unique_name_is_user_at_machine_colon_home_relative_path():
    name = agent_unique_name(SCRIPT, username="alice", hostname="devbox")
    assert name == f"alice@devbox:{SCRIPT.relative_to(Path.home())}"


def test_unique_name_is_stable_across_calls():
    assert agent_unique_name(SCRIPT) == agent_unique_name(SCRIPT)


def test_unique_name_outside_home_falls_back_to_absolute():
    name = agent_unique_name(Path("/opt/agents/bot.py"), username="a", hostname="b")
    assert name == "a@b:/opt/agents/bot.py"


def test_unique_name_changes_when_file_moves():
    here = agent_unique_name(SCRIPT, username="a", hostname="b")
    moved = agent_unique_name(SCRIPT.parent / "elsewhere.py", username="a", hostname="b")
    assert here != moved


# ── policy inference ──────────────────────────────────────────────────────


def test_inferred_mandate_for_example_tools():
    assert infer_policy_set(EXAMPLE_TOOLS) == (
        'permit(principal, action == Ovid::Action::"read", resource)'
        ' when { resource.path like "scratch_space/*" };\n'
        'permit(principal, action == Ovid::Action::"exec", resource == Ovid::Shell::"sh");\n'
        'permit(principal, action == Ovid::Action::"write", resource)'
        ' when { resource.path like "scratch_space/*" };'
    )


def test_inferred_mandate_tracks_the_tool_set():
    read_only = infer_policy_set(["read_file"])
    assert read_only != infer_policy_set(EXAMPLE_TOOLS)
    assert "exec" not in read_only


def test_unknown_tool_is_rejected():
    with pytest.raises(PolicyInferenceError, match="launch_missiles"):
        infer_policy_set(["read_file", "launch_missiles"])


def test_empty_tool_set_is_rejected():
    with pytest.raises(PolicyInferenceError, match="no tools"):
        infer_policy_set([])


def test_inferred_mandate_passes_java_cedar_validation(cli: OvidCli):
    result = cli.validate_cedar(infer_policy_set(EXAMPLE_TOOLS))
    assert result == {"valid": True}


def test_tool_names_introspected_from_example_agent():
    module = load_example_module()
    agent = module.build_agent(TestModel())
    assert agent_tool_names(agent) == EXAMPLE_TOOLS


def test_example_agent_runs_under_test_model(tmp_path: Path):
    module = load_example_module()
    agent = module.build_agent(TestModel(), project_root=tmp_path)
    result = agent.run_sync("write then read a note")
    assert result.output  # TestModel exercised every tool without an LLM


# ── bootstrap ─────────────────────────────────────────────────────────────


def test_first_run_registers_and_mints_verifiable_root(cli: OvidCli, registry: FakeRegistry):
    identity = bootstrap_root_identity(
        script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=registry, cli=cli
    )
    assert identity.newly_registered and not identity.policy_drift

    stored = registry.items[identity.unique_name]
    assert stored.keys.public_key == identity.public_key
    assert stored.policy_set == identity.policy_set
    assert stored.wire_protocol == "0.4.0"

    verified = cli.verify(identity.jwt, [identity.public_key])
    assert verified["valid"]
    assert verified["principal"] == identity.unique_name
    assert verified["chain"] == [identity.unique_name]
    assert verified["policySet"] == identity.policy_set


def test_second_run_reuses_registered_key(cli: OvidCli, registry: FakeRegistry):
    first = bootstrap_root_identity(
        script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=registry, cli=cli
    )
    second = bootstrap_root_identity(
        script_path=SCRIPT,
        tool_names=EXAMPLE_TOOLS,
        registry=registry,
        cli=cli,
        ttl_seconds=900,
    )
    assert not second.newly_registered
    assert second.public_key == first.public_key
    assert len(registry.items) == 1
    # Fresh mint under the same identity: different lifetime, still verifies.
    assert second.expires_at < first.expires_at
    assert cli.verify(second.jwt, [first.public_key])["valid"]


def test_tool_change_after_registration_reports_policy_drift(cli: OvidCli, registry: FakeRegistry):
    bootstrap_root_identity(
        script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=registry, cli=cli
    )
    narrowed = bootstrap_root_identity(
        script_path=SCRIPT, tool_names=["read_file"], registry=registry, cli=cli
    )
    assert narrowed.policy_drift
    # The minted token carries the current (inferred) mandate, not the stale one.
    verified = cli.verify(narrowed.jwt, [narrowed.public_key])
    assert "exec" not in verified["policySet"]


def test_token_does_not_verify_under_foreign_root(cli: OvidCli, registry: FakeRegistry):
    identity = bootstrap_root_identity(
        script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=registry, cli=cli
    )
    foreign = cli.keygen()
    assert cli.verify(identity.jwt, [foreign.public_key]) == {"valid": False}


def test_corrupt_registered_key_fails_bootstrap_loudly(cli: OvidCli, registry: FakeRegistry):
    good = cli.keygen()
    bad = KeyPair(public_key=cli.keygen().public_key, private_key=good.private_key)
    name = agent_unique_name(SCRIPT)
    registry.create(
        RegisteredAgent(unique_name=name, keys=bad, policy_set="p", wire_protocol="0.4.0")
    )
    with pytest.raises(OvidCliError, match="self-verification"):
        bootstrap_root_identity(
            script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=registry, cli=cli
        )


# ── integration: real 1Password ───────────────────────────────────────────


needs_1password = pytest.mark.skipif(
    not os.environ.get("OP_SERVICE_ACCOUNT_TOKEN"),
    reason="OP_SERVICE_ACCOUNT_TOKEN not set",
)


@needs_1password
@pytest.mark.integration
class TestOnePasswordRegistry:
    @pytest.fixture
    def op_registry(self) -> OnePasswordRegistry:
        return OnePasswordRegistry(vault_title=Config.from_env().vault_title)

    @pytest.fixture
    def test_name(self, op_registry: OnePasswordRegistry):
        name = f"test/ovid4j-example/{uuid.uuid4()}"
        yield name
        try:
            op_registry.delete(name)
        except Exception:
            pass  # test may not have created it

    def test_find_unregistered_returns_none(self, op_registry, test_name):
        assert op_registry.find(test_name) is None

    def test_bootstrap_against_real_vault(self, cli, op_registry, test_name, monkeypatch):
        monkeypatch.setattr("ovid_identity.agent_unique_name", lambda *_a, **_k: test_name)
        first = bootstrap_root_identity(
            script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=op_registry, cli=cli
        )
        assert first.newly_registered
        assert cli.verify(first.jwt, [first.public_key])["valid"]

        second = bootstrap_root_identity(
            script_path=SCRIPT, tool_names=EXAMPLE_TOOLS, registry=op_registry, cli=cli
        )
        assert not second.newly_registered
        assert second.public_key == first.public_key
