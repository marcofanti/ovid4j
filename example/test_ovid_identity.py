"""Tests for the OVID root-identity bootstrap.

Unit tier: fake registry, real ovid4j CLI jar (build with ``mvn package``),
pydantic-ai TestModel — no network, no LLM, no 1Password.
Integration tier (``-m integration``): real 1Password via OP_SERVICE_ACCOUNT_TOKEN.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import uuid
from pathlib import Path

import pytest
from dotenv import load_dotenv
from pydantic_ai.models.test import TestModel

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

EXAMPLE_DIR = Path(__file__).resolve().parent
load_dotenv(EXAMPLE_DIR.parent / ".env")


def load_example_module():
    """Import the hyphen-named example script as a module."""
    spec = importlib.util.spec_from_file_location(
        "pydantic_ai_read_write_edit", EXAMPLE_DIR / "pydantic-ai-read-write-edit.py"
    )
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


SCRIPT = EXAMPLE_DIR / "pydantic-ai-read-write-edit.py"
EXAMPLE_TOOLS = ("read_file", "run_command", "write_file")


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
        return OnePasswordRegistry()

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
