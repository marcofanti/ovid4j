"""E2E tests for delegation: root → sub-agent with a narrowed OVID mandate."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic_ai.models.test import TestModel

from conftest import SCRIPT, FakeRegistry, load_example_module
from ovid_identity import OvidCliError, RootIdentity, bootstrap_root_identity
from subagent import DelegationError, mint_child_identity, spawn_subagent

REPO_ROOT = SCRIPT.parents[1]
TS_DIST = REPO_ROOT.parent / "ovid" / "dist" / "index.js"
ROOT_TOOLS = ("read_file", "run_command", "spawn_subagent", "write_file")


@pytest.fixture
def root(cli, registry) -> RootIdentity:
    return bootstrap_root_identity(
        script_path=SCRIPT, tool_names=ROOT_TOOLS, registry=registry, cli=cli
    )


# ── delegation chain ──────────────────────────────────────────────────────


def test_child_chain_of_two_verifies_in_java(cli, root):
    child = mint_child_identity(parent=root, tool_names=["read_file"], cli=cli, label="reader")
    assert child.unique_name == f"{root.unique_name}/reader"
    assert child.chain == (root.unique_name, child.unique_name)
    assert child.public_key != root.public_key  # child binds fresh keys

    verified = cli.verify(child.jwt, [root.public_key])
    assert verified["valid"]
    assert verified["principal"] == child.unique_name
    assert "read" in verified["policySet"]
    assert "exec" not in verified["policySet"]


def test_child_token_verifies_in_typescript_library(cli, root):
    """Cross-language E2E: a Python-orchestrated delegation chain anchors in the TS lib."""
    if shutil.which("node") is None or not TS_DIST.exists():
        pytest.skip(f"needs node and the built TS reference library at {TS_DIST}")
    child = mint_child_identity(parent=root, tool_names=["read_file"], cli=cli, label="ts-check")

    result = subprocess.run(
        ["node", str(REPO_ROOT / "interop" / "verify-token.mjs")],
        input=json.dumps({"jwt": child.jwt, "rootPublicKey": root.public_key}),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    verdict = json.loads(result.stdout)
    assert verdict["valid"]
    assert verdict["principal"] == child.unique_name
    assert verdict["chain"] == [root.unique_name, child.unique_name]


# ── attenuation refusals ──────────────────────────────────────────────────


def test_child_cannot_outlive_parent(cli, root):
    with pytest.raises(OvidCliError, match="attenuation"):
        mint_child_identity(parent=root, tool_names=["read_file"], cli=cli, ttl_seconds=24 * 3600)


def test_tools_outside_parent_mandate_are_refused(cli, registry):
    narrow_root = bootstrap_root_identity(
        script_path=SCRIPT,
        tool_names=("read_file", "spawn_subagent"),
        registry=registry,
        cli=cli,
    )
    with pytest.raises(DelegationError, match="run_command"):
        mint_child_identity(parent=narrow_root, tool_names=["run_command"], cli=cli)


def test_children_do_not_get_a_spawn_tool(cli, root):
    with pytest.raises(DelegationError, match="spawn"):
        spawn_subagent(
            parent=root,
            task="delegate further",
            tool_names=["read_file", "spawn_subagent"],
            cli=cli,
            agent_factory=lambda tools: pytest.fail("must refuse before building an agent"),
        )


# ── running the sub-agent ─────────────────────────────────────────────────


def test_spawn_runs_restricted_agent_under_child_identity(cli, root, tmp_path: Path):
    module = load_example_module()
    (tmp_path / "note.txt").write_text("hello from the parent")

    run = spawn_subagent(
        parent=root,
        task="read note.txt and report its contents",
        tool_names=["read_file"],
        cli=cli,
        agent_factory=lambda tools: module.build_agent(TestModel(), tmp_path, tools),
        label="reader",
    )
    assert run.output
    assert run.identity.chain == (root.unique_name, f"{root.unique_name}/reader")
    assert run.identity.tool_names == ("read_file",)


def test_restricted_agent_only_carries_granted_tools():
    module = load_example_module()
    agent = module.build_agent(TestModel(), tool_names=("read_file",))
    from ovid_identity import agent_tool_names

    assert agent_tool_names(agent) == ("read_file",)
    with pytest.raises(ValueError, match="unknown tools"):
        module.build_agent(TestModel(), tool_names=("read_file", "launch_missiles"))


# ── full-program E2E ──────────────────────────────────────────────────────


def test_main_end_to_end_with_test_model(cli, tmp_path: Path, capsys):
    module = load_example_module()
    registry = FakeRegistry()
    module.main(
        "write hello.txt then read it back",
        registry=registry,
        model=TestModel(),
        project_root=tmp_path,
    )
    out = capsys.readouterr().out
    assert "=== response ===" in out
    # The root registered itself (with the delegation grant) during main().
    (registered,) = registry.items.values()
    assert "delegate" in registered.policy_set
