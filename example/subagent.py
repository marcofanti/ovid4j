"""Delegation: spawn sub-agents under narrowed OVID mandates.

The parent mints a child token (the parent signs the chain link, the child
binds fresh keys — all via the ovid4j CLI) and runs a restricted agent that
holds only the granted tool subset. Two attenuation rules apply:

- **actions**: the child's tools must be a subset of the parent's — enforced
  here, before minting, because the OVID libraries deliberately don't compare
  policy semantics;
- **lifetime**: the child cannot outlive the parent — enforced by the library
  (minting fails on violation).

Children are ephemeral: their keys stay in memory and are never registered in
1Password (only roots are). Children also don't get a spawn tool, so the chain
cannot deepen implicitly.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from ovid_identity import (
    ChildIdentity,
    KeyPair,
    OvidCli,
    OvidCliError,
    RootIdentity,
    infer_policy_set,
)

DEFAULT_CHILD_TTL_SECONDS = 600

logger = logging.getLogger("ovid_identity.subagent")


class DelegationError(ValueError):
    """The requested delegation would exceed the parent's mandate."""


@dataclass(frozen=True)
class SubagentRun:
    output: str
    identity: ChildIdentity


def mint_child_identity(
    *,
    parent: RootIdentity | ChildIdentity,
    tool_names: Sequence[str],
    cli: OvidCli,
    label: str | None = None,
    ttl_seconds: int = DEFAULT_CHILD_TTL_SECONDS,
    trusted_root: str | None = None,
) -> ChildIdentity:
    """Mint and verify a child token whose mandate covers exactly ``tool_names``.

    ``trusted_root`` is the root public key the child's chain must anchor to;
    it defaults to the parent's key, which is correct when the parent is the root.
    """
    requested = tuple(sorted(set(tool_names)))
    excess = set(requested) - set(parent.tool_names)
    if excess:
        raise DelegationError(
            f"cannot delegate tools {sorted(excess)}: parent "
            f'"{parent.unique_name}" only holds {sorted(parent.tool_names)}'
        )
    policy_set = infer_policy_set(requested)
    child_name = f"{parent.unique_name}/{label or 'sub-' + uuid.uuid4().hex[:6]}"
    logger.info(
        'delegating to "%s" with tools %s (ttl %ds)', child_name, list(requested), ttl_seconds
    )

    minted = cli.create_child(
        child_name, policy_set, parent.jwt, parent.keys, ttl_seconds=ttl_seconds
    )
    root_key = trusted_root or parent.public_key
    verified = cli.verify(minted["jwt"], [root_key])
    if not verified.get("valid"):
        raise OvidCliError(
            f'freshly minted child token for "{child_name}" failed verification '
            "against the trusted root — refusing to hand out an unverifiable identity"
        )
    logger.info("child chain verified: %s", " -> ".join(verified["chain"]))
    return ChildIdentity(
        unique_name=child_name,
        jwt=minted["jwt"],
        public_key=minted["publicKey"],
        policy_set=policy_set,
        tool_names=requested,
        expires_at=int(minted["exp"]),
        chain=tuple(verified["chain"]),
        keys=KeyPair(minted["publicKey"], minted["privateKey"]),
    )


def spawn_subagent(
    *,
    parent: RootIdentity,
    task: str,
    tool_names: Sequence[str],
    cli: OvidCli,
    agent_factory: Callable[[tuple[str, ...]], Any],
    label: str | None = None,
    ttl_seconds: int = DEFAULT_CHILD_TTL_SECONDS,
) -> SubagentRun:
    """Mint a child identity, run a restricted agent for ``task``, return both."""
    if "spawn_subagent" in set(tool_names):
        raise DelegationError(
            "children do not get a spawn tool — the chain cannot deepen implicitly"
        )
    identity = mint_child_identity(
        parent=parent, tool_names=tool_names, cli=cli, label=label, ttl_seconds=ttl_seconds
    )
    agent = agent_factory(identity.tool_names)
    result = agent.run_sync(task)
    logger.info('subagent "%s" finished', identity.unique_name)
    return SubagentRun(output=str(result.output), identity=identity)


def add_spawn_tool(
    agent: Any,
    *,
    parent: RootIdentity,
    cli: OvidCli,
    agent_factory: Callable[[tuple[str, ...]], Any],
    ttl_seconds: int = DEFAULT_CHILD_TTL_SECONDS,
) -> None:
    """Register a ``spawn_subagent`` tool on the root agent.

    The root's own mandate must cover delegation — include ``"spawn_subagent"``
    in the tool names passed to ``bootstrap_root_identity`` (it maps to the
    Cedar ``delegate`` action).
    """

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def spawn_subagent_tool(task: str, tools: list[str]) -> str:
        """Delegate a task to a sub-agent that only gets the listed tools.

        Args:
            task: The task for the sub-agent to perform.
            tools: Tool names the sub-agent may use — a subset of your own tools.
        """
        try:
            run = spawn_subagent(
                parent=parent,
                task=task,
                tool_names=tools,
                cli=cli,
                agent_factory=agent_factory,
                ttl_seconds=ttl_seconds,
            )
        except (DelegationError, OvidCliError) as error:
            return f"delegation refused: {error}"
        return (
            f"[{run.identity.unique_name} · chain {' -> '.join(run.identity.chain)}]\n{run.output}"
        )
