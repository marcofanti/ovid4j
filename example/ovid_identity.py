"""OVID root identity for a Python agent program.

The program's file path (plus user and machine) is its identity; its Ed25519
keypair lives in 1Password; its Cedar mandate is inferred from the tools the
agent actually registers. Minting and verification are delegated to the ovid4j
CLI jar (``mvn package`` builds it), so the wire format stays byte-exact with
the Java and TypeScript libraries.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import socket
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

WIRE_PROTOCOL_VERSION = "0.4.0"
DEFAULT_VAULT_TITLE = "OVID Agents"
DEFAULT_TTL_SECONDS = 1800


class OvidCliError(RuntimeError):
    """The ovid4j CLI could not be located, run, or returned an error."""


class PolicyInferenceError(ValueError):
    """The agent's tools could not be mapped to a Cedar mandate."""


class RegistryError(RuntimeError):
    """The 1Password registry could not complete an operation."""


@dataclass(frozen=True)
class KeyPair:
    public_key: str  # base64url raw 32-byte Ed25519 public key (wire agent_pub)
    private_key: str  # base64url raw 32-byte Ed25519 seed (JWK d) — never log or persist


@dataclass(frozen=True)
class RegisteredAgent:
    unique_name: str
    keys: KeyPair
    policy_set: str
    wire_protocol: str


@dataclass(frozen=True)
class RootIdentity:
    unique_name: str
    jwt: str
    public_key: str
    policy_set: str
    expires_at: int
    newly_registered: bool
    policy_drift: bool


# ── unique naming ─────────────────────────────────────────────────────────


def agent_unique_name(
    script_path: Path, *, username: str | None = None, hostname: str | None = None
) -> str:
    """Derive the agent's stable identity: ``user@machine:path-under-home``.

    The path is home-relative when possible (absolute otherwise), so the same
    checkout produces the same identity run after run — and a moved file is,
    deliberately, a different agent.
    """
    resolved = script_path.resolve()
    try:
        shown = resolved.relative_to(Path.home())
    except ValueError:
        shown = resolved
    user = username or getpass.getuser()
    machine = hostname or socket.gethostname().removesuffix(".local")
    return f"{user}@{machine}:{shown}"


# ── policy inference ──────────────────────────────────────────────────────

_FILE_SCOPE_TOOLS = {"read_file": "read", "write_file": "write"}
_SHELL_TOOLS = {"run_command": "exec"}


def infer_policy_set(tool_names: Sequence[str], *, scope: str = "scratch_space") -> str:
    """Map the agent's registered tool names to a Cedar mandate.

    Emits the same Cedar subset ovid4j's MandateBuilder produces (and its
    CedarSyntax validator accepts). Unknown tools fail loudly: a tool that
    grants nothing would otherwise run outside the mandate entirely.
    """
    if not tool_names:
        raise PolicyInferenceError("agent registers no tools; refusing to mint an empty mandate")
    statements: list[str] = []
    for tool in sorted(set(tool_names)):
        if tool in _FILE_SCOPE_TOOLS:
            action = _FILE_SCOPE_TOOLS[tool]
            statements.append(
                f'permit(principal, action == Ovid::Action::"{action}", resource) '
                f'when {{ resource.path like "{scope}/*" }};'
            )
        elif tool in _SHELL_TOOLS:
            action = _SHELL_TOOLS[tool]
            statements.append(
                f'permit(principal, action == Ovid::Action::"{action}", '
                f'resource == Ovid::Shell::"sh");'
            )
        else:
            raise PolicyInferenceError(
                f'no Cedar mapping for tool "{tool}" — add it to ovid_identity or rename the tool'
            )
    return "\n".join(statements)


def agent_tool_names(agent: Any) -> tuple[str, ...]:
    """List the tool names registered on a pydantic-ai Agent, sorted."""
    names: list[str] = []
    for toolset in getattr(agent, "toolsets", []):
        tools = getattr(toolset, "tools", None)
        if isinstance(tools, dict):
            names.extend(tools.keys())
    if not names:
        raise PolicyInferenceError(
            "could not find any function tools on the agent "
            "(pydantic-ai toolset layout changed, or no tools are registered)"
        )
    return tuple(sorted(names))


# ── ovid4j CLI bridge ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class OvidCli:
    """Subprocess bridge to the ovid4j CLI jar: JSON in, JSON out."""

    jar_path: Path

    @classmethod
    def locate(cls, repo_root: Path | None = None) -> OvidCli:
        root = repo_root or Path(__file__).resolve().parents[1]
        jars = sorted(root.glob("target/ovid4j-*-cli.jar"))
        if not jars:
            raise OvidCliError(
                f"no ovid4j CLI jar under {root / 'target'} — build it with: mvn -f {root} package"
            )
        return cls(jar_path=jars[-1])

    def keygen(self) -> KeyPair:
        output = self._run("keygen", {})
        return KeyPair(public_key=output["publicKey"], private_key=output["privateKey"])

    def create_root(
        self, name: str, policy_set: str, keys: KeyPair, *, ttl_seconds: int
    ) -> dict[str, Any]:
        return self._run(
            "create",
            {
                "name": name,
                "policySet": policy_set,
                "ttlSeconds": ttl_seconds,
                "keys": {"publicKey": keys.public_key, "privateKey": keys.private_key},
            },
        )

    def verify(self, jwt: str, trusted_roots: Sequence[str]) -> dict[str, Any]:
        return self._run("verify", {"jwt": jwt, "trustedRoots": list(trusted_roots)})

    def validate_cedar(self, policy_set: str) -> dict[str, Any]:
        return self._run("cedar", {"policySet": policy_set})

    def _run(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        result = subprocess.run(
            ["java", "-jar", str(self.jar_path), command],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
        )
        try:
            output = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise OvidCliError(
                f"ovid4j {command}: non-JSON output (exit {result.returncode}): "
                f"{result.stdout!r} stderr={result.stderr!r}"
            ) from error
        if result.returncode != 0:
            raise OvidCliError(f"ovid4j {command}: {output.get('error', result.stderr)}")
        return output


# ── registry (1Password) ──────────────────────────────────────────────────


class Registry(Protocol):
    def find(self, unique_name: str) -> RegisteredAgent | None: ...

    def create(self, agent: RegisteredAgent) -> None: ...

    def delete(self, unique_name: str) -> None: ...


@dataclass(frozen=True)
class OnePasswordRegistry:
    """One 1Password item per agent; the item title is the unique name.

    Requires OP_SERVICE_ACCOUNT_TOKEN and a pre-existing vault the service
    account can write to (service accounts cannot create vaults).
    """

    vault_title: str = DEFAULT_VAULT_TITLE

    def find(self, unique_name: str) -> RegisteredAgent | None:
        return asyncio.run(self._find(unique_name))

    def create(self, agent: RegisteredAgent) -> None:
        asyncio.run(self._create(agent))

    def delete(self, unique_name: str) -> None:
        asyncio.run(self._delete(unique_name))

    async def _client(self) -> Any:
        from onepassword import Client

        token = os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
        if not token:
            raise RegistryError(
                "OP_SERVICE_ACCOUNT_TOKEN is not set — create a 1Password service account "
                f'with write access to the "{self.vault_title}" vault and export the token'
            )
        return await Client.authenticate(
            auth=token, integration_name="ovid4j-example", integration_version="0.1.0"
        )

    async def _vault_id(self, client: Any) -> str:
        for vault in await client.vaults.list():
            if vault.title == self.vault_title:
                return vault.id
        raise RegistryError(
            f'vault "{self.vault_title}" not found — create it in 1Password and grant '
            "the service account read/write access"
        )

    async def _find(self, unique_name: str) -> RegisteredAgent | None:
        client = await self._client()
        vault_id = await self._vault_id(client)
        overview = await self._find_overview(client, vault_id, unique_name)
        if overview is None:
            return None
        item = await client.items.get(vault_id, overview.id)
        fields = {field.id: field.value for field in item.fields}
        try:
            return RegisteredAgent(
                unique_name=unique_name,
                keys=KeyPair(fields["public_key"], fields["private_key"]),
                policy_set=fields["policy_set"],
                wire_protocol=fields["wire_protocol"],
            )
        except KeyError as error:
            raise RegistryError(
                f'1Password item "{unique_name}" is missing field {error} — '
                "delete the item to re-register the agent"
            ) from error

    async def _create(self, agent: RegisteredAgent) -> None:
        from onepassword import (
            ItemCategory,
            ItemCreateParams,
            ItemField,
            ItemFieldType,
            ItemSection,
        )

        client = await self._client()
        vault_id = await self._vault_id(client)
        if await self._find_overview(client, vault_id, agent.unique_name) is not None:
            raise RegistryError(f'agent "{agent.unique_name}" is already registered')
        await client.items.create(
            ItemCreateParams(
                title=agent.unique_name,
                category=ItemCategory.LOGIN,
                vault_id=vault_id,
                fields=[
                    ItemField(
                        id="public_key",
                        title="public_key",
                        field_type=ItemFieldType.TEXT,
                        value=agent.keys.public_key,
                    ),
                    ItemField(
                        id="private_key",
                        title="private_key",
                        field_type=ItemFieldType.CONCEALED,
                        value=agent.keys.private_key,
                    ),
                    ItemField(
                        id="policy_set",
                        title="policy_set",
                        field_type=ItemFieldType.TEXT,
                        value=agent.policy_set,
                    ),
                    ItemField(
                        id="wire_protocol",
                        title="wire_protocol",
                        field_type=ItemFieldType.TEXT,
                        value=agent.wire_protocol,
                    ),
                ],
                sections=[ItemSection(id="", title="")],
            )
        )

    async def _delete(self, unique_name: str) -> None:
        client = await self._client()
        vault_id = await self._vault_id(client)
        overview = await self._find_overview(client, vault_id, unique_name)
        if overview is None:
            raise RegistryError(f'agent "{unique_name}" is not registered')
        await client.items.delete(vault_id, overview.id)

    @staticmethod
    async def _find_overview(client: Any, vault_id: str, title: str) -> Any | None:
        for overview in await client.items.list(vault_id):
            if overview.title == title:
                return overview
        return None


# ── bootstrap ─────────────────────────────────────────────────────────────


def bootstrap_root_identity(
    *,
    script_path: Path,
    tool_names: Sequence[str],
    registry: Registry,
    cli: OvidCli,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> RootIdentity:
    """Load-or-register this program's identity, then mint and self-verify a root OVID.

    First run: generate a keypair via the CLI and store it in the registry.
    Every run: mint a fresh root token under the registered key, with the
    mandate inferred from the *current* tool set (code is the source of truth;
    ``policy_drift`` reports divergence from what was registered).
    """
    unique_name = agent_unique_name(script_path)
    policy_set = infer_policy_set(tool_names)

    existing = registry.find(unique_name)
    if existing is None:
        keys = cli.keygen()
        registry.create(
            RegisteredAgent(
                unique_name=unique_name,
                keys=keys,
                policy_set=policy_set,
                wire_protocol=WIRE_PROTOCOL_VERSION,
            )
        )
    else:
        keys = existing.keys

    minted = cli.create_root(unique_name, policy_set, keys, ttl_seconds=ttl_seconds)
    verified = cli.verify(minted["jwt"], [keys.public_key])
    if not verified.get("valid"):
        raise OvidCliError(
            f'freshly minted root token for "{unique_name}" failed self-verification — '
            "the registered key material is corrupt; delete the registry item to re-register"
        )

    return RootIdentity(
        unique_name=unique_name,
        jwt=minted["jwt"],
        public_key=keys.public_key,
        policy_set=policy_set,
        expires_at=int(minted["exp"]),
        newly_registered=existing is None,
        policy_drift=existing is not None and existing.policy_set != policy_set,
    )
