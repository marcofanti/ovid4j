import subprocess
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic_ai import Agent

from event_logging import make_event_stream_printer, print_response
from ovid_identity import (
    OnePasswordRegistry,
    OvidCli,
    agent_tool_names,
    bootstrap_root_identity,
)

load_dotenv(Path(__file__).resolve().parents[1] / ".env")


def build_agent(
    model: Any = "anthropic:claude-haiku-4-5", project_root: Path | None = None
) -> Agent:
    project_root = project_root or Path(__file__).resolve().parents[1] / "scratch_space"

    agent = Agent(
        model,
        name="read_write_shell_agent",
        retries=3,
        instructions="You are a helpful assistant. Be concise.",
    )

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def read_file(path: str) -> str:
        """Read a file.

        Args:
            path: The path to the file, relative to the scratch_space directory.
        """
        try:
            return (project_root / path).read_text()
        except Exception as error:
            return str(error)

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def write_file(path: str, content: str) -> str:
        """Write a file.

        Args:
            path: The path to the file, relative to the scratch_space directory.
            content: The text content to write.
        """
        try:
            full_path = project_root / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
            return f"Wrote {full_path}"
        except Exception as error:
            return str(error)

    @agent.tool_plain(docstring_format="google", require_parameter_descriptions=True)
    def run_command(command: str) -> str:
        """Run a shell command.

        Args:
            command: The shell command to run inside the scratch_space directory.
        """
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=project_root,
                capture_output=True,
                text=True,
            )
            return f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
        except Exception as error:
            return str(error)

    return agent


def main(user_prompt: str) -> None:
    agent = build_agent()

    # This program is an OVID root: its identity is this file on this machine,
    # its keys live in 1Password, and its mandate is inferred from its tools.
    identity = bootstrap_root_identity(
        script_path=Path(__file__),
        tool_names=agent_tool_names(agent),
        registry=OnePasswordRegistry(),
        cli=OvidCli.locate(),
    )
    print(f"OVID root: {identity.unique_name}")
    print(
        f"  registered: {'new' if identity.newly_registered else 'existing'}"
        f" · token expires at {identity.expires_at}"
    )
    if identity.policy_drift:
        print("  WARNING: tool set changed since registration — registry mandate is stale")

    result = agent.run_sync(user_prompt, event_stream_handler=make_event_stream_printer())
    print_response(result.output)


if __name__ == "__main__":
    main(input("Prompt: "))
