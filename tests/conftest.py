from __future__ import annotations

import subprocess

import pytest


class FakeIptables:
    """In-memory iptables command runner for tests; never touches the host."""

    def __init__(self) -> None:
        self.chain_exists = False
        self.input_jump_exists = False
        self.blocked_sources: set[str] = set()
        self.commands: list[list[str]] = []
        self.fail_next_change = False

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess:
        self.commands.append(command.copy())
        if command[-1] == "--version":
            return self._completed(command, 0, "iptables v1.8.4")

        action = self._action(command)
        if action == "-L":
            return self._completed(command, 0 if self.chain_exists else 1)
        if action == "-N":
            if self.fail_next_change:
                self.fail_next_change = False
                return self._completed(command, 2, stderr="simulated create failure")
            self.chain_exists = True
            return self._completed(command, 0)
        if action == "-X":
            if self.fail_next_change:
                self.fail_next_change = False
                return self._completed(command, 2, stderr="simulated chain delete failure")
            if self.blocked_sources:
                return self._completed(command, 1, stderr="chain is not empty")
            self.chain_exists = False
            return self._completed(command, 0)
        if action == "-S":
            if not self.chain_exists:
                return self._completed(command, 1, stderr="chain missing")
            rules = [
                f"-A SSH_SECURITY_APP -s {source}/32 -p tcp --dport 22 -j DROP"
                for source in sorted(self.blocked_sources)
            ]
            return self._completed(command, 0, "\n".join(rules))
        if action == "-C" and "INPUT" in command:
            return self._completed(command, 0 if self.input_jump_exists else 1)
        if action == "-I" and "INPUT" in command:
            if self.fail_next_change:
                self.fail_next_change = False
                return self._completed(command, 2, stderr="simulated jump failure")
            self.input_jump_exists = True
            return self._completed(command, 0)
        if action == "-D" and "INPUT" in command:
            if self.fail_next_change:
                self.fail_next_change = False
                return self._completed(command, 2, stderr="simulated jump delete failure")
            self.input_jump_exists = False
            return self._completed(command, 0)

        source = command[command.index("-s") + 1]
        if action == "-C":
            return self._completed(command, 0 if source in self.blocked_sources else 1)
        if action == "-I":
            if self.fail_next_change:
                self.fail_next_change = False
                return self._completed(command, 2, stderr="simulated insert failure")
            self.blocked_sources.add(source)
            return self._completed(command, 0)
        if action == "-D":
            if self.fail_next_change:
                self.fail_next_change = False
                return self._completed(command, 2, stderr="simulated delete failure")
            self.blocked_sources.discard(source)
            return self._completed(command, 0)
        return self._completed(command, 2, stderr="unexpected test command")

    @staticmethod
    def _action(command: list[str]) -> str:
        return next(item for item in ("-L", "-N", "-X", "-S", "-C", "-I", "-D") if item in command)

    @staticmethod
    def _completed(
        command: list[str],
        return_code: int,
        stdout: str = "",
        stderr: str = "",
    ) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(command, return_code, stdout, stderr)


@pytest.fixture
def fake_iptables() -> FakeIptables:
    return FakeIptables()
