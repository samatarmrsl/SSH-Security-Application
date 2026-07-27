"""Dedicated-chain iptables manager with strict command construction."""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
from datetime import datetime, timezone
from typing import Protocol

from ssh_security_app.config import ResponseConfig
from ssh_security_app.constants import HealthState
from ssh_security_app.models import (
    FirewallCommandResult,
    FirewallOperationResult,
    HealthStatus,
)
from ssh_security_app.response.rules import parse_project_rules

_CHAIN_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,27}$")


class CommandRunner(Protocol):
    def __call__(self, command: list[str]) -> subprocess.CompletedProcess: ...


class HealthCallback(Protocol):
    def __call__(self, health: HealthStatus) -> None: ...


class FirewallError(RuntimeError):
    """Raised when firewall state cannot be checked safely."""


class FirewallCommandBuilder:
    """Construct only commands scoped to the configured project chain."""

    def __init__(self, *, executable: str, chain: str, ssh_port: int) -> None:
        if not executable.startswith("/"):
            raise ValueError("iptables executable must be an absolute path")
        if not _CHAIN_PATTERN.fullmatch(chain):
            raise ValueError("invalid project iptables chain")
        if not 1 <= ssh_port <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        self.executable = executable
        self.chain = chain
        self.ssh_port = ssh_port

    def version(self) -> list[str]:
        return [self.executable, "--version"]

    def check_chain(self) -> list[str]:
        return [self.executable, "-w", "5", "-n", "-L", self.chain]

    def create_chain(self) -> list[str]:
        return [self.executable, "-w", "5", "-N", self.chain]

    def check_input_jump(self) -> list[str]:
        return [
            self.executable,
            "-w",
            "5",
            "-C",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            str(self.ssh_port),
            "-j",
            self.chain,
        ]

    def insert_input_jump(self) -> list[str]:
        return [
            self.executable,
            "-w",
            "5",
            "-I",
            "INPUT",
            "1",
            "-p",
            "tcp",
            "--dport",
            str(self.ssh_port),
            "-j",
            self.chain,
        ]

    def delete_input_jump(self) -> list[str]:
        return [
            self.executable,
            "-w",
            "5",
            "-D",
            "INPUT",
            "-p",
            "tcp",
            "--dport",
            str(self.ssh_port),
            "-j",
            self.chain,
        ]

    def delete_chain(self) -> list[str]:
        return [self.executable, "-w", "5", "-X", self.chain]

    def check_block(self, source_ip: str) -> list[str]:
        return self._rule_command("-C", source_ip)

    def insert_block(self, source_ip: str) -> list[str]:
        return self._rule_command("-I", source_ip, position="1")

    def delete_block(self, source_ip: str) -> list[str]:
        return self._rule_command("-D", source_ip)

    def list_rules(self) -> list[str]:
        return [self.executable, "-w", "5", "-S", self.chain]

    def _rule_command(
        self,
        action: str,
        source_ip: str,
        *,
        position: str | None = None,
    ) -> list[str]:
        normalized = str(ipaddress.IPv4Address(source_ip))
        command = [self.executable, "-w", "5", action, self.chain]
        if position is not None:
            command.append(position)
        command.extend(
            [
                "-s",
                normalized,
                "-p",
                "tcp",
                "--dport",
                str(self.ssh_port),
                "-j",
                "DROP",
            ]
        )
        return command


class FirewallManager:
    """Inspect and mutate only the dedicated SSH Security Application chain."""

    component_name = "firewall_manager"

    def __init__(
        self,
        response: ResponseConfig,
        *,
        ssh_port: int,
        runner: CommandRunner | None = None,
        on_health: HealthCallback | None = None,
    ) -> None:
        self.response = response
        self.builder = FirewallCommandBuilder(
            executable=response.iptables_path,
            chain=response.iptables_chain,
            ssh_port=ssh_port,
        )
        self.runner = runner or self._run_subprocess
        self.on_health = on_health
        self.logger = logging.getLogger("ssh_security_app.response.firewall_manager")

    def inspect_readiness(self) -> tuple[bool, bool]:
        version = self._execute(self.builder.version())
        if not version.succeeded:
            self._report_failure("iptables executable is unavailable", version)
            return False, False
        try:
            chain_exists, chain_result = self._check(self.builder.check_chain())
        except FirewallError as exc:
            self._report_failure(str(exc))
            return False, False
        if not chain_exists:
            self._report(
                HealthState.DEGRADED,
                error="project firewall chain does not exist",
                details={"chain": self.response.iptables_chain},
            )
            return True, False
        try:
            jump_exists, jump_result = self._check(self.builder.check_input_jump())
        except FirewallError as exc:
            self._report_failure(str(exc))
            return False, False
        if not jump_exists:
            self._report(
                HealthState.DEGRADED,
                error="project INPUT jump does not exist",
                details={"chain": self.response.iptables_chain},
            )
            return True, False
        self._report(
            HealthState.HEALTHY,
            details={
                "chain": self.response.iptables_chain,
                "chain_check_return_code": chain_result.return_code,
                "jump_check_return_code": jump_result.return_code,
            },
        )
        return True, True

    def initialize_chain(self) -> FirewallOperationResult:
        results: list[FirewallCommandResult] = []
        version = self._execute(self.builder.version())
        results.append(version)
        if not version.succeeded:
            return self._failure("iptables executable is unavailable", results)
        try:
            chain_exists, check_chain = self._check(self.builder.check_chain())
            results.append(check_chain)
            chain_created = False
            if not chain_exists:
                create_chain = self._execute(self.builder.create_chain())
                results.append(create_chain)
                if not create_chain.succeeded:
                    return self._failure("could not create the project chain", results)
                chain_created = True

            jump_exists, check_jump = self._check(self.builder.check_input_jump())
            results.append(check_jump)
            jump_created = False
            if not jump_exists:
                insert_jump = self._execute(self.builder.insert_input_jump())
                results.append(insert_jump)
                if not insert_jump.succeeded:
                    return self._failure("could not add the INPUT jump", results)
                jump_created = True

            confirmed_chain, confirm_chain = self._check(self.builder.check_chain())
            confirmed_jump, confirm_jump = self._check(self.builder.check_input_jump())
            results.extend((confirm_chain, confirm_jump))
            if not confirmed_chain or not confirmed_jump:
                return self._failure("firewall initialization could not be confirmed", results)
        except FirewallError as exc:
            return self._failure(str(exc), results)

        changed = chain_created or jump_created
        message = (
            "project chain and INPUT jump initialized"
            if changed
            else "project chain and INPUT jump already exist"
        )
        self._report(
            HealthState.HEALTHY,
            details={"chain": self.response.iptables_chain, "initialized": True},
        )
        return FirewallOperationResult(True, changed, message, tuple(results))

    def rule_exists(self, source_ip: str) -> bool:
        exists, _result = self._check(self.builder.check_block(source_ip))
        return exists

    def insert_block_rule(self, source_ip: str) -> FirewallOperationResult:
        return self._change_rule(source_ip, insert=True)

    def delete_block_rule(self, source_ip: str) -> FirewallOperationResult:
        return self._change_rule(source_ip, insert=False)

    def list_project_rules(
        self,
    ) -> tuple[FirewallOperationResult, tuple[str, ...]]:
        result = self._execute(self.builder.list_rules())
        if not result.succeeded:
            return self._failure("could not list project rules", [result]), ()
        rules = tuple(line for line in result.stdout.splitlines() if line.strip())
        return (
            FirewallOperationResult(
                True,
                False,
                f"listed {len(rules)} project-chain rules",
                (result,),
            ),
            rules,
        )

    def cleanup_project_chain(self) -> FirewallOperationResult:
        """Remove only recognized project rules, its exact jump, and empty chain."""

        results: list[FirewallCommandResult] = []
        try:
            chain_exists, chain_check = self._check(self.builder.check_chain())
            results.append(chain_check)
            if not chain_exists:
                return FirewallOperationResult(
                    True,
                    False,
                    "project firewall chain is already absent",
                    tuple(results),
                )

            listed, lines = self.list_project_rules()
            results.extend(listed.command_results)
            if not listed.success:
                return self._failure(listed.message, results)
            parsed = parse_project_rules(
                lines,
                chain=self.builder.chain,
                ssh_port=self.builder.ssh_port,
            )
            duplicates = {
                source: count for source, count in parsed.source_counts.items() if count != 1
            }
            if parsed.unknown_rules or duplicates:
                return self._failure(
                    "cleanup refused because the project chain contains unknown or duplicate rules",
                    results,
                )

            for source in parsed.sources:
                deletion = self.delete_block_rule(source)
                results.extend(deletion.command_results)
                if not deletion.success:
                    return self._failure(deletion.message, results)

            jump_exists, jump_check = self._check(self.builder.check_input_jump())
            results.append(jump_check)
            if jump_exists:
                jump_delete = self._execute(self.builder.delete_input_jump())
                results.append(jump_delete)
                if not jump_delete.succeeded:
                    return self._failure("could not remove the exact INPUT jump", results)
                jump_still_exists, jump_confirmation = self._check(self.builder.check_input_jump())
                results.append(jump_confirmation)
                if jump_still_exists:
                    return self._failure("INPUT jump deletion could not be confirmed", results)

            chain_delete = self._execute(self.builder.delete_chain())
            results.append(chain_delete)
            if not chain_delete.succeeded:
                return self._failure("could not delete the empty project chain", results)
            chain_still_exists, chain_confirmation = self._check(self.builder.check_chain())
            results.append(chain_confirmation)
            if chain_still_exists:
                return self._failure("project chain deletion could not be confirmed", results)
        except FirewallError as exc:
            return self._failure(str(exc), results)

        self._report(
            HealthState.HEALTHY,
            details={"chain": self.response.iptables_chain, "cleaned_up": True},
        )
        return FirewallOperationResult(
            True,
            True,
            "recognized project rules, exact INPUT jump, and project chain removed",
            tuple(results),
        )

    def _change_rule(self, source_ip: str, *, insert: bool) -> FirewallOperationResult:
        results: list[FirewallCommandResult] = []
        try:
            chain_exists, chain_check = self._check(self.builder.check_chain())
            results.append(chain_check)
            if not chain_exists:
                return self._failure("project firewall chain does not exist", results)
            rule_exists, rule_check = self._check(self.builder.check_block(source_ip))
            results.append(rule_check)
            if insert and rule_exists:
                return FirewallOperationResult(
                    True,
                    False,
                    "exact block rule already exists",
                    tuple(results),
                )
            if not insert and not rule_exists:
                return FirewallOperationResult(
                    True,
                    False,
                    "exact block rule is already absent",
                    tuple(results),
                )

            command = (
                self.builder.insert_block(source_ip)
                if insert
                else self.builder.delete_block(source_ip)
            )
            change = self._execute(command)
            results.append(change)
            if not change.succeeded:
                operation = "insert" if insert else "delete"
                return self._failure(f"could not {operation} exact block rule", results)

            confirmed, confirmation = self._check(self.builder.check_block(source_ip))
            results.append(confirmation)
            expected = insert
            if confirmed is not expected:
                return self._failure("firewall rule change could not be confirmed", results)
        except (FirewallError, ipaddress.AddressValueError) as exc:
            return self._failure(str(exc), results)

        self._report(
            HealthState.HEALTHY,
            details={"chain": self.response.iptables_chain, "last_rule_change": source_ip},
        )
        return FirewallOperationResult(
            True,
            True,
            "exact block rule inserted" if insert else "exact block rule deleted",
            tuple(results),
        )

    def _check(self, command: list[str]) -> tuple[bool, FirewallCommandResult]:
        result = self._execute(command)
        if result.return_code == 0:
            return True, result
        if result.return_code == 1:
            return False, result
        raise FirewallError(
            f"firewall check failed with status {result.return_code}: "
            f"{result.stderr or 'no error output'}"
        )

    def _execute(self, command: list[str]) -> FirewallCommandResult:
        try:
            completed = self.runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            self.logger.error("firewall command failed to execute: %s", exc)
            return FirewallCommandResult(tuple(command), 126, "", str(exc))
        return FirewallCommandResult(
            command=tuple(command),
            return_code=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )

    def _run_subprocess(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            timeout=self.response.command_timeout_seconds,
        )

    def _failure(
        self,
        message: str,
        results: list[FirewallCommandResult],
    ) -> FirewallOperationResult:
        self._report_failure(message, results[-1] if results else None)
        return FirewallOperationResult(False, False, message, tuple(results))

    def _report_failure(
        self,
        message: str,
        result: FirewallCommandResult | None = None,
    ) -> None:
        details: dict[str, object] = {"chain": self.response.iptables_chain}
        if result is not None:
            details["return_code"] = result.return_code
            details["stderr"] = result.stderr
        self._report(HealthState.FAILED, error=message, details=details)

    def _report(
        self,
        status: HealthState,
        *,
        error: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        health = HealthStatus(
            component=self.component_name,
            status=status,
            last_success=datetime.now(timezone.utc) if status is HealthState.HEALTHY else None,
            last_error=error,
            details=details or {},
        )
        if self.on_health:
            self.on_health(health)
        log_method = self.logger.error if status is HealthState.FAILED else self.logger.info
        log_method("firewall status=%s details=%s error=%s", status, details, error)
