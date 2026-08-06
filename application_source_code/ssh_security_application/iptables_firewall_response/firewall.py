"""Project-owned iptables rules, temporary blocks, expiry, and reconciliation."""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
import subprocess
import uuid
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Event
from typing import Protocol

from ssh_security_application.audit import AuditService
from ssh_security_application.config import ResponseConfig
from ssh_security_application.constants import BlockStatus, Decision, HealthState
from ssh_security_application.health import HealthMonitor
from ssh_security_application.ip_validation import validate_ip_address
from ssh_security_application.models import (
    BlockRecord,
    BlockResponse,
    Detection,
    FirewallCommandResult,
    FirewallOperationResult,
    HealthStatus,
)
from ssh_security_application.sqlite_data_storage.storage import (
    AllowlistRepository,
    BlockRepository,
)
from ssh_security_application.ssh_brute_force_detection.normalization import (
    ensure_utc,
)


# ---- iptables rule parser ----
@dataclass(frozen=True)
class ParsedProjectRules:
    sources: tuple[str, ...]
    unknown_rules: tuple[str, ...]

    @property
    def source_counts(self) -> Counter[str]:
        return Counter(self.sources)


def parse_project_rules(
    rules: tuple[str, ...],
    *,
    chain: str,
    ssh_port: int,
) -> ParsedProjectRules:
    """Separate exact SSH block rules from declarations or unknown rules."""

    sources: list[str] = []
    unknown: list[str] = []
    for rule in rules:
        try:
            tokens = shlex.split(rule)
        except ValueError:
            unknown.append(rule)
            continue
        if tokens == ["-N", chain]:
            continue
        if tokens[:2] != ["-A", chain]:
            unknown.append(rule)
            continue
        body = tokens[2:]
        expected_tail = ["-p", "tcp", "--dport", str(ssh_port), "-j", "DROP"]
        canonical_tail = [
            "-p",
            "tcp",
            "-m",
            "tcp",
            "--dport",
            str(ssh_port),
            "-j",
            "DROP",
        ]
        if (
            len(body) < 2
            or body[0] != "-s"
            or body[2:]
            not in (
                expected_tail,
                canonical_tail,
            )
        ):
            unknown.append(rule)
            continue
        try:
            network = ipaddress.IPv4Network(body[1], strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            unknown.append(rule)
            continue
        if network.prefixlen != 32:
            unknown.append(rule)
            continue
        sources.append(str(network.network_address))
    return ParsedProjectRules(tuple(sources), tuple(unknown))


# ---- iptables command manager ----
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

    def input_jump_rule(self) -> str:
        return f"-A INPUT -p tcp --dport {self.ssh_port} -j {self.chain}"

    def source_drop_rule(self, source_ip: str) -> str:
        normalized = str(ipaddress.IPv4Address(source_ip))
        return f"-A {self.chain} -s {normalized}/32 -p tcp --dport {self.ssh_port} -j DROP"

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
        self.logger = logging.getLogger(
            "ssh_security_application.iptables_firewall_response.firewall"
        )

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


# ---- Temporary block manager ----
class BlockManager:
    """Coordinate validated firewall and SQLite block creation."""

    def __init__(
        self,
        *,
        firewall: FirewallManager,
        blocks: BlockRepository,
        allowlist: AllowlistRepository,
        audit: AuditService,
        duration_seconds: int,
        protected_addresses: Iterable[str] = (),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if duration_seconds < 1:
            raise ValueError("block duration must be positive")
        self.firewall = firewall
        self.blocks = blocks
        self.allowlist = allowlist
        self.audit = audit
        self.duration = timedelta(seconds=duration_seconds)
        self.protected_addresses = tuple(protected_addresses)
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def block_detection(self, detection: Detection) -> BlockResponse:
        now = ensure_utc(self.clock())
        if detection.decision is not Decision.BLOCK:
            return self._reject(
                detection,
                "detection decision does not authorize a firewall block",
            )
        allowlisted = self.allowlist.is_allowlisted(detection.source_ip, at=now)
        validation = validate_ip_address(
            detection.source_ip,
            protected_addresses=self.protected_addresses,
            allowlisted=allowlisted,
        )
        if not validation.eligible_for_automatic_blocking:
            return self._reject(
                detection,
                validation.exclusion_reason or "source is not eligible for blocking",
            )
        if self.blocks.get_active(detection.source_ip) is not None:
            return self._reject(detection, "source already has an active database block")
        try:
            if self.firewall.rule_exists(detection.source_ip):
                return self._reject(
                    detection,
                    "exact firewall rule exists without an active database block",
                )
        except FirewallError as exc:
            return self._reject(detection, f"could not verify duplicate rule: {exc}")

        firewall_result = self.firewall.insert_block_rule(detection.source_ip)
        if not firewall_result.success or not firewall_result.changed:
            return self._reject(
                detection,
                f"firewall block failed: {firewall_result.message}",
                firewall_result=firewall_result,
            )

        block = BlockRecord(
            block_id=str(uuid.uuid4()),
            source_ip=detection.source_ip,
            detection_id=detection.detection_id,
            blocked_at=now,
            expires_at=now + self.duration,
            removed_at=None,
            status=BlockStatus.ACTIVE,
            removal_method=None,
            firewall_result=firewall_result.message,
            error_message=None,
        )
        try:
            self.blocks.activate(block)
        except Exception as exc:
            compensation = self.firewall.delete_block_rule(detection.source_ip)
            message = f"database block activation failed: {exc}"
            if not compensation.success:
                message += f"; firewall rollback also failed: {compensation.message}"
            return self._reject(
                detection,
                message,
                firewall_result=firewall_result,
            )

        self.audit.record(
            component="block_manager",
            action="successful_block",
            target=detection.source_ip,
            result="success",
            details={
                "block_id": block.block_id,
                "detection_id": detection.detection_id,
                "blocked_at": block.blocked_at.isoformat(),
                "expires_at": block.expires_at.isoformat(),
            },
        )
        return BlockResponse(
            True,
            f"source blocked until {block.expires_at.isoformat()}",
            block,
            firewall_result,
        )

    def _reject(
        self,
        detection: Detection,
        message: str,
        *,
        firewall_result: FirewallOperationResult | None = None,
    ) -> BlockResponse:
        self.audit.record(
            component="block_manager",
            action="failed_block",
            target=detection.source_ip,
            result="failure",
            details={"detection_id": detection.detection_id, "error": message},
        )
        return BlockResponse(False, message, firewall_result=firewall_result)


# ---- Expired block removal ----
@dataclass(frozen=True)
class ExpirationCycleResult:
    examined: int
    expired: int
    failed: int


class ExpirationWorker:
    component_name = "expiration_worker"

    def __init__(
        self,
        *,
        firewall: FirewallManager,
        blocks: BlockRepository,
        audit: AuditService,
        health: HealthMonitor,
        clock: Callable[[], datetime] | None = None,
        on_unblock: Callable[[BlockRecord, str], None] | None = None,
    ) -> None:
        self.firewall = firewall
        self.blocks = blocks
        self.audit = audit
        self.health = health
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.on_unblock = on_unblock

    def process_once(self, *, limit: int = 100) -> ExpirationCycleResult:
        now = ensure_utc(self.clock())
        candidates = self.blocks.list_expired(at=now, limit=limit)
        expired = 0
        failed = 0
        for block in candidates:
            try:
                exists = self.firewall.rule_exists(block.source_ip)
            except FirewallError as exc:
                self._record_failure(block.block_id, block.source_ip, str(exc))
                failed += 1
                continue

            firewall_message = "exact block rule was already absent"
            if exists:
                operation = self.firewall.delete_block_rule(block.source_ip)
                firewall_message = operation.message
                if not operation.success:
                    self._record_failure(
                        block.block_id,
                        block.source_ip,
                        operation.message,
                    )
                    failed += 1
                    continue

            updated = self.blocks.mark_removed(
                block.block_id,
                status=BlockStatus.EXPIRED,
                removal_method="Automatic",
                removed_at=now,
                firewall_result=firewall_message,
            )
            if not updated:
                self._record_failure(
                    block.block_id,
                    block.source_ip,
                    "block status changed while expiration was being processed",
                )
                failed += 1
                continue
            expired += 1
            self.audit.record(
                component=self.component_name,
                action="automatic_unblock",
                target=block.source_ip,
                result="success",
                details={"block_id": block.block_id, "firewall": firewall_message},
            )
            if self.on_unblock is not None:
                self.on_unblock(block, firewall_message)

        if failed:
            self.health.degraded(
                self.component_name,
                f"{failed} expired block(s) could not be processed",
                examined=len(candidates),
                expired=expired,
                failed=failed,
            )
        else:
            self.health.healthy(
                self.component_name,
                examined=len(candidates),
                expired=expired,
                failed=0,
            )
        return ExpirationCycleResult(len(candidates), expired, failed)

    def run(self, stop_event: Event, *, interval_seconds: int) -> None:
        if interval_seconds < 1:
            raise ValueError("expiration interval must be positive")
        while not stop_event.is_set():
            self.process_once()
            stop_event.wait(interval_seconds)
        self.health.stopped(self.component_name)

    def _record_failure(self, block_id: str, source_ip: str, message: str) -> None:
        self.blocks.record_error(block_id, error_message=message)
        self.audit.record(
            component=self.component_name,
            action="automatic_unblock",
            target=source_ip,
            result="failure",
            details={"block_id": block_id, "error": message},
        )


# ---- Firewall database reconciliation ----
@dataclass(frozen=True)
class ReconciliationResult:
    active_consistent: int
    expired_removed: int
    missing_marked_inconsistent: int
    unknown_rules: int
    failed: int


class FirewallReconciler:
    component_name = "firewall_reconciler"

    def __init__(
        self,
        *,
        firewall: FirewallManager,
        blocks: BlockRepository,
        audit: AuditService,
        health: HealthMonitor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.firewall = firewall
        self.blocks = blocks
        self.audit = audit
        self.health = health
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def reconcile(self, *, limit: int = 10_000) -> ReconciliationResult:
        now = ensure_utc(self.clock())
        operation, lines = self.firewall.list_project_rules()
        if not operation.success:
            self.health.failed(self.component_name, operation.message)
            self.audit.record(
                component=self.component_name,
                action="reconciliation",
                result="failure",
                details={"error": operation.message},
            )
            return ReconciliationResult(0, 0, 0, 0, 1)

        parsed = parse_project_rules(
            lines,
            chain=self.firewall.builder.chain,
            ssh_port=self.firewall.builder.ssh_port,
        )
        remaining = parsed.source_counts
        consistent = 0
        expired = 0
        inconsistent = 0
        failed = 0

        for block in self.blocks.list_active(limit):
            rule_count = remaining.get(block.source_ip, 0)
            if block.expires_at <= now:
                firewall_message = "exact block rule was already absent"
                if rule_count:
                    removal = self.firewall.delete_block_rule(block.source_ip)
                    firewall_message = removal.message
                    if not removal.success:
                        self.blocks.record_error(
                            block.block_id,
                            error_message=removal.message,
                            firewall_result=removal.message,
                        )
                        self._audit_block(
                            block.source_ip, block.block_id, "failure", removal.message
                        )
                        failed += 1
                        continue
                    remaining[block.source_ip] -= 1
                if self.blocks.mark_removed(
                    block.block_id,
                    status=BlockStatus.EXPIRED,
                    removal_method="Reconciliation",
                    removed_at=now,
                    firewall_result=firewall_message,
                ):
                    expired += 1
                    self._audit_block(
                        block.source_ip,
                        block.block_id,
                        "expired",
                        firewall_message,
                    )
                else:
                    failed += 1
                continue

            if rule_count:
                remaining[block.source_ip] -= 1
                consistent += 1
                continue

            message = "active database block has no matching project firewall rule"
            if self.blocks.mark_removed(
                block.block_id,
                status=BlockStatus.INCONSISTENT,
                removal_method="Reconciliation",
                removed_at=now,
                error_message=message,
            ):
                inconsistent += 1
                self._audit_block(block.source_ip, block.block_id, "inconsistent", message)
            else:
                failed += 1

        unknown = len(parsed.unknown_rules) + sum(
            count for count in remaining.values() if count > 0
        )
        for line in parsed.unknown_rules:
            self._audit_unknown(line)
        for source, count in remaining.items():
            for _ in range(max(0, count)):
                self._audit_unknown(f"unowned exact rule for {source}")

        result = ReconciliationResult(
            consistent,
            expired,
            inconsistent,
            unknown,
            failed,
        )
        if failed:
            self.health.failed(
                self.component_name,
                f"{failed} reconciliation action(s) failed",
                **result.__dict__,
            )
        elif inconsistent or unknown:
            self.health.degraded(
                self.component_name,
                "firewall and database state require operator review",
                **result.__dict__,
            )
        else:
            self.health.healthy(self.component_name, **result.__dict__)
        self.audit.record(
            component=self.component_name,
            action="reconciliation_summary",
            result="failure" if failed else "review" if inconsistent or unknown else "success",
            details=result.__dict__,
        )
        return result

    def _audit_block(
        self,
        source_ip: str,
        block_id: str,
        result: str,
        message: str,
    ) -> None:
        self.audit.record(
            component=self.component_name,
            action="reconciliation",
            target=source_ip,
            result=result,
            details={"block_id": block_id, "message": message},
        )

    def _audit_unknown(self, rule: str) -> None:
        self.audit.record(
            component=self.component_name,
            action="unknown_firewall_rule",
            result="review",
            details={"rule": rule, "automatic_deletion": False},
        )


# ---- Response background worker ----
class ResponseWorker:
    component_name = "response_worker"

    def __init__(
        self,
        *,
        expiration: ExpirationWorker,
        reconciler: FirewallReconciler,
        health: HealthMonitor,
        interval_seconds: int,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("response worker interval must be positive")
        self.expiration = expiration
        self.reconciler = reconciler
        self.health = health
        self.interval_seconds = interval_seconds
        self.logger = logging.getLogger(
            "ssh_security_application.iptables_firewall_response.firewall"
        )

    def run(self, stop_event: Event) -> None:
        self.logger.info("response worker starting with startup reconciliation")
        self.reconciler.reconcile()
        self.health.healthy(
            self.component_name,
            interval_seconds=self.interval_seconds,
        )
        try:
            while not stop_event.is_set():
                expiration = self.expiration.process_once()
                self.health.healthy(
                    self.component_name,
                    expiration=expiration.__dict__,
                )
                stop_event.wait(self.interval_seconds)
        finally:
            self.health.stopped(self.component_name)
            self.logger.info("response worker stopped")
