"""One-command installer and verifier for the authorized Ubuntu live lab."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

CommandRunner = Callable[..., subprocess.CompletedProcess]

SERVICE_USER = "sshsecurityapp"
INSTALL_ROOT = Path("/opt/ssh-security-application")
CONFIG_DIRECTORY = Path("/etc/ssh-security-app")
CONFIG_PATH = CONFIG_DIRECTORY / "config.json"
DATA_DIRECTORY = Path("/var/lib/ssh-security-app")
LOG_DIRECTORY = Path("/var/log/ssh-security-app")
DATABASE_PATH = DATA_DIRECTORY / "ssh_security_application.db"
LOG_PATH = LOG_DIRECTORY / "ssh_security_application.log"
FIREWALL_UNIT = "ssh-security-application-firewall.service"
APPLICATION_UNIT = "ssh-security-application.service"
PROJECT_CHAIN = "SSH_SECURITY_APP"

REQUIRED_PACKAGES = (
    "rsync",
    "python3",
    "python3-venv",
    "python3-pip",
    "sqlite3",
    "tcpdump",
    "libcap2-bin",
    "iptables",
    "openssh-server",
)


class LiveLabSetupError(RuntimeError):
    """Raised when the live-lab plan cannot be applied or verified safely."""


@dataclass(frozen=True)
class InterfaceAddress:
    address: str
    prefix_length: int

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(
            f"{self.address}/{self.prefix_length}",
            strict=False,
        )


@dataclass(frozen=True)
class HostNetwork:
    interfaces: dict[str, tuple[InterfaceAddress, ...]]

    @property
    def protected_addresses(self) -> tuple[str, ...]:
        return tuple(
            item.address
            for addresses in self.interfaces.values()
            for item in addresses
            if not ipaddress.IPv4Address(item.address).is_loopback
        )


@dataclass(frozen=True)
class LiveLabPlan:
    repository_root: Path
    lab_interface: str
    server_ip: str
    client_ip: str
    protected_addresses: tuple[str, ...]
    ssh_port: int
    block_duration_seconds: int
    firewall_frontend: str
    firewalld_zone: str | None
    reset_host_iptables: bool


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Install, configure, start, and verify the complete SSH Security "
            "Application on an authorized Ubuntu lab VM."
        )
    )
    parser.add_argument(
        "--lab-interface",
        required=True,
        help="server interface connected to the disposable client, for example ens37",
    )
    parser.add_argument(
        "--client-ip",
        required=True,
        help="disposable lab client's IPv4 address, for example 192.168.12.3",
    )
    parser.add_argument(
        "--server-ip",
        help="server IPv4 on the lab interface; auto-detected when the interface has one address",
    )
    parser.add_argument("--ssh-port", type=_port, default=22)
    parser.add_argument(
        "--block-duration-seconds",
        type=_positive_int,
        default=120,
        help="temporary SSH block duration (default: 120)",
    )
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument(
        "--apply",
        action="store_true",
        help="perform the installation and start the complete infrastructure",
    )
    operation.add_argument(
        "--verify-only",
        action="store_true",
        help="run post-install health checks without reconfiguring the host",
    )
    parser.add_argument(
        "--confirm-firewall-changes",
        action="store_true",
        help="required with --apply to acknowledge dedicated-chain firewall changes",
    )
    parser.add_argument(
        "--skip-package-install",
        action="store_true",
        help="skip apt-get update/install when prerequisites are already present",
    )
    parser.add_argument(
        "--reset-host-iptables",
        action="store_true",
        help=(
            "authorized lab only: reset the host iptables filter table before "
            "installing the project chain"
        ),
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: CommandRunner = subprocess.run,
    repository_root: Path | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = (
            repository_root.resolve()
            if repository_root is not None
            else Path(__file__).resolve().parents[2]
        )
        plan = create_plan(args, repository_root=root, runner=runner)
        print_plan(plan)
        if args.verify_only:
            sudo = _required_executable("sudo")
            _checked_run([sudo, "-v"], runner=runner)
            verify_installation(plan, runner=runner, use_sudo=True)
            return 0
        if not args.apply:
            print("\nPreview only. Re-run with --apply and --confirm-firewall-changes to install.")
            return 0
        if not args.confirm_firewall_changes:
            raise LiveLabSetupError(
                "--apply requires --confirm-firewall-changes because the installer "
                f"creates the dedicated {PROJECT_CHAIN} chain"
            )
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise LiveLabSetupError("run the installer as the normal project user, not as root")
        apply_plan(
            plan,
            runner=runner,
            install_packages=not args.skip_package_install,
        )
        verify_installation(plan, runner=runner, use_sudo=True)
    except LiveLabSetupError as exc:
        print(f"Live-lab setup error: {exc}", file=sys.stderr)
        return 1
    print("\nLive-lab infrastructure is ready.")
    print(f"  SSH target: {plan.server_ip}:{plan.ssh_port}")
    print(f"  Disposable client: {plan.client_ip}")
    print(f"  Temporary block duration: {plan.block_duration_seconds} seconds")
    print("\nNo attack traffic was generated. The disposable client can now be tested separately.")
    return 0


def create_plan(
    args: argparse.Namespace,
    *,
    repository_root: Path,
    runner: CommandRunner,
) -> LiveLabPlan:
    _validate_repository(repository_root)
    network = discover_network(runner=runner)
    addresses = network.interfaces.get(args.lab_interface)
    if not addresses:
        available = ", ".join(sorted(network.interfaces)) or "none"
        raise LiveLabSetupError(
            f"lab interface {args.lab_interface!r} is not an active IPv4 interface; "
            f"available: {available}"
        )
    server = _select_server_address(addresses, args.server_ip)
    client = _validate_client_address(
        args.client_ip,
        server=server,
        protected_addresses=network.protected_addresses,
    )
    frontend = detect_firewall_frontend(runner=runner)
    zone = (
        detect_firewalld_zone(args.lab_interface, runner=runner)
        if frontend == "firewalld"
        else None
    )
    return LiveLabPlan(
        repository_root=repository_root,
        lab_interface=args.lab_interface,
        server_ip=server.address,
        client_ip=client,
        protected_addresses=network.protected_addresses,
        ssh_port=args.ssh_port,
        block_duration_seconds=args.block_duration_seconds,
        firewall_frontend=frontend,
        firewalld_zone=zone,
        reset_host_iptables=args.reset_host_iptables,
    )


def print_plan(plan: LiveLabPlan) -> None:
    print("SSH Security Application live-lab plan:")
    print(f"  repository: {plan.repository_root}")
    print(f"  lab interface: {plan.lab_interface}")
    print(f"  server IPv4: {plan.server_ip}")
    print(f"  disposable client IPv4: {plan.client_ip}")
    print(f"  protected server addresses: {', '.join(plan.protected_addresses)}")
    print(f"  SSH endpoint: {plan.server_ip}:{plan.ssh_port}")
    print("  response mode: automatic_response")
    print(f"  block duration: {plan.block_duration_seconds} seconds")
    print(f"  host firewall frontend: {plan.firewall_frontend}")
    if plan.firewalld_zone:
        print(f"  firewalld zone: {plan.firewalld_zone}")
    print(
        "  lab iptables reset: "
        + (
            "yes; filter table policies set to ACCEPT and custom chains flushed"
            if plan.reset_host_iptables
            else "no"
        )
    )
    print(f"  project chain: {PROJECT_CHAIN}")


def apply_plan(
    plan: LiveLabPlan,
    *,
    runner: CommandRunner = subprocess.run,
    install_packages: bool = True,
) -> None:
    tools = _bootstrap_tools()
    sudo = tools["sudo"]
    _checked_run([sudo, "-v"], runner=runner)
    if install_packages:
        apt_get = _required_executable("apt-get")
        _checked_run([sudo, apt_get, "update"], runner=runner)
        _checked_run(
            [sudo, apt_get, "install", "-y", *REQUIRED_PACKAGES],
            runner=runner,
        )

    tools = _installed_tools()
    ssh_unit = _detect_ssh_unit(tools["systemctl"], runner=runner)
    if ssh_unit is None:
        raise LiveLabSetupError(
            "OpenSSH was installed but neither ssh.service nor sshd.service is available"
        )
    _checked_run(
        [sudo, tools["systemctl"], "enable", "--now", ssh_unit],
        runner=runner,
    )
    _checked_run(
        [
            sudo,
            tools["setcap"],
            "cap_net_raw,cap_net_admin=eip",
            tools["tcpdump"],
        ],
        runner=runner,
    )

    _stop_existing_services(sudo=sudo, systemctl=tools["systemctl"], runner=runner)
    if plan.reset_host_iptables:
        _reset_host_iptables_for_lab(plan, sudo=sudo, tools=tools, runner=runner)
    _configure_host_firewall(plan, sudo=sudo, runner=runner)
    _ensure_service_account(sudo=sudo, tools=tools, runner=runner)
    _install_directories(sudo=sudo, tools=tools, runner=runner)
    _synchronize_source(plan, sudo=sudo, tools=tools, runner=runner)
    _install_production_environment(sudo=sudo, tools=tools, runner=runner)
    _install_configuration(plan, ssh_unit=ssh_unit, sudo=sudo, tools=tools, runner=runner)
    _initialize_database(sudo=sudo, runner=runner)
    _install_systemd_units(plan, sudo=sudo, tools=tools, runner=runner)
    _remove_stale_project_firewall(sudo=sudo, runner=runner)
    _restore_runtime_ownership(sudo=sudo, tools=tools, runner=runner)
    _start_services(sudo=sudo, tools=tools, runner=runner)


def verify_installation(
    plan: LiveLabPlan,
    *,
    runner: CommandRunner = subprocess.run,
    use_sudo: bool,
) -> None:
    systemctl = _required_executable("systemctl")
    prefix = [_required_executable("sudo")] if use_sudo else []
    checks: list[tuple[str, bool, str]] = []

    for unit in (
        _detect_ssh_unit(systemctl, runner=runner),
        FIREWALL_UNIT,
        APPLICATION_UNIT,
    ):
        if unit is None:
            checks.append(("OpenSSH unit", False, "not found"))
            continue
        completed = _captured_run(
            [systemctl, "is-active", unit],
            runner=runner,
            allowed_returncodes=(0, 3, 4),
        )
        active = completed.returncode == 0 and completed.stdout.strip() == "active"
        checks.append((unit, active, completed.stdout.strip() or "inactive"))

    config_ok = _run_for_status(
        [
            *prefix,
            str(INSTALL_ROOT / ".venv/bin/ssh-security-app"),
            "--config",
            str(CONFIG_PATH),
            "validate-config",
        ],
        runner=runner,
    )
    checks.append(("production configuration", config_ok, str(CONFIG_PATH)))

    firewall_ok = _run_for_status(
        [
            *prefix,
            str(INSTALL_ROOT / ".venv/bin/ssh-security-app"),
            "--config",
            str(CONFIG_PATH),
            "rules",
        ],
        runner=runner,
    )
    checks.append(("project firewall chain", firewall_ok, PROJECT_CHAIN))

    frontend_ok = True
    frontend_detail = plan.firewall_frontend
    if plan.firewall_frontend == "firewalld":
        firewall_cmd = _required_executable("firewall-cmd")
        if plan.firewalld_zone is None:
            frontend_ok = False
            frontend_detail = "firewalld zone is unknown"
        else:
            frontend_ok = all(
                _run_for_status(
                    [
                        *prefix,
                        firewall_cmd,
                        "--permanent",
                        f"--zone={plan.firewalld_zone}",
                        f"--query-rich-rule={firewalld_rich_rule(plan, port)}",
                    ],
                    runner=runner,
                )
                for port in (plan.ssh_port,)
            )
            frontend_detail = (
                f"firewalld zone {plan.firewalld_zone}; "
                f"{plan.client_ip} -> {plan.server_ip} ports "
                f"{plan.ssh_port}"
            )
    elif plan.firewall_frontend == "ufw":
        ufw = _required_executable("ufw")
        status = _captured_run(
            [*prefix, ufw, "status"],
            runner=runner,
            allowed_returncodes=(0, 1),
        )
        frontend_ok = status.returncode == 0 and "Status: active" in status.stdout
        frontend_detail = "UFW active with installer-managed lab rules"
    checks.append(("host firewall access path", frontend_ok, frontend_detail))

    client_rule = _captured_run(
        [
            *prefix,
            _required_executable("iptables"),
            "-w",
            "5",
            "-C",
            PROJECT_CHAIN,
            "-s",
            plan.client_ip,
            "-p",
            "tcp",
            "--dport",
            str(plan.ssh_port),
            "-j",
            "DROP",
        ],
        runner=runner,
        allowed_returncodes=(0, 1, 2, 3, 4),
    )
    client_ready = client_rule.returncode == 1
    checks.append(
        (
            "disposable client baseline",
            client_ready,
            "not blocked" if client_ready else "unexpected DROP rule is present",
        )
    )

    ssh_ok, ssh_detail = _tcp_listener_check(plan.server_ip, plan.ssh_port)
    checks.append(("SSH listener", ssh_ok, ssh_detail))

    print("\nPost-install verification:")
    failed = []
    for name, succeeded, detail in checks:
        marker = "PASS" if succeeded else "FAIL"
        print(f"  [{marker}] {name}: {detail}")
        if not succeeded:
            failed.append(name)
    if failed:
        raise LiveLabSetupError(f"verification failed: {', '.join(failed)}")


def discover_network(*, runner: CommandRunner = subprocess.run) -> HostNetwork:
    completed = _captured_run(
        ["ip", "-j", "-4", "address", "show", "up"],
        runner=runner,
    )
    try:
        records = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise LiveLabSetupError("could not decode IPv4 interface information") from exc
    if not isinstance(records, list):
        raise LiveLabSetupError("unexpected IPv4 interface information")
    interfaces: dict[str, tuple[InterfaceAddress, ...]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("ifname"), str):
            continue
        addresses = []
        for value in record.get("addr_info", []):
            if (
                isinstance(value, dict)
                and value.get("family") == "inet"
                and isinstance(value.get("local"), str)
                and isinstance(value.get("prefixlen"), int)
            ):
                try:
                    normalized = str(ipaddress.IPv4Address(value["local"]))
                    addresses.append(InterfaceAddress(normalized, value["prefixlen"]))
                except (ipaddress.AddressValueError, ValueError):
                    continue
        if addresses:
            interfaces[record["ifname"]] = tuple(addresses)
    return HostNetwork(interfaces)


def detect_firewall_frontend(*, runner: CommandRunner = subprocess.run) -> str:
    active = []
    firewalld = _captured_run(
        ["systemctl", "is-active", "firewalld.service"],
        runner=runner,
        allowed_returncodes=(0, 3, 4),
    )
    if firewalld.returncode == 0 and firewalld.stdout.strip() == "active":
        active.append("firewalld")
    if _ufw_is_enabled():
        active.append("ufw")
    if len(active) > 1:
        raise LiveLabSetupError(
            "firewalld and UFW are both active; disable one before automated setup"
        )
    return active[0] if active else "none"


def _ufw_is_enabled(config_path: Path = Path("/etc/ufw/ufw.conf")) -> bool:
    """Read UFW's actual enable flag; its oneshot unit can be active while disabled."""

    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, PermissionError, OSError):
        return False
    values = {
        key.strip().upper(): value.strip().lower()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
        for key, value in (line.split("=", 1),)
    }
    return values.get("ENABLED") == "yes"


def detect_firewalld_zone(
    interface: str,
    *,
    runner: CommandRunner = subprocess.run,
) -> str:
    firewall_cmd = _required_executable("firewall-cmd")
    completed = _captured_run(
        [firewall_cmd, "--get-zone-of-interface", interface],
        runner=runner,
        allowed_returncodes=(0, 2),
    )
    if completed.returncode == 2:
        detail = (completed.stderr or completed.stdout).strip()
        if detail.lower() != "no zone":
            raise LiveLabSetupError(f"could not determine firewalld zone for {interface}: {detail}")
    zone = completed.stdout.strip()
    if not zone or zone == "no zone":
        default = _captured_run(
            [firewall_cmd, "--get-default-zone"],
            runner=runner,
        )
        zone = default.stdout.strip()
    if not zone:
        raise LiveLabSetupError(f"could not determine firewalld zone for {interface}")
    return zone


def build_live_config(
    plan: LiveLabPlan,
    *,
    ssh_unit: str,
    tcpdump_path: str,
    iptables_path: str,
) -> dict[str, Any]:
    return {
        "application": {"environment": "ubuntu-live-demo"},
        "response": {
            "mode": "automatic_response",
            "block_duration_seconds": plan.block_duration_seconds,
            "expiration_check_seconds": 10,
            "iptables_path": iptables_path,
        },
        "authentication_sensor": {"systemd_unit": ssh_unit},
        "network_sensor": {
            "interface": plan.lab_interface,
            "tcpdump_path": tcpdump_path,
            "protected_ipv4_addresses": list(plan.protected_addresses),
        },
        "database": {"path": str(DATABASE_PATH)},
        "logging": {"path": str(LOG_PATH)},
    }


def firewalld_rich_rule(plan: LiveLabPlan, port: int) -> str:
    return (
        'rule family="ipv4" '
        f'source address="{plan.client_ip}/32" '
        f'destination address="{plan.server_ip}/32" '
        f'port port="{port}" protocol="tcp" accept'
    )


def _configure_host_firewall(
    plan: LiveLabPlan,
    *,
    sudo: str,
    runner: CommandRunner,
) -> None:
    if plan.firewall_frontend == "firewalld":
        firewall_cmd = _required_executable("firewall-cmd")
        if plan.firewalld_zone is None:
            raise LiveLabSetupError("firewalld is active but its lab zone is unknown")
        for port in (plan.ssh_port,):
            rule = firewalld_rich_rule(plan, port)
            query = _captured_run(
                [
                    sudo,
                    firewall_cmd,
                    "--permanent",
                    f"--zone={plan.firewalld_zone}",
                    f"--query-rich-rule={rule}",
                ],
                runner=runner,
                allowed_returncodes=(0, 1),
            )
            if query.returncode != 0:
                _checked_run(
                    [
                        sudo,
                        firewall_cmd,
                        "--permanent",
                        f"--zone={plan.firewalld_zone}",
                        f"--add-rich-rule={rule}",
                    ],
                    runner=runner,
                )
        _checked_run([sudo, firewall_cmd, "--reload"], runner=runner)
        return
    if plan.firewall_frontend == "ufw":
        ufw = _required_executable("ufw")
        for port in (plan.ssh_port,):
            _checked_run(
                [
                    sudo,
                    ufw,
                    "allow",
                    "in",
                    "on",
                    plan.lab_interface,
                    "from",
                    plan.client_ip,
                    "to",
                    plan.server_ip,
                    "port",
                    str(port),
                    "proto",
                    "tcp",
                ],
                runner=runner,
            )
        return
    print(
        "  Host firewall frontend: none active; no UFW/firewalld rule was changed. "
        "The dedicated project chain will still be installed."
    )


def _ensure_service_account(
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    existing = _captured_run(
        [tools["getent"], "passwd", SERVICE_USER],
        runner=runner,
        allowed_returncodes=(0, 2),
    )
    if existing.returncode != 0:
        _checked_run(
            [
                sudo,
                tools["useradd"],
                "--system",
                "--home-dir",
                str(DATA_DIRECTORY),
                "--shell",
                "/usr/sbin/nologin",
                SERVICE_USER,
            ],
            runner=runner,
        )
    _checked_run(
        [sudo, tools["usermod"], "-aG", "systemd-journal", SERVICE_USER],
        runner=runner,
    )


def _install_directories(
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    directories = (
        ("root", "root", "0755", INSTALL_ROOT),
        ("root", SERVICE_USER, "0750", CONFIG_DIRECTORY),
        (SERVICE_USER, SERVICE_USER, "0750", DATA_DIRECTORY),
        (SERVICE_USER, SERVICE_USER, "0750", LOG_DIRECTORY),
    )
    for owner, group, mode, path in directories:
        _checked_run(
            [
                sudo,
                tools["install"],
                "-d",
                "-o",
                owner,
                "-g",
                group,
                "-m",
                mode,
                str(path),
            ],
            runner=runner,
        )


def _synchronize_source(
    plan: LiveLabPlan,
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    _checked_run(
        [
            sudo,
            tools["rsync"],
            "-a",
            "--delete",
            "--exclude",
            ".git/",
            "--exclude",
            ".venv/",
            "--exclude",
            "config/local.json",
            "--exclude",
            "data/",
            "--exclude",
            "logs/",
            f"{plan.repository_root}/",
            f"{INSTALL_ROOT}/",
        ],
        runner=runner,
    )


def _install_production_environment(
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    python = tools["python3"]
    _checked_run([sudo, python, "-m", "venv", str(INSTALL_ROOT / ".venv")], runner=runner)
    production_python = str(INSTALL_ROOT / ".venv/bin/python")
    _checked_run(
        [sudo, production_python, "-m", "pip", "install", "--upgrade", "pip"],
        runner=runner,
    )
    _checked_run(
        [
            sudo,
            production_python,
            "-m",
            "pip",
            "install",
            "--no-deps",
            str(INSTALL_ROOT),
        ],
        runner=runner,
    )


def _install_configuration(
    plan: LiveLabPlan,
    *,
    ssh_unit: str,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    document = build_live_config(
        plan,
        ssh_unit=ssh_unit,
        tcpdump_path=tools["tcpdump"],
        iptables_path=tools["iptables"],
    )
    if _run_for_status([sudo, "test", "-f", str(CONFIG_PATH)], runner=runner):
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        _checked_run(
            [
                sudo,
                tools["cp"],
                "--archive",
                str(CONFIG_PATH),
                f"{CONFIG_PATH}.{timestamp}.bak",
            ],
            runner=runner,
        )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="ssh-security-app-config-",
            suffix=".json",
            delete=False,
        ) as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
            temporary_path = Path(handle.name)
        _checked_run(
            [
                sudo,
                tools["install"],
                "-o",
                "root",
                "-g",
                SERVICE_USER,
                "-m",
                "0640",
                str(temporary_path),
                str(CONFIG_PATH),
            ],
            runner=runner,
        )
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _initialize_database(*, sudo: str, runner: CommandRunner) -> None:
    executable = str(INSTALL_ROOT / ".venv/bin/ssh-security-app")
    base = [
        sudo,
        "-u",
        SERVICE_USER,
        executable,
        "--config",
        str(CONFIG_PATH),
    ]
    _checked_run([*base, "validate-config"], runner=runner)
    _checked_run([*base, "init-db"], runner=runner)


def _install_systemd_units(
    plan: LiveLabPlan,
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    unit_names = (
        FIREWALL_UNIT,
        APPLICATION_UNIT,
    )
    for name in unit_names:
        source = plan.repository_root / "installation_and_service_setup" / name
        destination = Path("/etc/systemd/system") / name
        _checked_run(
            [
                sudo,
                tools["install"],
                "-o",
                "root",
                "-g",
                "root",
                "-m",
                "0644",
                str(source),
                str(destination),
            ],
            runner=runner,
        )
    _checked_run(
        [
            sudo,
            tools["install"],
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            str(
                plan.repository_root
                / "installation_and_service_setup/ssh-security-application-tmpfiles.conf"
            ),
            "/etc/tmpfiles.d/ssh-security-app.conf",
        ],
        runner=runner,
    )
    _checked_run(
        [
            sudo,
            tools["systemd-tmpfiles"],
            "--create",
            "/etc/tmpfiles.d/ssh-security-app.conf",
        ],
        runner=runner,
    )
    for name in unit_names:
        _checked_run(
            [
                sudo,
                tools["systemd-analyze"],
                "verify",
                f"/etc/systemd/system/{name}",
            ],
            runner=runner,
        )
    _checked_run([sudo, tools["systemctl"], "daemon-reload"], runner=runner)


def _remove_stale_project_firewall(*, sudo: str, runner: CommandRunner) -> None:
    _checked_run(
        [
            sudo,
            str(INSTALL_ROOT / ".venv/bin/ssh-security-app"),
            "--config",
            str(CONFIG_PATH),
            "firewall-cleanup",
            "--confirm-firewall-changes",
        ],
        runner=runner,
    )


def _reset_host_iptables_for_lab(
    plan: LiveLabPlan,
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    """Reset the filter table for a fresh authorized Ubuntu/Kali lab run."""

    print(
        "  Lab iptables reset: clearing filter-table rules before setup so "
        f"{plan.client_ip} can reach {plan.server_ip}:{plan.ssh_port} before detection."
    )
    iptables = tools["iptables"]
    for policy_chain in ("INPUT", "FORWARD", "OUTPUT"):
        _checked_run(
            [
                sudo,
                iptables,
                "-w",
                "5",
                "-t",
                "filter",
                "-P",
                policy_chain,
                "ACCEPT",
            ],
            runner=runner,
        )
    _checked_run(
        [sudo, iptables, "-w", "5", "-t", "filter", "-F"],
        runner=runner,
    )
    _checked_run(
        [sudo, iptables, "-w", "5", "-t", "filter", "-X"],
        runner=runner,
    )
    print("  Lab iptables reset complete: filter table is open before project rules.")


def _restore_runtime_ownership(
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    _checked_run(
        [
            sudo,
            tools["chown"],
            "-R",
            f"{SERVICE_USER}:{SERVICE_USER}",
            str(DATA_DIRECTORY),
            str(LOG_DIRECTORY),
        ],
        runner=runner,
    )


def _start_services(
    *,
    sudo: str,
    tools: dict[str, str],
    runner: CommandRunner,
) -> None:
    for unit in (FIREWALL_UNIT, APPLICATION_UNIT):
        _checked_run(
            [sudo, tools["systemctl"], "enable", "--now", unit],
            runner=runner,
        )


def _stop_existing_services(
    *,
    sudo: str,
    systemctl: str,
    runner: CommandRunner,
) -> None:
    for unit in (APPLICATION_UNIT, FIREWALL_UNIT):
        _captured_run(
            [sudo, systemctl, "stop", unit],
            runner=runner,
            allowed_returncodes=(0, 5),
        )


def _validate_repository(root: Path) -> None:
    required = (
        root / "pyproject.toml",
        root / "application_configuration/safe_default_configuration.json",
        root / "installation_and_service_setup/ssh-security-application-firewall.service",
        root / "installation_and_service_setup/ssh-security-application.service",
        root / "installation_and_service_setup/ssh-security-application-tmpfiles.conf",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise LiveLabSetupError(f"repository is missing required files: {', '.join(missing)}")


def _select_server_address(
    addresses: tuple[InterfaceAddress, ...],
    requested: str | None,
) -> InterfaceAddress:
    if requested is not None:
        normalized = str(ipaddress.IPv4Address(requested))
        for address in addresses:
            if address.address == normalized:
                return address
        available = ", ".join(item.address for item in addresses)
        raise LiveLabSetupError(
            f"server IP {normalized} is not assigned to the lab interface; available: {available}"
        )
    if len(addresses) != 1:
        available = ", ".join(item.address for item in addresses)
        raise LiveLabSetupError(
            "the lab interface has multiple IPv4 addresses; select one with "
            f"--server-ip ({available})"
        )
    return addresses[0]


def _validate_client_address(
    value: str,
    *,
    server: InterfaceAddress,
    protected_addresses: tuple[str, ...],
) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise LiveLabSetupError(f"invalid disposable client IPv4 address: {value}") from exc
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or address.is_link_local
    ):
        raise LiveLabSetupError("disposable client IP is not eligible for a lab block")
    normalized = str(address)
    if normalized in protected_addresses:
        raise LiveLabSetupError("disposable client IP matches a protected server address")
    if address not in server.network:
        raise LiveLabSetupError(
            f"disposable client {normalized} is not in lab subnet {server.network}"
        )
    return normalized


def _detect_ssh_unit(
    systemctl: str,
    *,
    runner: CommandRunner,
) -> str | None:
    for unit in ("ssh.service", "sshd.service"):
        completed = _captured_run(
            [systemctl, "show", unit, "--property=LoadState", "--value"],
            runner=runner,
            allowed_returncodes=(0, 1),
        )
        if completed.returncode == 0 and completed.stdout.strip() == "loaded":
            return unit
    return None


def _bootstrap_tools() -> dict[str, str]:
    return {"sudo": _required_executable("sudo")}


def _installed_tools() -> dict[str, str]:
    names = (
        "sudo",
        "systemctl",
        "setcap",
        "tcpdump",
        "iptables",
        "python3",
        "rsync",
        "getent",
        "useradd",
        "usermod",
        "install",
        "cp",
        "chown",
        "systemd-tmpfiles",
        "systemd-analyze",
    )
    return {name: _required_executable(name, resolve=name == "tcpdump") for name in names}


def _required_executable(name: str, *, resolve: bool = False) -> str:
    value = shutil.which(name)
    if not value:
        raise LiveLabSetupError(f"required executable {name!r} was not found")
    path = Path(value)
    return str(path.resolve() if resolve else path.absolute())


def _port(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _checked_run(
    command: list[str],
    *,
    runner: CommandRunner,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    completed = runner(
        command,
        cwd=cwd,
        check=False,
        shell=False,
        text=True,
    )
    if completed.returncode != 0:
        raise LiveLabSetupError(
            f"command failed with status {completed.returncode}: {' '.join(command)}"
        )
    return completed


def _captured_run(
    command: list[str],
    *,
    runner: CommandRunner,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess:
    completed = runner(
        command,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
    )
    if completed.returncode not in allowed_returncodes:
        detail = (completed.stderr or completed.stdout or "no output").strip()
        raise LiveLabSetupError(f"command failed: {' '.join(command)}: {detail}")
    return completed


def _run_for_status(
    command: list[str],
    *,
    runner: CommandRunner,
) -> bool:
    completed = runner(
        command,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
    )
    return completed.returncode == 0


def _tcp_listener_check(host: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True, f"{host}:{port}"
    except OSError as exc:
        return False, str(exc)


if __name__ == "__main__":
    raise SystemExit(main())
