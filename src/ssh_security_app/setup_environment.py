"""Prepare a normal-user Ubuntu lab environment for SSH Security Application testing."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ssh_security_app.config import load_config

CommandRunner = Callable[..., subprocess.CompletedProcess]


class SetupError(RuntimeError):
    """Raised when the test environment cannot be prepared safely."""


@dataclass(frozen=True)
class HostNetwork:
    interfaces: dict[str, tuple[str, ...]]

    @property
    def protected_addresses(self) -> tuple[str, ...]:
        return tuple(
            address
            for addresses in self.interfaces.values()
            for address in addresses
            if not ipaddress.IPv4Address(address).is_loopback
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Prepare SSH, tcpdump capability, local configuration, and a test database.")
    )
    parser.add_argument(
        "--lab-interface",
        required=True,
        help="interface connected to the disposable lab client, for example ens37",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/local.json"),
        help="local override file to create (default: config/local.json)",
    )
    parser.add_argument(
        "--database-path",
        default="data/ssh_security_app_test.db",
        help="SQLite path written into a new configuration",
    )
    parser.add_argument(
        "--log-path",
        default="logs/ssh_security_app_test.log",
        help="JSON log path written into a new configuration",
    )
    parser.add_argument(
        "--dashboard-host",
        default="127.0.0.1",
        help="private or loopback dashboard IPv4 address",
    )
    parser.add_argument(
        "--ssh-unit",
        default="auto",
        help="OpenSSH systemd unit, or auto to detect/install it (default: auto)",
    )
    parser.add_argument(
        "--overwrite-config",
        action="store_true",
        help="replace an existing local configuration after making a backup",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform changes; without this flag the command prints its plan",
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
        return prepare_environment(
            args,
            runner=runner,
            repository_root=repository_root,
        )
    except SetupError as exc:
        print(f"Setup error: {exc}", file=sys.stderr)
        return 1


def prepare_environment(
    args: argparse.Namespace,
    *,
    runner: CommandRunner = subprocess.run,
    repository_root: Path | None = None,
) -> int:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SetupError("run this script as the normal project user, not with sudo")
    if sys.prefix == sys.base_prefix:
        raise SetupError("activate the project .venv before running setup")

    repository_root = (
        repository_root.resolve()
        if repository_root is not None
        else Path(__file__).resolve().parents[2]
    )
    network = discover_network(runner=runner)
    if args.lab_interface not in network.interfaces:
        available = ", ".join(sorted(network.interfaces)) or "none"
        raise SetupError(
            f"lab interface {args.lab_interface!r} is not an active IPv4 interface; "
            f"available: {available}"
        )
    if not network.protected_addresses:
        raise SetupError("no non-loopback IPv4 server addresses were discovered")

    tcpdump_path = _required_executable("tcpdump", resolve_symlink=True)
    iptables_path = _required_executable("iptables")
    systemctl_path = _required_executable("systemctl")
    setcap_path = _required_executable("setcap")
    getcap_path = _required_executable("getcap")
    sudo_path = _required_executable("sudo")
    config_path = _resolve_under_root(repository_root, args.config)
    ssh_unit = detect_ssh_unit(
        systemctl_path=systemctl_path,
        requested=args.ssh_unit,
        runner=runner,
    )
    install_openssh = ssh_unit is None
    if install_openssh and args.ssh_unit != "auto":
        raise SetupError(
            f"requested OpenSSH unit {args.ssh_unit!r} does not exist; "
            "use --ssh-unit auto to install and detect OpenSSH"
        )

    print("SSH Security Application test-environment plan:")
    if install_openssh:
        print("  OpenSSH server: missing; will install openssh-server")
        print("  SSH unit: detect after installation")
    else:
        print(f"  SSH unit: {ssh_unit}")
    print(f"  lab interface: {args.lab_interface}")
    print(f"  protected server IPv4 addresses: {', '.join(network.protected_addresses)}")
    print(f"  tcpdump: {tcpdump_path}")
    print(f"  iptables: {iptables_path}")
    print(f"  local config: {config_path}")
    print("  response mode: simulation")
    if not args.apply:
        print("\nPreview only. Re-run with --apply to perform these changes.")
        return 0

    _checked_run([sudo_path, "-v"], runner=runner)
    if install_openssh:
        apt_get_path = _required_executable("apt-get")
        _checked_run([sudo_path, apt_get_path, "update"], runner=runner)
        _checked_run(
            [sudo_path, apt_get_path, "install", "-y", "openssh-server"],
            runner=runner,
        )
        _checked_run(
            [sudo_path, systemctl_path, "daemon-reload"],
            runner=runner,
        )
        ssh_unit = detect_ssh_unit(
            systemctl_path=systemctl_path,
            requested="auto",
            runner=runner,
        )
        if ssh_unit is None:
            raise SetupError(
                "openssh-server was installed but neither ssh.service nor sshd.service was detected"
            )
    if ssh_unit is None:
        raise SetupError("OpenSSH systemd unit could not be resolved")
    _checked_run(
        [sudo_path, systemctl_path, "enable", "--now", ssh_unit],
        runner=runner,
    )
    _checked_run(
        [
            sudo_path,
            setcap_path,
            "cap_net_raw,cap_net_admin=eip",
            tcpdump_path,
        ],
        runner=runner,
    )

    _checked_run(
        [sys.executable, "-m", "pip", "install", "-e", "."],
        runner=runner,
        cwd=repository_root,
    )

    config_document = build_local_config(
        lab_interface=args.lab_interface,
        protected_addresses=network.protected_addresses,
        tcpdump_path=tcpdump_path,
        iptables_path=iptables_path,
        ssh_unit=ssh_unit,
        dashboard_host=args.dashboard_host,
        database_path=args.database_path,
        log_path=args.log_path,
    )
    write_local_config(
        config_path,
        config_document,
        overwrite=args.overwrite_config,
    )

    loaded = load_config(config_path)
    if loaded.response.mode.value != "simulation":
        raise SetupError("generated test configuration is not in Simulation Mode")
    _checked_run(
        [
            sys.executable,
            "-m",
            "ssh_security_app.main",
            "--config",
            str(config_path),
            "validate-config",
        ],
        runner=runner,
        cwd=repository_root,
    )
    _checked_run(
        [
            sys.executable,
            "-m",
            "ssh_security_app.main",
            "--config",
            str(config_path),
            "init-db",
        ],
        runner=runner,
        cwd=repository_root,
    )

    active = _captured_run(
        [systemctl_path, "is-active", ssh_unit],
        runner=runner,
    ).stdout.strip()
    capabilities = _captured_run(
        [getcap_path, tcpdump_path],
        runner=runner,
    ).stdout.strip()
    if active != "active":
        raise SetupError(f"{ssh_unit} did not become active")
    if "cap_net_admin" not in capabilities or "cap_net_raw" not in capabilities:
        raise SetupError("tcpdump capture capabilities could not be confirmed")
    dashboard_asset = repository_root / "src" / "ssh_security_app" / "ui" / "static" / "index.html"
    if not dashboard_asset.is_file():
        raise SetupError("first-party dashboard assets could not be confirmed")

    print("\nSetup complete:")
    print(f"  {ssh_unit}: active")
    print(f"  tcpdump capabilities: {capabilities}")
    print("  first-party dashboard: ready (standard-library server)")
    print(f"  config: {config_path}")
    print(f"  database: {loaded.database.path}")
    print("\nNext: run the automated checks and Simulation Mode fixture test.")
    return 0


def detect_ssh_unit(
    *,
    systemctl_path: str,
    requested: str,
    runner: CommandRunner = subprocess.run,
) -> str | None:
    candidates = ("ssh.service", "sshd.service") if requested == "auto" else (requested,)
    for unit in candidates:
        completed = runner(
            [systemctl_path, "show", unit, "--property=LoadState", "--value"],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
        )
        if completed.returncode == 0 and completed.stdout.strip() == "loaded":
            return unit
    return None


def discover_network(*, runner: CommandRunner = subprocess.run) -> HostNetwork:
    completed = _captured_run(
        ["ip", "-j", "-4", "address", "show", "up"],
        runner=runner,
    )
    try:
        records = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SetupError("could not decode IPv4 interface information") from exc
    if not isinstance(records, list):
        raise SetupError("unexpected IPv4 interface information")
    interfaces: dict[str, tuple[str, ...]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("ifname"), str):
            continue
        addresses = []
        for address in record.get("addr_info", []):
            if (
                isinstance(address, dict)
                and address.get("family") == "inet"
                and isinstance(address.get("local"), str)
            ):
                try:
                    addresses.append(str(ipaddress.IPv4Address(address["local"])))
                except ipaddress.AddressValueError:
                    continue
        if addresses:
            interfaces[record["ifname"]] = tuple(addresses)
    return HostNetwork(interfaces)


def build_local_config(
    *,
    lab_interface: str,
    protected_addresses: Sequence[str],
    tcpdump_path: str,
    iptables_path: str,
    ssh_unit: str,
    dashboard_host: str,
    database_path: str,
    log_path: str,
) -> dict[str, Any]:
    normalized_protected = [str(ipaddress.IPv4Address(address)) for address in protected_addresses]
    dashboard_address = ipaddress.IPv4Address(dashboard_host)
    if dashboard_address.is_unspecified or not (
        dashboard_address.is_private or dashboard_address.is_loopback
    ):
        raise SetupError("dashboard host must be a private or loopback IPv4 address")
    return {
        "application": {"environment": "ubuntu-live-test"},
        "response": {
            "mode": "simulation",
            "block_duration_seconds": 120,
            "expiration_check_seconds": 10,
            "iptables_path": iptables_path,
        },
        "authentication_sensor": {"systemd_unit": ssh_unit},
        "network_sensor": {
            "interface": lab_interface,
            "tcpdump_path": tcpdump_path,
            "protected_ipv4_addresses": normalized_protected,
        },
        "database": {"path": database_path},
        "dashboard": {"host": str(dashboard_address), "port": 8501},
        "logging": {"path": log_path},
    }


def write_local_config(
    path: Path,
    document: dict[str, Any],
    *,
    overwrite: bool,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        print(f"Existing configuration preserved: {path}")
        return
    if path.exists():
        backup = path.with_suffix(f"{path.suffix}.before-test-setup")
        if backup.exists():
            raise SetupError(f"configuration backup already exists: {backup}")
        path.replace(backup)
        print(f"Existing configuration backed up to: {backup}")
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    temporary.replace(path)
    print(f"Created Simulation Mode configuration: {path}")


def _required_executable(name: str, *, resolve_symlink: bool = False) -> str:
    path = shutil.which(name)
    if not path:
        raise SetupError(
            f"required executable {name!r} was not found; install OS prerequisites first"
        )
    executable = Path(path)
    return str(executable.resolve() if resolve_symlink else executable.absolute())


def _resolve_under_root(root: Path, path: Path) -> Path:
    resolved = path.resolve() if path.is_absolute() else (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SetupError("configuration path must remain inside the repository") from exc
    return resolved


def _checked_run(
    command: list[str],
    *,
    runner: CommandRunner,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = runner(
        command,
        cwd=cwd,
        check=False,
        shell=False,
        text=True,
    )
    if completed.returncode != 0:
        raise SetupError(f"command failed with status {completed.returncode}: {' '.join(command)}")
    return completed


def _captured_run(
    command: list[str],
    *,
    runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    completed = runner(
        command,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "no output").strip()
        raise SetupError(f"command failed: {' '.join(command)}: {detail}")
    return completed


if __name__ == "__main__":
    raise SystemExit(main())
