"""One command workflow for setting up and starting the Ubuntu/Kali live lab."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Callable

from ssh_security_application.live_lab_setup import (
    APPLICATION_UNIT,
)
from ssh_security_application.live_lab_setup import (
    main as install_start_and_verify_lab,
)

CommandRunner = Callable[..., subprocess.CompletedProcess]

DEFAULT_LAB_INTERFACE = "ens37"
DEFAULT_SECURITY_VM_IP = "192.168.12.1"
DEFAULT_KALI_ATTACKER_IP = "192.168.12.3"
DEFAULT_TEMPORARY_BLOCK_SECONDS = 120


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Set up, start, verify, and optionally watch the SSH Security "
            "Application Ubuntu/Kali lab with one command."
        )
    )
    parser.add_argument(
        "--lab-interface",
        default=DEFAULT_LAB_INTERFACE,
        help=f"Ubuntu interface connected to Kali (default: {DEFAULT_LAB_INTERFACE})",
    )
    parser.add_argument(
        "--server-ip",
        default=DEFAULT_SECURITY_VM_IP,
        help=f"Ubuntu Security VM IPv4 address (default: {DEFAULT_SECURITY_VM_IP})",
    )
    parser.add_argument(
        "--client-ip",
        default=DEFAULT_KALI_ATTACKER_IP,
        help=f"Kali attacker IPv4 address (default: {DEFAULT_KALI_ATTACKER_IP})",
    )
    parser.add_argument(
        "--ssh-port",
        type=_port_number,
        default=22,
        help="OpenSSH port on the Ubuntu Security VM (default: 22)",
    )
    parser.add_argument(
        "--block-duration-seconds",
        type=_positive_integer,
        default=DEFAULT_TEMPORARY_BLOCK_SECONDS,
        help=(
            f"how long Kali is blocked after detection (default: {DEFAULT_TEMPORARY_BLOCK_SECONDS})"
        ),
    )
    parser.add_argument(
        "--skip-package-install",
        action="store_true",
        help="skip apt package installation when packages are already installed",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="only verify the already-installed live lab",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="perform setup/start actions and approve the dedicated iptables chain",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help=f"after setup, follow logs from {APPLICATION_UNIT}",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: CommandRunner = subprocess.run,
    repository_root: Path | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    root = (
        repository_root.resolve()
        if repository_root is not None
        else Path(__file__).resolve().parents[2]
    )
    installer_arguments = [
        "--lab-interface",
        args.lab_interface,
        "--server-ip",
        args.server_ip,
        "--client-ip",
        args.client_ip,
        "--ssh-port",
        str(args.ssh_port),
        "--block-duration-seconds",
        str(args.block_duration_seconds),
    ]
    if args.skip_package_install:
        installer_arguments.append("--skip-package-install")
    if args.verify_only:
        installer_arguments.append("--verify-only")
    elif args.apply:
        installer_arguments.extend(["--apply", "--confirm-firewall-changes"])

    if not args.apply and not args.verify_only:
        print("Preview mode: no services or firewall rules will be changed.")
        print("To set up and start the lab, run this same command with --apply.")

    result = install_start_and_verify_lab(
        installer_arguments,
        runner=runner,
        repository_root=root,
    )
    if result != 0:
        return result
    if args.watch:
        return watch_application_service_log(runner=runner)
    _print_next_steps(args)
    return 0


def watch_application_service_log(*, runner: CommandRunner = subprocess.run) -> int:
    sudo = shutil.which("sudo")
    journalctl = shutil.which("journalctl")
    if sudo is None:
        print("Cannot watch logs because sudo is not installed.", file=sys.stderr)
        return 1
    if journalctl is None:
        print("Cannot watch logs because journalctl is not installed.", file=sys.stderr)
        return 1
    print(f"\nFollowing {APPLICATION_UNIT}. Press Ctrl+C to stop watching logs.")
    completed = runner([sudo, journalctl, "-fu", APPLICATION_UNIT])
    return completed.returncode


def _print_next_steps(args: argparse.Namespace) -> None:
    config = "/etc/ssh-security-app/config.json"
    print("\nUseful verification commands:")
    print(
        f"  sudo /opt/ssh-security-application/.venv/bin/ssh-security-app --config {config} status"
    )
    print(
        f"  sudo /opt/ssh-security-application/.venv/bin/ssh-security-app --config {config} rules"
    )
    print(f"  sudo journalctl -fu {APPLICATION_UNIT}")
    print("\nKali demo target:")
    print(f"  ssh://{args.server_ip}:{args.ssh_port}")
    print(f"  expected attacker IP: {args.client_ip}")


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _port_number(value: str) -> int:
    parsed = _positive_integer(value)
    if parsed > 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return parsed
