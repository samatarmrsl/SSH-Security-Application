from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from ssh_security_app.live_lab_setup import (
    LiveLabPlan,
    LiveLabSetupError,
    _configure_host_firewall,
    _ufw_is_enabled,
    apply_plan,
    build_live_config,
    create_plan,
    firewalld_rich_rule,
    main,
    verify_installation,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
IP_OUTPUT = json.dumps(
    [
        {
            "ifname": "lo",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "127.0.0.1",
                    "prefixlen": 8,
                }
            ],
        },
        {
            "ifname": "ens33",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "192.168.13.128",
                    "prefixlen": 24,
                }
            ],
        },
        {
            "ifname": "ens37",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "192.168.12.1",
                    "prefixlen": 24,
                }
            ],
        },
    ]
)


def plan_runner(command, **_kwargs):
    if command == ["ip", "-j", "-4", "address", "show", "up"]:
        return subprocess.CompletedProcess(command, 0, IP_OUTPUT, "")
    if command == ["systemctl", "is-active", "firewalld.service"]:
        return subprocess.CompletedProcess(command, 0, "active\n", "")
    if command == ["/usr/bin/firewall-cmd", "--get-zone-of-interface", "ens37"]:
        return subprocess.CompletedProcess(command, 0, "public\n", "")
    raise AssertionError(f"unexpected command: {command}")


def make_args(**overrides) -> argparse.Namespace:
    values = {
        "lab_interface": "ens37",
        "client_ip": "192.168.12.3",
        "server_ip": None,
        "ssh_port": 22,
        "dashboard_port": 8501,
        "block_duration_seconds": 120,
        "apply": False,
        "verify_only": False,
        "confirm_firewall_changes": False,
        "skip_package_install": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_plan_autodetects_server_and_firewalld_zone(monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr("ssh_security_app.live_lab_setup._ufw_is_enabled", lambda: False)

    plan = create_plan(
        make_args(),
        repository_root=REPOSITORY_ROOT,
        runner=plan_runner,
    )

    assert plan.server_ip == "192.168.12.1"
    assert plan.client_ip == "192.168.12.3"
    assert plan.firewall_frontend == "firewalld"
    assert plan.firewalld_zone == "public"
    assert plan.protected_addresses == ("192.168.13.128", "192.168.12.1")


def test_plan_rejects_client_outside_lab_subnet(monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr("ssh_security_app.live_lab_setup._ufw_is_enabled", lambda: False)

    with pytest.raises(LiveLabSetupError, match="not in lab subnet"):
        create_plan(
            make_args(client_ip="192.168.99.3"),
            repository_root=REPOSITORY_ROOT,
            runner=plan_runner,
        )


def test_plan_rejects_protected_server_as_client(monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr("ssh_security_app.live_lab_setup._ufw_is_enabled", lambda: False)

    with pytest.raises(LiveLabSetupError, match="protected server"):
        create_plan(
            make_args(client_ip="192.168.12.1"),
            repository_root=REPOSITORY_ROOT,
            runner=plan_runner,
        )


def test_live_config_enables_two_minute_automatic_response() -> None:
    plan = LiveLabPlan(
        repository_root=REPOSITORY_ROOT,
        lab_interface="ens37",
        server_ip="192.168.12.1",
        client_ip="192.168.12.3",
        protected_addresses=("192.168.13.128", "192.168.12.1"),
        ssh_port=22,
        dashboard_port=8501,
        block_duration_seconds=120,
        firewall_frontend="firewalld",
        firewalld_zone="public",
    )

    document = build_live_config(
        plan,
        ssh_unit="ssh.service",
        tcpdump_path="/usr/sbin/tcpdump",
        iptables_path="/usr/sbin/iptables",
    )

    assert document["response"]["mode"] == "automatic_response"
    assert document["response"]["block_duration_seconds"] == 120
    assert document["network_sensor"]["interface"] == "ens37"
    assert document["dashboard"] == {"host": "192.168.12.1", "port": 8501}


def test_firewalld_rules_are_limited_to_client_server_and_port(monkeypatch) -> None:
    plan = LiveLabPlan(
        repository_root=REPOSITORY_ROOT,
        lab_interface="ens37",
        server_ip="192.168.12.1",
        client_ip="192.168.12.3",
        protected_addresses=("192.168.12.1",),
        ssh_port=22,
        dashboard_port=8501,
        block_duration_seconds=120,
        firewall_frontend="firewalld",
        firewalld_zone="public",
    )
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if "--query-rich-rule" in command[-1]:
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )

    _configure_host_firewall(plan, sudo="/usr/bin/sudo", runner=runner)

    add_commands = [command for command in commands if "--add-rich-rule" in command[-1]]
    assert firewalld_rich_rule(plan, 22) in add_commands[0][-1]
    assert 'source address="192.168.12.3/32"' in add_commands[0][-1]
    assert 'destination address="192.168.12.1/32"' in add_commands[0][-1]
    assert 'port port="8501"' in add_commands[1][-1]
    assert commands[-1] == [
        "/usr/bin/sudo",
        "/usr/bin/firewall-cmd",
        "--reload",
    ]


def test_ufw_enabled_flag_uses_configuration_not_oneshot_unit(tmp_path) -> None:
    config = tmp_path / "ufw.conf"
    config.write_text("ENABLED=no\n", encoding="utf-8")
    assert not _ufw_is_enabled(config)

    config.write_text("ENABLED=yes\n", encoding="utf-8")
    assert _ufw_is_enabled(config)


def test_preview_performs_no_privileged_commands(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr("ssh_security_app.live_lab_setup._ufw_is_enabled", lambda: False)

    result = main(
        ["--lab-interface", "ens37", "--client-ip", "192.168.12.3"],
        runner=plan_runner,
        repository_root=REPOSITORY_ROOT,
    )

    assert result == 0
    output = capsys.readouterr().out
    assert "Preview only" in output
    assert "192.168.12.1:8501" in output
    assert "firewalld zone: public" in output


def test_apply_requires_explicit_firewall_confirmation(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    monkeypatch.setattr("ssh_security_app.live_lab_setup._ufw_is_enabled", lambda: False)

    result = main(
        [
            "--lab-interface",
            "ens37",
            "--client-ip",
            "192.168.12.3",
            "--apply",
        ],
        runner=plan_runner,
        repository_root=REPOSITORY_ROOT,
    )

    assert result == 1
    assert "--confirm-firewall-changes" in capsys.readouterr().err


def test_firewall_service_initializes_and_cleans_dedicated_chain() -> None:
    unit = (REPOSITORY_ROOT / "systemd/ssh-security-app-firewall.service").read_text(
        encoding="utf-8"
    )
    application_unit = (REPOSITORY_ROOT / "systemd/ssh-security-app.service").read_text(
        encoding="utf-8"
    )

    assert "firewall-init --confirm-firewall-changes" in unit
    assert "firewall-cleanup --confirm-firewall-changes" in unit
    assert "User=sshsecurityapp" in unit
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in unit
    assert "After=network-online.target ssh.service ssh-security-app-firewall.service" in (
        application_unit
    )


def test_apply_plan_orchestrates_complete_idempotent_install(monkeypatch) -> None:
    plan = LiveLabPlan(
        repository_root=REPOSITORY_ROOT,
        lab_interface="ens37",
        server_ip="192.168.12.1",
        client_ip="192.168.12.3",
        protected_addresses=("192.168.13.128", "192.168.12.1"),
        ssh_port=22,
        dashboard_port=8501,
        block_duration_seconds=120,
        firewall_frontend="none",
        firewalld_zone=None,
    )
    tool_names = (
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
    tools = {name: f"/tool/{name}" for name in tool_names}
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if command[:2] == ["/tool/systemctl", "show"]:
            state = "loaded\n" if command[2] == "ssh.service" else "not-found\n"
            return subprocess.CompletedProcess(command, 0, state, "")
        if command[:3] == ["/tool/sudo", "/tool/systemctl", "stop"]:
            return subprocess.CompletedProcess(command, 5, "", "unit not found")
        if command == ["/tool/getent", "passwd", "sshsecurityapp"]:
            return subprocess.CompletedProcess(command, 2, "", "")
        if command[:3] == ["/tool/sudo", "test", "-f"]:
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup._bootstrap_tools",
        lambda: {"sudo": "/tool/sudo"},
    )
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup._installed_tools",
        lambda: tools,
    )
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup._required_executable",
        lambda name, **_kwargs: f"/tool/{name}",
    )

    apply_plan(plan, runner=runner, install_packages=True)

    assert ["/tool/sudo", "/tool/apt-get", "update"] in commands
    assert any("/tool/useradd" in command for command in commands)
    assert any("/tool/rsync" in command for command in commands)
    assert any("firewall-cleanup" in command for command in commands)
    enabled = [
        command[-1]
        for command in commands
        if command[:4]
        == ["/tool/sudo", "/tool/systemctl", "enable", "--now"]
        and command[-1].startswith("ssh-security-app")
    ]
    assert enabled == [
        "ssh-security-app-firewall.service",
        "ssh-security-app.service",
        "ssh-security-app-dashboard.service",
    ]


def test_verify_installation_checks_services_chain_client_and_endpoints(
    capsys,
    monkeypatch,
) -> None:
    plan = LiveLabPlan(
        repository_root=REPOSITORY_ROOT,
        lab_interface="ens37",
        server_ip="192.168.12.1",
        client_ip="192.168.12.3",
        protected_addresses=("192.168.13.128", "192.168.12.1"),
        ssh_port=22,
        dashboard_port=8501,
        block_duration_seconds=120,
        firewall_frontend="firewalld",
        firewalld_zone="public",
    )

    def runner(command, **_kwargs):
        if command[:2] == ["/tool/systemctl", "show"]:
            state = "loaded\n" if command[2] == "ssh.service" else "not-found\n"
            return subprocess.CompletedProcess(command, 0, state, "")
        if command[:2] == ["/tool/systemctl", "is-active"]:
            return subprocess.CompletedProcess(command, 0, "active\n", "")
        if "-C" in command:
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "ok\n", "")

    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup._required_executable",
        lambda name, **_kwargs: f"/tool/{name}",
    )
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup._wait_for_dashboard",
        lambda _url: (True, "snapshot ready"),
    )
    monkeypatch.setattr(
        "ssh_security_app.live_lab_setup._tcp_listener_check",
        lambda _host, _port: (True, "listener ready"),
    )

    verify_installation(plan, runner=runner, use_sudo=True)

    output = capsys.readouterr().out
    assert "[PASS] ssh-security-app-firewall.service" in output
    assert "[PASS] project firewall chain" in output
    assert "[PASS] disposable client baseline: not blocked" in output
    assert "[PASS] dashboard HTTP API" in output
