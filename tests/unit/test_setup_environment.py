from __future__ import annotations

import json
import subprocess

import pytest

from ssh_security_app.setup_environment import (
    SetupError,
    build_local_config,
    discover_network,
    main,
    write_local_config,
)

IP_OUTPUT = json.dumps(
    [
        {
            "ifname": "lo",
            "addr_info": [{"family": "inet", "local": "127.0.0.1"}],
        },
        {
            "ifname": "ens33",
            "addr_info": [{"family": "inet", "local": "192.168.13.128"}],
        },
        {
            "ifname": "ens37",
            "addr_info": [{"family": "inet", "local": "192.168.12.1"}],
        },
    ]
)


def network_runner(command, **_kwargs):
    if command == ["ip", "-j", "-4", "address", "show", "up"]:
        return subprocess.CompletedProcess(command, 0, IP_OUTPUT, "")
    if command == [
        "/usr/bin/systemctl",
        "show",
        "ssh.service",
        "--property=LoadState",
        "--value",
    ]:
        return subprocess.CompletedProcess(command, 0, "loaded\n", "")
    raise AssertionError(f"unexpected command: {command}")


def test_network_discovery_protects_all_non_loopback_server_addresses() -> None:
    network = discover_network(runner=network_runner)

    assert network.interfaces["ens37"] == ("192.168.12.1",)
    assert network.protected_addresses == ("192.168.13.128", "192.168.12.1")


def test_generated_config_is_simulation_only_and_uses_discovered_tools() -> None:
    document = build_local_config(
        lab_interface="ens37",
        protected_addresses=("192.168.13.128", "192.168.12.1"),
        tcpdump_path="/usr/sbin/tcpdump",
        iptables_path="/usr/sbin/iptables",
        ssh_unit="ssh.service",
        dashboard_host="127.0.0.1",
        database_path="data/test.db",
        log_path="logs/test.log",
    )

    assert document["response"]["mode"] == "simulation"
    assert document["response"]["block_duration_seconds"] == 120
    assert document["network_sensor"]["interface"] == "ens37"
    assert document["network_sensor"]["protected_ipv4_addresses"] == [
        "192.168.13.128",
        "192.168.12.1",
    ]


def test_generated_config_rejects_public_dashboard_binding() -> None:
    with pytest.raises(SetupError, match="private or loopback"):
        build_local_config(
            lab_interface="ens37",
            protected_addresses=("192.168.12.1",),
            tcpdump_path="/usr/sbin/tcpdump",
            iptables_path="/usr/sbin/iptables",
            ssh_unit="ssh.service",
            dashboard_host="8.8.8.8",
            database_path="data/test.db",
            log_path="logs/test.log",
        )


def test_config_writer_preserves_existing_file_without_overwrite(tmp_path) -> None:
    path = tmp_path / "local.json"
    path.write_text('{"existing": true}\n', encoding="utf-8")

    write_local_config(path, {"replacement": True}, overwrite=False)

    assert json.loads(path.read_text(encoding="utf-8")) == {"existing": True}


def test_config_writer_backs_up_before_explicit_overwrite(tmp_path) -> None:
    path = tmp_path / "local.json"
    path.write_text('{"existing": true}\n', encoding="utf-8")

    write_local_config(path, {"replacement": True}, overwrite=True)

    assert json.loads(path.read_text(encoding="utf-8")) == {"replacement": True}
    backup = tmp_path / "local.json.before-test-setup"
    assert json.loads(backup.read_text(encoding="utf-8")) == {"existing": True}


def test_preview_lists_plan_without_privileged_commands(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.setup_environment.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    result = main(["--lab-interface", "ens37"], runner=network_runner)

    assert result == 0
    output = capsys.readouterr().out
    assert "Preview only" in output
    assert "response mode: simulation" in output


def test_preview_rejects_unknown_interface(capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        "ssh_security_app.setup_environment.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    result = main(["--lab-interface", "not-real"], runner=network_runner)

    assert result == 1
    assert "available: ens33, ens37, lo" in capsys.readouterr().err


def test_apply_runs_guarded_setup_and_writes_valid_config(
    tmp_path,
    capsys,
    monkeypatch,
) -> None:
    fake_module = tmp_path / "src" / "ssh_security_app" / "setup_environment.py"
    monkeypatch.setattr("ssh_security_app.setup_environment.__file__", str(fake_module))
    monkeypatch.setattr(
        "ssh_security_app.setup_environment.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )
    dashboard_asset = (
        tmp_path / "src" / "ssh_security_app" / "ui" / "static" / "index.html"
    )
    dashboard_asset.parent.mkdir(parents=True)
    dashboard_asset.write_text("<!doctype html>", encoding="utf-8")
    commands = []
    openssh_installed = {"value": False}

    def apply_runner(command, **kwargs):
        commands.append(command)
        if command == ["ip", "-j", "-4", "address", "show", "up"]:
            return subprocess.CompletedProcess(command, 0, IP_OUTPUT, "")
        if command[:2] == ["/usr/bin/systemctl", "show"]:
            unit = command[2]
            state = (
                "loaded\n"
                if unit == "ssh.service" and openssh_installed["value"]
                else "not-found\n"
            )
            return subprocess.CompletedProcess(command, 0, state, "")
        if command == [
            "/usr/bin/sudo",
            "/usr/bin/apt-get",
            "install",
            "-y",
            "openssh-server",
        ]:
            openssh_installed["value"] = True
            return subprocess.CompletedProcess(command, 0, "", "")
        if command == ["/usr/bin/systemctl", "is-active", "ssh.service"]:
            return subprocess.CompletedProcess(command, 0, "active\n", "")
        if command == ["/usr/bin/getcap", "/usr/bin/tcpdump"]:
            return subprocess.CompletedProcess(
                command,
                0,
                "/usr/bin/tcpdump cap_net_admin,cap_net_raw=eip\n",
                "",
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    result = main(
        [
            "--lab-interface",
            "ens37",
            "--config",
            "config/local.json",
            "--apply",
        ],
        runner=apply_runner,
    )

    assert result == 0
    document = json.loads((tmp_path / "config" / "local.json").read_text(encoding="utf-8"))
    assert document["response"]["mode"] == "simulation"
    assert document["network_sensor"]["protected_ipv4_addresses"] == [
        "192.168.13.128",
        "192.168.12.1",
    ]
    assert ["/usr/bin/sudo", "-v"] in commands
    assert [
        "/usr/bin/sudo",
        "/usr/bin/apt-get",
        "install",
        "-y",
        "openssh-server",
    ] in commands
    assert [
        "/usr/bin/sudo",
        "/usr/bin/systemctl",
        "enable",
        "--now",
        "ssh.service",
    ] in commands
    assert any("pip" in command for command in commands)
    output = capsys.readouterr().out
    assert "Setup complete" in output
    assert "standard-library server" in output
