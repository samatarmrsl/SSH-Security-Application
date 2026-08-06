from __future__ import annotations

import subprocess

from ssh_security_application import lab as workflow


def test_one_command_apply_uses_default_lab_values_and_confirms_firewall(
    monkeypatch,
    tmp_path,
    capsys,
) -> None:
    calls = {}

    def fake_installer(arguments, *, runner, repository_root):
        calls["arguments"] = arguments
        calls["runner"] = runner
        calls["repository_root"] = repository_root
        return 0

    monkeypatch.setattr(workflow, "install_start_and_verify_lab", fake_installer)

    result = workflow.main(["--apply"], repository_root=tmp_path)

    assert result == 0
    assert calls["repository_root"] == tmp_path
    assert calls["arguments"] == [
        "--lab-interface",
        "ens37",
        "--server-ip",
        "192.168.12.1",
        "--client-ip",
        "192.168.12.3",
        "--ssh-port",
        "22",
        "--block-duration-seconds",
        "120",
        "--apply",
        "--confirm-firewall-changes",
    ]
    assert "Useful verification commands" in capsys.readouterr().out


def test_one_command_can_override_lab_values(monkeypatch, tmp_path) -> None:
    calls = {}

    def fake_installer(arguments, *, runner, repository_root):
        calls["arguments"] = arguments
        return 0

    monkeypatch.setattr(workflow, "install_start_and_verify_lab", fake_installer)

    result = workflow.main(
        [
            "--apply",
            "--lab-interface",
            "ens40",
            "--server-ip",
            "10.10.10.5",
            "--client-ip",
            "10.10.10.20",
            "--block-duration-seconds",
            "180",
            "--skip-package-install",
        ],
        repository_root=tmp_path,
    )

    assert result == 0
    assert calls["arguments"] == [
        "--lab-interface",
        "ens40",
        "--server-ip",
        "10.10.10.5",
        "--client-ip",
        "10.10.10.20",
        "--ssh-port",
        "22",
        "--block-duration-seconds",
        "180",
        "--skip-package-install",
        "--apply",
        "--confirm-firewall-changes",
    ]


def test_one_command_watch_follows_service_logs_after_success(monkeypatch, tmp_path) -> None:
    calls = {}

    def fake_installer(arguments, *, runner, repository_root):
        return 0

    def fake_watch(*, runner):
        calls["watched"] = True
        return 0

    monkeypatch.setattr(workflow, "install_start_and_verify_lab", fake_installer)
    monkeypatch.setattr(workflow, "watch_application_service_log", fake_watch)

    result = workflow.main(["--apply", "--watch"], repository_root=tmp_path)

    assert result == 0
    assert calls["watched"] is True


def test_watch_log_reports_missing_journalctl(monkeypatch, capsys) -> None:
    def fake_which(name):
        return "/usr/bin/sudo" if name == "sudo" else None

    monkeypatch.setattr(workflow.shutil, "which", fake_which)

    result = workflow.watch_application_service_log(
        runner=lambda command: subprocess.CompletedProcess(command, 0)
    )

    assert result == 1
    assert "journalctl is not installed" in capsys.readouterr().err
