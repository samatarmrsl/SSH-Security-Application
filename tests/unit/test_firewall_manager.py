from __future__ import annotations

import subprocess

import pytest

from ssh_security_app.config import load_config
from ssh_security_app.constants import HealthState
from ssh_security_app.response.firewall_manager import (
    FirewallCommandBuilder,
    FirewallManager,
)


def test_command_builder_uses_exact_dedicated_chain_commands() -> None:
    builder = FirewallCommandBuilder(
        executable="/usr/sbin/iptables",
        chain="SSH_SECURITY_APP",
        ssh_port=22,
    )

    assert builder.check_block("192.168.56.40") == [
        "/usr/sbin/iptables",
        "-w",
        "5",
        "-C",
        "SSH_SECURITY_APP",
        "-s",
        "192.168.56.40",
        "-p",
        "tcp",
        "--dport",
        "22",
        "-j",
        "DROP",
    ]
    assert builder.delete_block("192.168.56.40")[3:5] == [
        "-D",
        "SSH_SECURITY_APP",
    ]
    all_commands = (
        builder.create_chain(),
        builder.insert_input_jump(),
        builder.insert_block("192.168.56.40"),
        builder.delete_block("192.168.56.40"),
    )
    assert all("-F" not in command and "-P" not in command for command in all_commands)


@pytest.mark.parametrize(
    ("executable", "chain"),
    [
        ("iptables", "SSH_SECURITY_APP"),
        ("/usr/sbin/iptables", "bad-chain"),
    ],
)
def test_command_builder_rejects_unsafe_configuration(executable, chain) -> None:
    with pytest.raises(ValueError):
        FirewallCommandBuilder(executable=executable, chain=chain, ssh_port=22)


def test_command_builder_rejects_non_ipv4_rule_input() -> None:
    builder = FirewallCommandBuilder(
        executable="/usr/sbin/iptables",
        chain="SSH_SECURITY_APP",
        ssh_port=22,
    )

    with pytest.raises(ValueError):
        builder.insert_block("192.168.56.40; DROP TABLE")


def test_chain_initialization_and_rules_are_idempotent(fake_iptables) -> None:
    health = []
    manager = FirewallManager(
        load_config().response,
        ssh_port=22,
        runner=fake_iptables,
        on_health=health.append,
    )

    first = manager.initialize_chain()
    second = manager.initialize_chain()
    inserted = manager.insert_block_rule("192.168.56.40")
    duplicate = manager.insert_block_rule("192.168.56.40")
    list_result, rules = manager.list_project_rules()
    deleted = manager.delete_block_rule("192.168.56.40")
    absent = manager.delete_block_rule("192.168.56.40")

    assert first.success and first.changed
    assert second.success and not second.changed
    assert inserted.success and inserted.changed
    assert duplicate.success and not duplicate.changed
    assert list_result.success
    assert len(rules) == 1
    assert deleted.success and deleted.changed
    assert absent.success and not absent.changed
    assert health[-1].status is HealthState.HEALTHY


def test_readiness_requires_both_chain_and_input_jump(fake_iptables) -> None:
    manager = FirewallManager(
        load_config().response,
        ssh_port=22,
        runner=fake_iptables,
    )

    assert manager.inspect_readiness() == (True, False)
    fake_iptables.chain_exists = True
    assert manager.inspect_readiness() == (True, False)
    fake_iptables.input_jump_exists = True
    assert manager.inspect_readiness() == (True, True)


def test_cleanup_removes_only_recognized_project_state(fake_iptables) -> None:
    manager = FirewallManager(
        load_config().response,
        ssh_port=22,
        runner=fake_iptables,
    )
    assert manager.initialize_chain().success
    assert manager.insert_block_rule("192.168.56.40").success

    result = manager.cleanup_project_chain()

    assert result.success and result.changed
    assert fake_iptables.blocked_sources == set()
    assert fake_iptables.input_jump_exists is False
    assert fake_iptables.chain_exists is False
    commands = [command_result.command for command_result in result.command_results]
    assert all("-F" not in command and "-P" not in command for command in commands)


def test_command_execution_failure_is_explicit() -> None:
    def fail(_command):
        raise subprocess.TimeoutExpired(["iptables"], 1)

    manager = FirewallManager(load_config().response, ssh_port=22, runner=fail)

    result = manager.initialize_chain()

    assert not result.success
    assert "unavailable" in result.message
