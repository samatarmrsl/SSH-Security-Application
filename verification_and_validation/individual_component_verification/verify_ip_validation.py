from __future__ import annotations

import pytest
from ssh_security_application.constants import IPAddressCategory
from ssh_security_application.ip_validation import validate_ip_address


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("192.168.56.20", IPAddressCategory.PRIVATE),
        ("8.8.8.8", IPAddressCategory.GLOBALLY_REACHABLE),
        ("127.0.0.1", IPAddressCategory.LOOPBACK),
        ("169.254.10.20", IPAddressCategory.LINK_LOCAL),
        ("224.0.0.1", IPAddressCategory.MULTICAST),
        ("0.0.0.0", IPAddressCategory.UNSPECIFIED),
        ("240.0.0.1", IPAddressCategory.RESERVED_OR_SPECIAL_PURPOSE),
    ],
)
def test_ipv4_categories(value, category) -> None:
    result = validate_ip_address(value)

    assert result.is_valid is True
    assert result.ip_version == 4
    assert result.category is category


def test_private_lab_ipv4_is_detection_and_block_eligible() -> None:
    result = validate_ip_address(" 192.168.056.020 ")

    assert result.is_valid is False
    assert result.eligible_for_automatic_blocking is False

    valid = validate_ip_address("192.168.56.20")
    assert valid.eligible_for_detection is True
    assert valid.eligible_for_automatic_blocking is True
    assert valid.exclusion_reason is None


def test_allowlisted_address_is_still_detection_eligible() -> None:
    result = validate_ip_address("192.168.56.20", allowlisted=True)

    assert result.eligible_for_detection is True
    assert result.eligible_for_automatic_blocking is False
    assert "allowlist" in (result.exclusion_reason or "")


def test_protected_server_address_cannot_be_blocked() -> None:
    result = validate_ip_address(
        "192.168.56.10",
        protected_addresses=["192.168.56.10"],
    )

    assert result.eligible_for_detection is True
    assert result.eligible_for_automatic_blocking is False
    assert "protected SSH server" in (result.exclusion_reason or "")


def test_ipv6_is_valid_but_ineligible_in_version_one() -> None:
    result = validate_ip_address("2001:4860:4860::8888")

    assert result.is_valid is True
    assert result.ip_version == 6
    assert result.eligible_for_detection is False
    assert result.eligible_for_automatic_blocking is False
    assert "IPv6" in (result.exclusion_reason or "")


@pytest.mark.parametrize("value", [None, "", "not-an-ip", "999.1.1.1"])
def test_invalid_values_have_an_explanation(value) -> None:
    result = validate_ip_address(value)

    assert result.is_valid is False
    assert result.category is IPAddressCategory.INVALID
    assert result.normalized_ip is None
    assert result.exclusion_reason
