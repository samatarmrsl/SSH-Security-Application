"""Explicit IP normalization, classification, and safety eligibility."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from ssh_guard.constants import IPAddressCategory
from ssh_guard.models import IPValidationResult


def validate_ip_address(
    value: str | None,
    *,
    protected_addresses: Iterable[str] = (),
    allowlisted: bool = False,
) -> IPValidationResult:
    """Validate an IP and explain whether it may be detected or blocked.

    Version 1 records valid IPv6 evidence but does not use IPv6 for detection or
    automatic firewall action. Only private and globally reachable IPv4 sources
    are detection candidates. Private IPv4 is intentionally allowed for the lab.
    """

    original = value
    candidate = value.strip() if isinstance(value, str) else ""
    if not candidate:
        return _invalid(original, "IP address is missing")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return _invalid(original, "Value is not a valid IP address")

    normalized = str(address)
    category = _classify(address)

    if address.version != 4:
        return IPValidationResult(
            original_value=original,
            normalized_ip=normalized,
            is_valid=True,
            ip_version=address.version,
            category=category,
            eligible_for_detection=False,
            eligible_for_automatic_blocking=False,
            exclusion_reason=(
                "IPv6 is recorded but is not supported for detection or blocking in version 1"
            ),
        )

    detectable = category in {
        IPAddressCategory.PRIVATE,
        IPAddressCategory.GLOBALLY_REACHABLE,
    }
    if not detectable:
        return IPValidationResult(
            original_value=original,
            normalized_ip=normalized,
            is_valid=True,
            ip_version=4,
            category=category,
            eligible_for_detection=False,
            eligible_for_automatic_blocking=False,
            exclusion_reason=f"{category.value} addresses are excluded from detection and blocking",
        )

    normalized_protected = _normalize_protected_addresses(protected_addresses)
    if normalized in normalized_protected:
        return IPValidationResult(
            original_value=original,
            normalized_ip=normalized,
            is_valid=True,
            ip_version=4,
            category=category,
            eligible_for_detection=True,
            eligible_for_automatic_blocking=False,
            exclusion_reason="Address belongs to the protected SSH server",
        )

    if allowlisted:
        return IPValidationResult(
            original_value=original,
            normalized_ip=normalized,
            is_valid=True,
            ip_version=4,
            category=category,
            eligible_for_detection=True,
            eligible_for_automatic_blocking=False,
            exclusion_reason="Address has an active allowlist entry",
        )

    return IPValidationResult(
        original_value=original,
        normalized_ip=normalized,
        is_valid=True,
        ip_version=4,
        category=category,
        eligible_for_detection=True,
        eligible_for_automatic_blocking=True,
        exclusion_reason=None,
    )


def _invalid(original: str | None, reason: str) -> IPValidationResult:
    return IPValidationResult(
        original_value=original,
        normalized_ip=None,
        is_valid=False,
        ip_version=None,
        category=IPAddressCategory.INVALID,
        eligible_for_detection=False,
        eligible_for_automatic_blocking=False,
        exclusion_reason=reason,
    )


def _classify(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> IPAddressCategory:
    if address.is_unspecified:
        return IPAddressCategory.UNSPECIFIED
    if address.is_loopback:
        return IPAddressCategory.LOOPBACK
    if address.is_link_local:
        return IPAddressCategory.LINK_LOCAL
    if address.is_multicast:
        return IPAddressCategory.MULTICAST
    if address.is_reserved:
        return IPAddressCategory.RESERVED_OR_SPECIAL_PURPOSE
    if address.is_private:
        return IPAddressCategory.PRIVATE
    if address.is_global:
        return IPAddressCategory.GLOBALLY_REACHABLE
    return IPAddressCategory.RESERVED_OR_SPECIAL_PURPOSE


def _normalize_protected_addresses(values: Iterable[str]) -> set[str]:
    normalized: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value.strip())
        except (AttributeError, ValueError):
            continue
        if address.version == 4:
            normalized.add(str(address))
    return normalized
