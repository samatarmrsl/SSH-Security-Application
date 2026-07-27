"""Parse only the exact project-owned iptables rule shape."""

from __future__ import annotations

import ipaddress
import shlex
from collections import Counter
from dataclasses import dataclass


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
