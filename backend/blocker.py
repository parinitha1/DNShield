"""
blocker.py — maintains a set of blocked domains detected as malicious.
When a domain is blocked, the sniffer will drop future packets for it.
"""

blocked_domains: set[str] = set()

def block_domain(domain: str) -> None:
    """Add domain to the in-memory block list."""
    blocked_domains.add(domain)
    print(f"[BLOCKED] {domain}")

def is_blocked(domain: str) -> bool:
    return domain in blocked_domains
