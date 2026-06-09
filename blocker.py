"""
blocker.py — DNS Shield
Thread-safe in-memory block list for malicious FQDNs.

The DomainBlocker class wraps a Python set with a threading.RLock so that
concurrent reads from the sniffer thread and writes from the ML pipeline
never race.  A global singleton `blocker` is exported for convenience.
"""

import threading
from typing import FrozenSet


class DomainBlocker:
    """
    Thread-safe in-memory store for blocked Fully Qualified Domain Names.

    Attributes (private)
    --------------------
    _blocked : set[str]
        The canonical set of currently blocked domains (lower-cased FQDNs).
    _lock    : threading.RLock
        Re-entrant lock protecting all mutations and reads.
    _block_count : int
        Running total of unique domains added (never decremented on remove).

    Public methods
    --------------
    add(domain)      -> bool   : Block a domain; returns True if newly added.
    is_blocked(domain) -> bool : Return True if the domain is on the list.
    remove(domain)   -> bool   : Remove a domain; returns True if it existed.
    snapshot()       -> list   : Return a sorted copy of all blocked domains.
    size()           -> int    : Number of currently blocked domains.
    clear()          -> int    : Wipe the block list; returns count removed.
    """

    def __init__(self) -> None:
        self._blocked: set = set()
        self._lock = threading.RLock()
        self._block_count: int = 0   # monotonically increasing

    # ── Write operations ──────────────────────────────────────────────────────

    def add(self, domain: str) -> bool:
        """
        Add a domain to the block list.

        The domain is normalised to lower-case before storage so that
        lookups are case-insensitive.  Trailing dots (from Scapy QNAME) are
        stripped.

        Parameters
        ----------
        domain : str
            FQDN to block (e.g. "evil.tunnel.io").

        Returns
        -------
        bool
            True if the domain was newly added, False if it was already present.
        """
        if not domain or not isinstance(domain, str):
            return False

        normalised = domain.strip().rstrip(".").lower()
        if not normalised:
            return False

        with self._lock:
            if normalised in self._blocked:
                return False          # already blocked — no-op
            self._blocked.add(normalised)
            self._block_count += 1
            return True

    def remove(self, domain: str) -> bool:
        """
        Remove a domain from the block list.

        Parameters
        ----------
        domain : str
            FQDN to unblock.

        Returns
        -------
        bool
            True if it was present and removed, False if not found.
        """
        if not domain or not isinstance(domain, str):
            return False

        normalised = domain.strip().rstrip(".").lower()
        with self._lock:
            if normalised in self._blocked:
                self._blocked.discard(normalised)
                return True
            return False

    def clear(self) -> int:
        """
        Remove all entries from the block list.

        Returns
        -------
        int
            Number of entries removed.
        """
        with self._lock:
            count = len(self._blocked)
            self._blocked.clear()
            return count

    # ── Read operations ───────────────────────────────────────────────────────

    def is_blocked(self, domain: str) -> bool:
        """
        Return True if the domain (or its normalised form) is on the block list.

        This is the hot path — called for every DNS packet that reaches the
        feature-extraction stage.  The RLock adds ~100 ns overhead vs a bare
        set lookup; negligible at DNS query rates.

        Parameters
        ----------
        domain : str
            FQDN to check.

        Returns
        -------
        bool
        """
        if not domain or not isinstance(domain, str):
            return False

        normalised = domain.strip().rstrip(".").lower()
        with self._lock:
            return normalised in self._blocked

    def snapshot(self) -> list:
        """
        Return a sorted list of all currently blocked domains.

        The list is a fresh copy — the caller may iterate it safely even
        while the sniffer thread mutates the underlying set.

        Returns
        -------
        list[str]
        """
        with self._lock:
            return sorted(self._blocked)

    def size(self) -> int:
        """Return the number of currently blocked domains."""
        with self._lock:
            return len(self._blocked)

    @property
    def total_blocked_ever(self) -> int:
        """Monotonically increasing count of unique domains ever blocked."""
        with self._lock:
            return self._block_count

    # ── Dunder helpers ────────────────────────────────────────────────────────

    def __len__(self) -> int:
        return self.size()

    def __contains__(self, domain: str) -> bool:
        return self.is_blocked(domain)

    def __repr__(self) -> str:
        return f"DomainBlocker(size={self.size()}, ever_blocked={self._block_count})"


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton — import this everywhere
# ──────────────────────────────────────────────────────────────────────────────
blocker = DomainBlocker()


# ──────────────────────────────────────────────────────────────────────────────
# Self-test  (python blocker.py)
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import time, threading

    def _stress_writer(n: int):
        for i in range(n):
            blocker.add(f"domain{i}.evil.net")

    def _stress_reader(n: int):
        for i in range(n):
            _ = blocker.is_blocked(f"domain{i}.evil.net")

    threads = [
        threading.Thread(target=_stress_writer, args=(200,)),
        threading.Thread(target=_stress_reader, args=(200,)),
        threading.Thread(target=_stress_writer, args=(200,)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"Blocker after stress test: {blocker}")
    print(f"Sample snapshot (first 5): {blocker.snapshot()[:5]}")

    assert blocker.is_blocked("domain0.evil.net"), "Should be blocked"
    assert not blocker.is_blocked("google.com"),   "Should NOT be blocked"
    assert blocker.is_blocked("DOMAIN0.EVIL.NET"), "Case-insensitive check"

    print("[✓] All assertions passed.")
