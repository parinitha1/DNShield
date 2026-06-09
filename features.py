"""
features.py — DNS Shield
Core mathematical feature-extraction module.

Exposes two public functions:
  • calculate_shannon_entropy(domain_string) -> float
  • extract_features(domain_string)          -> dict
"""

import math


def calculate_shannon_entropy(domain_string: str) -> float:
    """
    Compute the Shannon entropy (in bits) of a domain string.

    Formula:
        H(d) = -sum( p(c) * log2(p(c)) )  for each unique character c in d

    where p(c) = count(c) / len(d).

    Parameters
    ----------
    domain_string : str
        Raw domain name (e.g. "www.google.com" or a long base64-encoded label).

    Returns
    -------
    float
        Entropy in bits.  Returns 0.0 for empty or single-char strings.

    Examples
    --------
    >>> calculate_shannon_entropy("aaaa")
    0.0
    >>> calculate_shannon_entropy("abcd")
    2.0
    """
    if not domain_string or len(domain_string) < 2:
        return 0.0

    n = len(domain_string)
    freq: dict = {}
    for ch in domain_string:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * math.log2(p)

    return entropy


def extract_features(domain_string: str) -> dict:
    """
    Extract numerical features from a DNS query domain name.

    Features
    --------
    length  (int)   : Absolute character count of the domain string.
    entropy (float) : Shannon entropy of the domain string (bits).

    Discrimination logic:
      - Benign domains   => short (10-30 chars), low entropy  (2.1-3.2 bits)
      - Tunneled domains => long  (70-120 chars), high entropy (4.5-5.8 bits)

    Parameters
    ----------
    domain_string : str
        Raw domain name. Leading/trailing whitespace and trailing dots
        (present in Scapy DNSQR.qname bytes) are stripped automatically.

    Returns
    -------
    dict  with keys:
        "length"  -> int
        "entropy" -> float (rounded to 6 decimal places)

    Raises
    ------
    TypeError  : If domain_string is not a str.
    ValueError : If domain_string is empty after sanitisation.
    """
    if not isinstance(domain_string, str):
        raise TypeError(
            f"domain_string must be str, got {type(domain_string).__name__}"
        )

    cleaned = domain_string.strip().rstrip(".")
    if not cleaned:
        raise ValueError("domain_string is empty after sanitisation.")

    return {
        "length":  len(cleaned),
        "entropy": round(calculate_shannon_entropy(cleaned), 6),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Quick self-test  (python features.py)
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cases = [
        ("www.google.com",           "benign"),
        ("mail.yahoo.co.in",         "benign"),
        ("aaaa",                     "trivial"),
        ("aB3kQz9xLmPvRwTyDfGhJs.bZqXcVmNpLo.evil-corp.net", "simulated tunnel"),
    ]
    print(f"{'Domain':<55} {'Length':>6}  {'Entropy':>8}  Label")
    print("-" * 80)
    for domain, label in cases:
        feats = extract_features(domain)
        print(f"{domain:<55} {feats['length']:>6}  {feats['entropy']:>8.4f}  {label}")
