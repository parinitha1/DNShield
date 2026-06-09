"""
data_generator.py — DNS Shield
Generates a synthetic training dataset of benign and malicious (DNS-tunneled)
domain queries for the Isolation Forest model.

Output: dns_training_data.csv  (columns: domain, length, entropy, label)
"""

import random
import string
import math
import csv
import os

# ──────────────────────────────────────────────────────────────────────────────
# Reproducibility
# ──────────────────────────────────────────────────────────────────────────────
RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# ──────────────────────────────────────────────────────────────────────────────
# Helper: Shannon entropy
# ──────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) for a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# ──────────────────────────────────────────────────────────────────────────────
# Benign domain generators
# ──────────────────────────────────────────────────────────────────────────────

# Common English syllables to produce natural-looking hostnames
_SYLLABLES = [
    "ab", "ac", "ad", "al", "am", "an", "ar", "at", "be", "bi",
    "bo", "bu", "ca", "ce", "ci", "co", "cu", "da", "de", "di",
    "do", "du", "ea", "ed", "el", "em", "en", "er", "es", "et",
    "fa", "fe", "fi", "fo", "fu", "ga", "ge", "gi", "go", "gu",
    "ha", "he", "hi", "ho", "hu", "ia", "ic", "id", "ie", "ig",
    "il", "im", "in", "io", "ip", "ir", "is", "it", "ja", "je",
    "jo", "ju", "ka", "ke", "ki", "ko", "ku", "la", "le", "li",
    "lo", "lu", "ma", "me", "mi", "mo", "mu", "na", "ne", "ni",
    "no", "nu", "oa", "ob", "oc", "od", "of", "on", "op", "or",
    "os", "ot", "ou", "ov", "ow", "ox", "pa", "pe", "pi", "po",
    "pu", "ra", "re", "ri", "ro", "ru", "sa", "se", "si", "so",
    "su", "ta", "te", "ti", "to", "tu", "ua", "ub", "uc", "ud",
    "ue", "uf", "ug", "ul", "um", "un", "up", "ur", "us", "ut",
    "va", "ve", "vi", "vo", "vu", "wa", "we", "wi", "wo", "ya",
    "ye", "yo", "za", "ze", "zi", "zo", "tion", "ing", "ness",
    "ment", "able", "ible", "ful", "less", "ous", "ive", "ance",
]

_TLDS = [".com", ".net", ".org", ".edu", ".io", ".co", ".info",
         ".gov", ".biz", ".app", ".dev", ".tech"]

_SUBDOMAINS = ["www", "mail", "blog", "shop", "api", "cdn", "static",
               "media", "assets", "login", "auth", "docs", "support", ""]


def _make_benign_domain(target_length_range=(10, 30)) -> str:
    """
    Build a human-readable, natural-looking domain.
    Iterates until the assembled string falls within the target length range
    AND its entropy lands between 2.1 and 3.2 bits.
    """
    tld = random.choice(_TLDS)
    subdomain = random.choice(_SUBDOMAINS)
    prefix = (subdomain + ".") if subdomain else ""

    for _ in range(500):  # up to 500 attempts
        # build hostname from syllables
        n_syllables = random.randint(2, 5)
        hostname = "".join(random.choice(_SYLLABLES) for _ in range(n_syllables))

        domain = f"{prefix}{hostname}{tld}"
        length = len(domain)
        entropy = _shannon_entropy(domain)

        if (target_length_range[0] <= length <= target_length_range[1]
                and 2.1 <= entropy <= 3.2):
            return domain

    # Fallback: return whatever we have last (shouldn't happen often)
    return domain


# ──────────────────────────────────────────────────────────────────────────────
# Malicious (tunneled) domain generators
# ──────────────────────────────────────────────────────────────────────────────

_BASE64_CHARS = string.ascii_letters + string.digits + "+/="
_HEX_CHARS    = string.digits + "abcdef"

_C2_TLDS = [".evil-corp.net", ".data-exfil.com", ".tunnel.io",
            ".c2server.net", ".botnet.xyz", ".exfil.ru"]


def _make_malicious_domain(target_length_range=(70, 120)) -> str:
    """
    Simulate a DNS-tunneled query by embedding a pseudo-encoded payload
    (Base64 or Hex) as multiple labels in the domain name.
    Entropy must be between 4.5 and 5.8 bits.
    """
    c2_tld = random.choice(_C2_TLDS)
    encoding = random.choice(["base64", "hex"])
    char_pool = _BASE64_CHARS if encoding == "base64" else _HEX_CHARS

    for _ in range(500):
        # Payload chunk split across 2-4 labels of 20-35 chars each
        labels = []
        n_labels = random.randint(2, 4)
        for _ in range(n_labels):
            lbl_len = random.randint(20, 35)
            labels.append("".join(random.choice(char_pool) for _ in range(lbl_len)))

        domain = ".".join(labels) + c2_tld
        length = len(domain)
        entropy = _shannon_entropy(domain)

        if (target_length_range[0] <= length <= target_length_range[1]
                and 4.5 <= entropy <= 5.8):
            return domain

    return domain  # fallback


# ──────────────────────────────────────────────────────────────────────────────
# Dataset assembly
# ──────────────────────────────────────────────────────────────────────────────

def generate_dataset(
    n_benign: int = 2000,
    n_malicious: int = 500,
    output_path: str = "dns_training_data.csv",
) -> None:
    """
    Generate synthetic DNS query records and write them to a CSV file.

    Parameters
    ----------
    n_benign   : Number of benign samples to generate (default 2000).
    n_malicious: Number of malicious samples to generate (default 500).
    output_path: Destination CSV file path.
    """
    records = []

    print(f"[*] Generating {n_benign} benign records …")
    for i in range(n_benign):
        domain = _make_benign_domain()
        records.append({
            "domain":  domain,
            "length":  len(domain),
            "entropy": round(_shannon_entropy(domain), 6),
            "label":   0,
        })
        if (i + 1) % 500 == 0:
            print(f"    {i + 1}/{n_benign} benign done")

    print(f"[*] Generating {n_malicious} malicious records …")
    for i in range(n_malicious):
        domain = _make_malicious_domain()
        records.append({
            "domain":  domain,
            "length":  len(domain),
            "entropy": round(_shannon_entropy(domain), 6),
            "label":   1,
        })
        if (i + 1) % 100 == 0:
            print(f"    {i + 1}/{n_malicious} malicious done")

    # Shuffle before saving so train/test splits are fair
    random.shuffle(records)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True) \
        if os.path.dirname(output_path) else None

    fieldnames = ["domain", "length", "entropy", "label"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    benign_count    = sum(1 for r in records if r["label"] == 0)
    malicious_count = sum(1 for r in records if r["label"] == 1)
    print(f"\n[✓] Dataset saved → {output_path}")
    print(f"    Total records : {len(records)}")
    print(f"    Benign  (0)   : {benign_count}")
    print(f"    Malicious (1) : {malicious_count}")
    print(f"    Contamination : {malicious_count / len(records):.2%}")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    generate_dataset(
        n_benign=2000,
        n_malicious=500,
        output_path="dns_training_data.csv",
    )
