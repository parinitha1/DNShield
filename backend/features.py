import math

def calculate_entropy(domain):
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum([p * math.log2(p) for p in prob])

def extract_features(domain):
    return {
        "length": len(domain),
        "entropy": calculate_entropy(domain)
    }