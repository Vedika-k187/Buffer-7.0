import re
from analysis.entropy_detector import calculate_entropy

def extract_features(domain):
    name = domain.split(".")[0]
    
    domain_length = len(domain)
    entropy_score = calculate_entropy(domain)
    
    digit_count = sum(1 for c in name if c.isdigit())
    digit_ratio = digit_count / len(name) if len(name) > 0 else 0
    
    hyphen_count = domain.count("-")
    subdomain_count = len(domain.split(".")) - 2
    subdomain_count = max(0, subdomain_count)

    return {
        "domain": domain,
        "domain_length": domain_length,
        "entropy_score": entropy_score,
        "digit_ratio": round(digit_ratio, 4),
        "hyphen_count": hyphen_count,
        "subdomain_count": subdomain_count
    }