from analysis.trie import Trie
from analysis.levenshtein import levenshtein_distance
from config.settings import TYPOSQUATTING_EDIT_DISTANCE
from config.database import get_connection

legit_trie = Trie()
legit_trie.load_from_file("data/domain_lists/legit_domains.txt")
legit_domains = legit_trie.get_all_domains()

def check_typosquatting(domain):
    if legit_trie.search(domain):
        return {
            "queried_domain": domain,
            "matched_legit_domain": domain,
            "edit_distance": 0,
            "is_suspicious": False,
            "reason": "Exact match in legitimate domains"
        }

    best_match = None
    best_distance = float("inf")

    for legit in legit_domains:
        dist = levenshtein_distance(domain, legit)
        if dist < best_distance:
            best_distance = dist
            best_match = legit

    is_suspicious = 0 < best_distance <= TYPOSQUATTING_EDIT_DISTANCE

    return {
        "queried_domain": domain,
        "matched_legit_domain": best_match,
        "edit_distance": best_distance,
        "is_suspicious": is_suspicious,
        "reason": f"Similar to {best_match} with edit distance {best_distance}" if is_suspicious else "No typosquatting detected"
    }

def save_typosquatting_result(result):
    conn = get_connection()
    cursor = conn.cursor()
    query = """
        INSERT INTO typosquatting_results 
        (queried_domain, matched_legit_domain, edit_distance, is_suspicious)
        VALUES (%s, %s, %s, %s)
    """
    cursor.execute(query, (
        result["queried_domain"],
        result["matched_legit_domain"],
        result["edit_distance"],
        result["is_suspicious"]
    ))
    conn.commit()
    cursor.close()
    conn.close()

def analyze_all_records():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT domain FROM dns_records")
    domains = cursor.fetchall()
    cursor.close()
    conn.close()

    results = []
    for (domain,) in domains:
        result = check_typosquatting(domain)
        save_typosquatting_result(result)
        results.append(result)
    return results