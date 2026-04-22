import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from analysis.trie import Trie

class TestTrie:

    def setup_method(self):
        self.trie = Trie()
        for domain in ["google.com", "amazon.com", "facebook.com", "github.com"]:
            self.trie.insert(domain)

    def test_exact_match_found(self):
        assert self.trie.search("google.com") is True

    def test_missing_domain_not_found(self):
        assert self.trie.search("evil.com") is False

    def test_partial_match_not_found(self):
        assert self.trie.search("google") is False

    def test_all_inserted_domains_found(self):
        domains = ["google.com", "amazon.com", "facebook.com", "github.com"]
        for d in domains:
            assert self.trie.search(d) is True

    def test_get_all_returns_correct_count(self):
        all_domains = self.trie.get_all_domains()
        assert len(all_domains) == 4

    def test_insert_and_search_new_domain(self):
        self.trie.insert("newdomain.net")
        assert self.trie.search("newdomain.net") is True

    def test_load_from_file(self):
        new_trie = Trie()
        new_trie.load_from_file("data/domain_lists/legit_domains.txt")
        assert new_trie.search("google.com") is True
        assert new_trie.search("paypal.com") is True

    def test_case_sensitive(self):
        assert self.trie.search("Google.com") is False