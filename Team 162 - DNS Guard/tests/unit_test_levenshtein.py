import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from analysis.levenshtein import levenshtein_distance

class TestLevenshteinDistance:

    def test_identical_strings(self):
        assert levenshtein_distance("google", "google") == 0

    def test_one_substitution(self):
        assert levenshtein_distance("google", "g00gle") == 2

    def test_one_deletion(self):
        assert levenshtein_distance("google", "gogle") == 1

    def test_one_insertion(self):
        assert levenshtein_distance("google", "gooogle") == 1

    def test_empty_strings(self):
        assert levenshtein_distance("", "") == 0

    def test_one_empty_string(self):
        assert levenshtein_distance("google", "") == 6
        assert levenshtein_distance("", "google") == 6

    def test_completely_different(self):
        dist = levenshtein_distance("google", "amazon")
        assert dist > 3

    def test_result_is_integer(self):
        result = levenshtein_distance("test", "text")
        assert isinstance(result, int)

    def test_symmetric(self):
        d1 = levenshtein_distance("google", "g00gle")
        d2 = levenshtein_distance("g00gle", "google")
        assert d1 == d2

    def test_paypal_typo(self):
        assert levenshtein_distance("paypal", "paypa1") == 1