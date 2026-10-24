"""Pin the cached-token alias contract.

Upstreams disagree on where the cache hit lives: prompt_tokens_details
.cached_tokens, prompt_cache_hit_tokens, cache_read_input_tokens,
input_tokens_details.cached_tokens ... and some responses carry the real value
in one while emitting 0 in the others. Strict clients pick one alias and then
report "no cache hits" forever. The gateway now reads the best positive value
across every alias and writes it back into all of them.

Run with: python tests/_test_usage_cache_aliases.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_proxy as proxy
import ca_protocol


class BestCachedTokensTests(unittest.TestCase):
    def test_every_alias_is_read(self):
        cases = [
            {"prompt_tokens_details": {"cached_tokens": 12}},
            {"prompt_cache_hit_tokens": 12},
            {"cache_read_input_tokens": 12},
            {"cached_tokens": 12},
            {"input_tokens_details": {"cached_tokens": 12}},
            {"completion_tokens_details": {"cached_tokens": 12}},
        ]
        for usage in cases:
            self.assertEqual(ca_protocol.best_cached_tokens(usage), 12, usage)

    def test_zero_aliases_do_not_shadow_a_real_hit(self):
        usage = {"prompt_tokens_details": {"cached_tokens": 0},
                 "cache_read_input_tokens": 5}
        self.assertEqual(ca_protocol.best_cached_tokens(usage), 5)

    def test_missing_or_broken_usage_is_zero(self):
        self.assertEqual(ca_protocol.best_cached_tokens(None), 0)
        self.assertEqual(ca_protocol.best_cached_tokens({}), 0)
        self.assertEqual(ca_protocol.best_cached_tokens({"cached_tokens": "x"}), 0)


class ExtractUsageTests(unittest.TestCase):
    def test_extract_usage_uses_the_best_alias(self):
        usage = {"prompt_tokens": 100, "completion_tokens": 5,
                 "total_tokens": 105, "cached_tokens": 0,
                 "prompt_tokens_details": {"cached_tokens": 80}}
        fields = proxy._extract_usage(usage)
        self.assertEqual(fields["cached_tokens"], 80)
        self.assertEqual(fields["total_tokens"], 105)


if __name__ == "__main__":
    unittest.main(verbosity=2)
