from __future__ import annotations

import json
import unittest

from re_ctm.errors import ReCTMError
from re_ctm.research import HTTPResponse, TheoremSearchClient


class TheoremSearchClientTestCase(unittest.TestCase):
    def test_bounded_normalization_and_usage_warning(self) -> None:
        def transport(_request, _timeout, _limit):
            return HTTPResponse(
                status=200,
                content_type="application/json; charset=utf-8",
                body=json.dumps(
                    [
                        {
                            "title": "Ordered fields",
                            "theorem": "For every real x, x^2 is nonnegative.",
                            "arxiv_id": "0000.00000",
                            "theorem_id": "T1",
                        },
                        "ignored",
                    ]
                ).encode("utf-8"),
            )

        client = TheoremSearchClient(transport=transport)
        result = client.search_theorems(
            query="For every real x, x^2 is nonnegative.",
            num_results=5,
            search_intent="theorem",
        )
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["theorem_id"], "T1")
        self.assertEqual(result["source_trust"], "external_unverified")
        self.assertIn("verify applicability", result["usage_rule"])

    def test_non_https_endpoint_is_rejected(self) -> None:
        with self.assertRaises(ReCTMError) as denied:
            TheoremSearchClient("http://example.com/search")
        self.assertEqual(denied.exception.code, "INVALID_RESEARCH_ENDPOINT")


if __name__ == "__main__":
    unittest.main()
