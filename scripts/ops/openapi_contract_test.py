import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class OpenAPIContractTest(unittest.TestCase):
    def test_trace_and_investigation_exports_are_documented(self):
        spec = (ROOT / "openapi.yml").read_text(encoding="utf-8")
        for text in [
            "/api/v1/alerts/{id}/svg:",
            "/api/v1/alerts/{id}/svg/view:",
            "/api/v1/investigation/report:",
            "operationId: getInvestigationReport",
            "$ref: \"#/components/schemas/InvestigationReport\"",
            "enum: [tree, compact, timeline, grouped]",
            "enum: [json, markdown]",
            "text/markdown:",
        ]:
            self.assertIn(text, spec)

    def test_developer_openapi_summary_lists_trace_exports(self):
        spec = (ROOT / "docs/developer/openapi.yaml").read_text(encoding="utf-8")
        for text in [
            "/api/v1/alerts/{id}/svg:",
            "/api/v1/alerts/{id}/svg/view:",
            "/api/v1/investigation/report:",
            "enum: [tree, compact, timeline, grouped]",
        ]:
            self.assertIn(text, spec)


if __name__ == "__main__":
    unittest.main()
