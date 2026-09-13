import tempfile
import unittest
from pathlib import Path

from core.scanner import _capture_source_snippets
from core.translator import transform_semgrep_to_cyclonedx


class SourceEvidenceTests(unittest.TestCase):
    def finding(self, path, start=2, end=3):
        return {
            "path": str(path),
            "start": {"line": start},
            "end": {"line": end},
            "extra": {"metadata": {"algorithm": "RSA"}},
        }

    def test_evidence_survives_temporary_source_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "crypto.py"
            source.write_text("# header\nkey = RSA.generate(\n    2048)\n# footer\n")
            result = {"results": [self.finding(source)]}
            _capture_source_snippets(result, root)
        bom = transform_semgrep_to_cyclonedx(result)
        properties = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
        self.assertEqual(properties["ecdat:source:snippet"], "key = RSA.generate(\n    2048)")
        self.assertEqual(properties["ecdat:source:start-line"], "2")
        self.assertEqual(properties["ecdat:source:truncated"], "false")

    def test_missing_and_outside_files_do_not_disclose_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            target.mkdir()
            outside = root / "outside.py"
            outside.write_text("private\nprivate\nprivate\n")
            (target / "link.py").symlink_to(outside)
            findings = [self.finding(outside), self.finding(target / "missing.py"), self.finding(target / "link.py")]
            _capture_source_snippets({"results": findings}, target)
            for finding in findings:
                self.assertNotIn("ecdat_source", finding["extra"])

    def test_large_matches_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "large.py"
            source.write_text(("x" * 500 + "\n") * 100)
            finding = self.finding(source, 1, 100)
            _capture_source_snippets({"results": [finding]}, root)
            evidence = finding["extra"]["ecdat_source"]
            self.assertLessEqual(len(evidence["code"]), 16000)
            self.assertTrue(evidence["truncated"])


if __name__ == "__main__":
    unittest.main()
