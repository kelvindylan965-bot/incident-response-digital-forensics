import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "analyze_evidence.py"

class EvidenceIntegrityTests(unittest.TestCase):
    def test_hash_detects_changed_content(self):
        original = b"original evidence\n"
        changed = b"changed evidence\n"
        self.assertNotEqual(
            hashlib.sha256(original).hexdigest(),
            hashlib.sha256(changed).hexdigest()
        )

    def test_analyzer_rejects_modified_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "evidence").mkdir()
            (root / "tools").mkdir()
            (root / "timeline").mkdir()
            (root / "reports").mkdir()

            evidence = root / "evidence" / "authentication.log"
            hash_file = root / "evidence" / "SHA256SUMS"
            evidence.write_text(
                "2026-10-18T08:00:00Z host-lab sshd[1]: "
                "Accepted publickey for analyst from 192.0.2.15 port 52001 ssh2\n"
            )
            hash_file.write_text("0" * 64 + "  authentication.log\n")

            # Run a copy of the analyzer with paths redirected to this test fixture.
            source = SCRIPT.read_text()
            source = source.replace(
                'ROOT = Path(__file__).resolve().parent.parent',
                f'ROOT = Path({str(root)!r})'
            )
            test_script = root / "tools" / "analyze_evidence.py"
            test_script.write_text(source)

            result = subprocess.run(
                [sys.executable, str(test_script)],
                capture_output=True,
                text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("INTEGRITY CHECK FAILED", result.stdout)

if __name__ == "__main__":
    unittest.main()
