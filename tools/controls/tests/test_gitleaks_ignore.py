"""One OLD gitleaks finding (a JWT-sanitiser test string in crates/contact/src/gmail.rs, commit d25252d, 2026-11-05) is ignored by its exact
FINGERPRINT only, with a reason, so later scans stay meaningful. Not the path, not the rule. History is not rewritten."""
import os
import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
FINGERPRINT = "d25252d59ac09dd360895c77a9e8d3f09adc8b6a:crates/contact/src/gmail.rs:generic-api-key:169"


def gitleaks(cwd, *args):
    return subprocess.run(["gitleaks", "detect", "--no-banner", "--redact", *args], cwd=cwd, capture_output=True, text=True)


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks is not installed")
class GitleaksIgnoreTests(unittest.TestCase):
    def test_the_ignore_file_has_exactly_the_one_fingerprint_and_a_reason(self):
        lines = (ROOT / ".gitleaksignore").read_text().splitlines()
        entries = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        self.assertEqual(entries, [FINGERPRINT])
        comments = [l for l in lines if l.strip().startswith("#")]
        self.assertTrue(any("test string" in c.lower() and "false positive" in c.lower() for c in comments), comments)

    def test_a_full_history_scan_of_this_repository_is_clean(self):
        r = gitleaks(ROOT)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_ignore_is_narrow_the_same_path_and_rule_in_another_commit_is_still_found(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
            run = lambda *a: subprocess.run(["git", *a], cwd=d, env=env, check=True, capture_output=True)
            run("init", "-q")
            shutil.copy(ROOT / ".gitleaksignore", d / ".gitleaksignore")
            f = d / "crates" / "contact" / "src" / "gmail.rs"
            f.parent.mkdir(parents=True)
            f.write_text("// a clean file\n")
            run("add", "-A")
            run("commit", "-q", "-m", "clean")
            self.assertEqual(gitleaks(d).returncode, 0)                                   # nothing to find yet
            f.write_text('// built at run time, never stored as a literal\nlet api_key = "%s";\n' % hashlib.sha256(b"e1 gitleaks narrowness test value").hexdigest())          # deterministic: a random value sometimes falls under the entropy threshold
            run("add", "-A")
            run("commit", "-q", "-m", "a different commit, same path, same rule")
            r = gitleaks(d)
            self.assertEqual(r.returncode, 1, "the fingerprint ignore must not hide a new finding in the same file\n" + r.stdout + r.stderr)

    def test_the_toml_allowlist_was_not_widened(self):
        toml = (ROOT / ".gitleaks.toml").read_text()
        self.assertNotIn("gmail.rs", toml)
        self.assertNotIn("generic-api-key", toml)


if __name__ == "__main__":
    unittest.main()
