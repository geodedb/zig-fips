# SPDX-License-Identifier: Apache-2.0
"""Exercise the macOS wrapper without network, Homebrew, or a native runner."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("ci-macos.sh")
BASH = shutil.which("bash")


class MacOSWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls"
        self.env = {
            "PATH": str(self.bin),
            "HOME": str(self.root),
            "CALL_LOG": str(self.log),
            "OPENSSL_VERSION": "3.6.3",
        }
        for name in ("gpg", "wget", "perl", "curl", "make", "cc", "zig"):
            self.stub(name)
        self.stub("brew", status=73)
        for name in ("mkdir", "chmod", "bash"):
            (self.bin / name).symlink_to(shutil.which(name))
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "verify-fips-provider.sh").write_text(
            'printf "verify\\n" >> "$CALL_LOG"\n', encoding="utf-8"
        )

    def stub(self, name, status=0):
        script = self.bin / name
        script.write_text(
            f"#!{BASH}\n"
            f"printf '%s' '{name}' >> \"$CALL_LOG\"\n"
            'printf ":<%s>" "$@" >> "$CALL_LOG"\n'
            'printf "|gpg=%s|version=%s\\n" "${REQUIRE_GPG:-}" '
            '"${OPENSSL_VERSION:-}" >> "$CALL_LOG"\n'
            f"exit {status}\n",
            encoding="utf-8",
        )
        script.chmod(0o755)

    def run_wrapper(self, *args):
        return subprocess.run(
            [BASH, str(SCRIPT), *args],
            cwd=self.root,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

    def calls(self):
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_preinstalled_tools_do_not_mutate_homebrew(self):
        result = self.run_wrapper(
            "test-unit", "-Doptimize=ReleaseSafe", "arg with space"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertNotIn("brew:", calls)
        self.assertIn("gpg:<--batch>:<--import>", calls)
        self.assertIn("make:<deps>|gpg=1|version=3.6.3", calls)
        self.assertIn("verify\n", calls)
        self.assertIn(
            "zig:<build>:<test-unit>:<-Doptimize=ReleaseSafe>:<arg with space>",
            calls,
        )
        self.assertIn(f":<-Dopenssl_path={self.root}/.ci-tools/openssl>", calls)

    def test_missing_tools_fail_before_download_or_install(self):
        for name in ("gpg", "wget", "perl", "curl", "make", "cc", "zig"):
            with self.subTest(tool=name):
                (self.bin / name).unlink()
                result = self.run_wrapper()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"missing required tool: {name}", result.stderr)
                self.assertEqual(self.calls(), "")
                self.stub(name)

    def test_missing_pin_fails_before_external_commands(self):
        del self.env["OPENSSL_VERSION"]
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CI must pin OpenSSL", result.stderr)
        self.assertEqual(self.calls(), "")

    def test_dependency_failure_stops_before_verify_or_build(self):
        self.stub("make", status=42)
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertNotIn("verify\n", self.calls())
        self.assertNotIn("zig:", self.calls())


if __name__ == "__main__":
    unittest.main()
