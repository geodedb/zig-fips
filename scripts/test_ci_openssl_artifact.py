#!/usr/bin/env python3
"""Exercise real archive handoff and fail-closed restoration."""

import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

from ci_openssl_artifact import transfer


class OpenSSLArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.prefix = self.root / "ssl"
        self.artifacts = self.root / "artifacts"
        (self.prefix / "lib64").mkdir(parents=True)
        (self.prefix / "lib64/libcrypto.so.3").write_bytes(b"shared-library-fixture")
        (self.prefix / "lib64/libcrypto.so").symlink_to("libcrypto.so.3")
        (self.prefix / "bin").mkdir()
        binary = self.prefix / "bin/openssl"
        binary.write_bytes(b"executable-fixture")
        binary.chmod(0o755)
        transfer("pack", self.prefix, self.artifacts)
        shutil.rmtree(self.prefix)

    def restore(self):
        transfer("restore", self.prefix, self.artifacts)

    def change_metadata(self, field, value):
        manifest = self.artifacts / "openssl.json"
        metadata = json.loads(manifest.read_text())
        metadata[field] = value
        manifest.write_text(json.dumps(metadata))

    def test_round_trip_preserves_library_symlink_and_executable(self):
        self.restore()
        self.assertTrue((self.prefix / "lib64/libcrypto.so").is_symlink())
        self.assertEqual(
            (self.prefix / "lib64/libcrypto.so").read_bytes(), b"shared-library-fixture"
        )
        self.assertEqual((self.prefix / "bin/openssl").stat().st_mode & 0o777, 0o755)

    def test_corruption_is_rejected_before_prefix_creation(self):
        archive = self.artifacts / "openssl.tar.gz"
        with archive.open("ab") as output:
            output.write(b"corrupted")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.restore()
        self.assertFalse(self.prefix.exists())

    def test_wrong_platform_architecture_prefix_and_schema_are_rejected(self):
        manifest = self.artifacts / "openssl.json"
        original = manifest.read_text()
        for field in ("system", "machine", "prefix", "schema"):
            with self.subTest(field=field):
                self.change_metadata(field, "different")
                with self.assertRaisesRegex(ValueError, field):
                    self.restore()
                self.assertFalse(self.prefix.exists())
                manifest.write_text(original)

    def test_existing_install_is_not_overwritten(self):
        self.prefix.mkdir()
        marker = self.prefix / "keep"
        marker.write_text("original")
        with self.assertRaisesRegex(ValueError, "existing"):
            self.restore()
        self.assertEqual(marker.read_text(), "original")

    def test_unsafe_archive_is_rejected_before_extracting_any_member(self):
        for kind in ("traversal", "symlink", "device"):
            with self.subTest(kind=kind):
                archive = self.artifacts / "openssl.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    safe = tarfile.TarInfo("safe")
                    safe.size = 4
                    bundle.addfile(safe, io.BytesIO(b"safe"))
                    unsafe = tarfile.TarInfo(
                        "../outside" if kind == "traversal" else kind
                    )
                    if kind == "symlink":
                        unsafe.type = tarfile.SYMTYPE
                        unsafe.linkname = "../../outside"
                    elif kind == "device":
                        unsafe.type = tarfile.CHRTYPE
                    bundle.addfile(unsafe)
                self.change_metadata(
                    "sha256", hashlib.sha256(archive.read_bytes()).hexdigest()
                )
                with self.assertRaises(tarfile.FilterError):
                    self.restore()
                self.assertFalse(self.prefix.exists())
                self.assertFalse((self.root / "outside").exists())

    def test_symlink_prefix_and_root_are_rejected(self):
        self.prefix.symlink_to(self.root, target_is_directory=True)
        for prefix in (self.prefix, Path("/"), Path("relative")):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                transfer("restore", prefix, self.artifacts)


if __name__ == "__main__":
    unittest.main()
