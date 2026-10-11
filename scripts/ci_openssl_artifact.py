#!/usr/bin/env python3
"""Transfer a CI-built OpenSSL prefix without changing its compiled-in paths."""

import argparse
import hashlib
import json
import platform
from pathlib import Path
import tarfile


def identity(prefix):
    return {
        "schema": 1,
        "system": platform.system(),
        "machine": platform.machine(),
        "prefix": str(prefix),
    }


def transfer(mode, prefix, artifact_dir):
    prefix = Path(prefix)
    artifact_dir = Path(artifact_dir)
    if not prefix.is_absolute() or prefix == Path(prefix.anchor):
        raise ValueError("OpenSSL prefix must be an absolute non-root directory")
    if prefix.is_symlink() or prefix.resolve() != prefix:
        raise ValueError("OpenSSL prefix must not contain symlinks or traversal")
    archive = artifact_dir / "openssl.tar.gz"
    manifest = artifact_dir / "openssl.json"
    if mode == "pack":
        if not prefix.is_dir():
            raise ValueError("OpenSSL prefix is missing")
        if artifact_dir.resolve().is_relative_to(prefix):
            raise ValueError("Artifact directory must be outside the OpenSSL prefix")
        artifact_dir.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive, "w:gz", dereference=False) as bundle:
            bundle.add(prefix, arcname=".")
        metadata = identity(prefix)
        with archive.open("rb") as source:
            metadata["sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
        manifest.write_text(json.dumps(metadata, indent=2) + "\n")
        return

    metadata = json.loads(manifest.read_text())
    for key, expected in identity(prefix).items():
        if metadata.get(key) != expected:
            raise ValueError(f"OpenSSL artifact {key} does not match this job")
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != metadata.get("sha256"):
            raise ValueError("OpenSSL artifact checksum mismatch")
    if prefix.exists() and any(prefix.iterdir()):
        raise ValueError("Refusing to mix an artifact with an existing OpenSSL install")
    # Validate every member before extraction, including links outside the prefix.
    # The data filter also rejects device nodes and absolute/traversal targets.
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            tarfile.data_filter(member, str(prefix))
        prefix.mkdir(parents=True, exist_ok=True)
        bundle.extractall(prefix, filter="data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["pack", "restore"])
    parser.add_argument("--prefix", default="/usr/local/ssl")
    parser.add_argument("--artifacts", default=".ci-artifacts/openssl")
    args = parser.parse_args()
    transfer(args.mode, args.prefix, args.artifacts)


if __name__ == "__main__":
    main()
