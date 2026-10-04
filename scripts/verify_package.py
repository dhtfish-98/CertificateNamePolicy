"""Validate built wheel metadata, licenses, RECORD hashes, and paired sdist."""

import argparse
import base64
import csv
import hashlib
import io
import json
import tarfile
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path


def require(condition, description):
    if not condition:
        raise ValueError(description)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("sdist", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    with zipfile.ZipFile(args.wheel) as wheel:
        names = wheel.namelist()
        require(
            not any(n.startswith("/") or ".." in n.split("/") for n in names), "unsafe wheel path"
        )
        require(
            not any(n.startswith("tests/") or "service_identity/" in n for n in names),
            "oracle in wheel",
        )
        metadata_name = next(n for n in names if n.endswith(".dist-info/METADATA"))
        metadata = Parser().parsestr(wheel.read(metadata_name).decode())
        require(metadata["Name"] == "certificate-name-policy", "wrong name")
        require(metadata["Version"] == version, "wrong version")
        require(metadata["Requires-Python"] == ">=3.11", "wrong Python range")
        require(metadata["License-Expression"] == "MIT", "missing license expression")
        requires = metadata.get_all("Requires-Dist")
        require(
            "cryptography==47.0.0" in requires and "idna==3.20" in requires, "unfixed dependencies"
        )
        for filename in ("项目文档/LICENSE", "项目文档/THIRD_PARTY_LICENSES/service-identity-MIT.txt"):
            packaged = next(n for n in names if n.endswith("/licenses/" + filename))
            require(
                wheel.read(packaged) == (root / filename).read_bytes(), "license content changed"
            )
        entry = next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
        require(
            "certificate-name-policy = certificate_name_policy.cli:main"
            in wheel.read(entry).decode(),
            "missing CLI",
        )
        record = next(n for n in names if n.endswith(".dist-info/RECORD"))
        count = 0
        for name, digest, length in csv.reader(io.StringIO(wheel.read(record).decode())):
            if name == record:
                require(not digest and not length, "invalid RECORD self entry")
                continue
            content = wheel.read(name)
            expected = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(content).digest()
            ).decode().rstrip("=")
            require(digest == expected and int(length) == len(content), "RECORD mismatch")
            count += 1
        require(count == len(names) - 1, "unrecorded wheel contents")
    with tarfile.open(args.sdist, "r:gz") as archive:
        members = archive.getmembers()
        require(
            not any(m.name.startswith("/") or ".." in m.name.split("/") for m in members),
            "unsafe sdist path",
        )
        for filename in ("项目文档/LICENSE", "项目文档/THIRD_PARTY_LICENSES/service-identity-MIT.txt"):
            member = next(m for m in members if m.name.endswith("/" + filename))
            require(
                archive.extractfile(member).read() == (root / filename).read_bytes(),
                "sdist license mismatch",
            )
        required = ("ORIGIN.md", "DEFENSIVE_SCOPE.md", "项目文档/SOURCE_AUDIT.json", "VALIDATION.md")
        require(
            all(any(m.name.endswith("/" + filename) for m in members) for filename in required),
            "source documentation missing",
        )
    print(
        json.dumps(
            {
                "status": "PASS",
                "wheel_name": args.wheel.name,
                "sdist_name": args.sdist.name,
                "wheel_sha256": hashlib.sha256(args.wheel.read_bytes()).hexdigest(),
                "sdist_sha256": hashlib.sha256(args.sdist.read_bytes()).hexdigest(),
                "record_files_checked": count,
                "metadata": "PASS",
                "licenses": "PASS",
                "oracle_excluded": "PASS",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
