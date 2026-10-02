import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from cryptography import x509

from certificate_name_policy import Limits, evaluate_file
from certificate_name_policy.cli import main


def test_regular_file_api(make_cert, tmp_path):
    path = tmp_path / "certificate.der"
    path.write_bytes(make_cert([x509.DNSName("example.test")]))
    assert evaluate_file(path, "example.test").status == "PASS"


def test_file_limits_missing_directory_and_nul(tmp_path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * 100)
    assert evaluate_file(path, "example.test", limits=Limits(max_bytes=99)).status == "OPEN"
    assert evaluate_file(tmp_path / "missing", "example.test").status == "OPEN"
    assert evaluate_file(tmp_path, "example.test").status == "OPEN"
    assert evaluate_file("invalid\x00path", "example.test").status == "OPEN"
    assert evaluate_file("", "example.test").status == "OPEN"


def test_symlink_leaf_and_parent_rejected(make_cert, tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    cert = folder / "certificate.der"
    cert.write_bytes(make_cert([x509.DNSName("example.test")]))
    leaf = tmp_path / "linked.der"
    leaf.symlink_to(cert)
    parent = tmp_path / "linked-dir"
    parent.symlink_to(folder, target_is_directory=True)
    assert evaluate_file(leaf, "example.test").status == "OPEN"
    assert evaluate_file(parent / "certificate.der", "example.test").status == "OPEN"


def test_parent_traversal_rejected(make_cert, tmp_path):
    cert = tmp_path / "certificate.der"
    cert.write_bytes(make_cert([x509.DNSName("example.test")]))
    assert (
        evaluate_file(tmp_path / "unused" / ".." / "certificate.der", "example.test").status
        == "OPEN"
    )


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_fifo_no_block_and_device_rejected(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    before = time.monotonic()
    assert evaluate_file(fifo, "example.test").status == "OPEN"
    assert time.monotonic() - before < 1
    assert evaluate_file("/dev/null", "example.test").status == "OPEN"


def test_changed_input_is_open(make_cert, tmp_path, monkeypatch):
    cert = tmp_path / "certificate.der"
    cert.write_bytes(make_cert([x509.DNSName("example.test")]))
    original = os.fstat
    calls = []

    def changing_stat(fd):
        value = original(fd)
        calls.append(fd)
        return SimpleNamespace(
            st_mode=value.st_mode,
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + len(calls),
            st_ctime_ns=value.st_ctime_ns,
        )

    monkeypatch.setattr(os, "fstat", changing_stat)
    result = evaluate_file(cert, "example.test")
    assert result.status == "OPEN"
    assert result.reason == "input_changed_while_reading"


def test_file_growth_read_limit(tmp_path, monkeypatch):
    cert = tmp_path / "certificate.der"
    cert.write_bytes(b"short")
    original_read = os.read

    def growing_read(fd, length):
        if os.fstat(fd).st_size == 5:
            return b"x" * length
        return original_read(fd, length)

    monkeypatch.setattr(os, "read", growing_read)
    result = evaluate_file(cert, "example.test", limits=Limits(max_bytes=16))
    assert result.status == "OPEN"
    assert result.reason == "input_too_large"


def test_unsupported_safe_open_platform_is_open(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "O_NOFOLLOW")
    result = evaluate_file(tmp_path / "anything.der", "example.test")
    assert result.status == "OPEN"
    assert result.reason == "safe_file_open_unsupported_platform"


@pytest.mark.parametrize(
    ("reference", "exit_code", "status"),
    [("example.test", 0, "PASS"), ("other.test", 1, "FAIL"), ("bad\x00.test", 2, "OPEN")],
)
def test_cli_json_exit_contract(make_cert, tmp_path, capsys, reference, exit_code, status):
    cert = tmp_path / "certificate.der"
    cert.write_bytes(make_cert([x509.DNSName("example.test")]))
    assert main([str(cert), reference]) == exit_code
    out = capsys.readouterr()
    report = json.loads(out.out)
    assert report["status"] == status
    assert report["trust_status"] == "OPEN"
    assert out.err == ""


@pytest.mark.parametrize(
    "argv",
    [[], ["one"], ["one", "two", "--kind", "srv"], ["one", "two", "--remote", "private-secret"]],
)
def test_cli_usage_errors_are_json_open(argv, capsys):
    assert main(argv) == 2
    out = capsys.readouterr()
    assert json.loads(out.out)["status"] == "OPEN"
    assert "private-secret" not in out.out + out.err


def test_module_cli_subprocess(make_cert, tmp_path):
    cert = tmp_path / "certificate.der"
    cert.write_bytes(make_cert([x509.DNSName("example.test")]))
    result = subprocess.run(
        [sys.executable, "-m", "certificate_name_policy", str(cert), "example.test"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["name_status"] == "NAME_MATCH"
    assert result.stderr == ""
