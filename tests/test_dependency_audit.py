import json
import os

import pytest

from github_security_agent import dependency_audit as audit
from github_security_agent.cli import main


def test_inventory_is_local_and_parses_exact_requirements(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nflask>=3.0\n-e .\n", encoding="utf-8"
    )
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: (_ for _ in ()).throw(AssertionError()))

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "complete"
    assert report.advisory_lookup == "not_requested"
    assert [(item.name, item.version, item.ecosystem) for item in report.dependencies] == [
        ("requests", "2.31.0", "PyPI")
    ]


def test_parses_npm_and_toml_lockfiles(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo", "version": "1.0.0"},
                    "node_modules/left-pad": {"version": "1.3.0"},
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.0"\n', encoding="utf-8"
    )
    (tmp_path / "poetry.lock").write_text(
        '[[package]]\nname = "urllib3"\nversion = "2.2.0"\n', encoding="utf-8"
    )

    report = audit.audit_dependencies(tmp_path)

    assert report.manifests_scanned == 3
    assert {(item.name, item.ecosystem) for item in report.dependencies} == {
        ("left-pad", "npm"),
        ("serde", "crates.io"),
        ("urllib3", "PyPI"),
    }


def test_parses_nested_legacy_npm_lockfile(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "parent": {"version": "1.0.0", "dependencies": {"child": {"version": "2.0.0"}}}
                }
            }
        ),
        encoding="utf-8",
    )

    report = audit.audit_dependencies(tmp_path)

    assert {(item.name, item.version) for item in report.dependencies} == {
        ("parent", "1.0.0"),
        ("child", "2.0.0"),
    }


def test_osv_is_explicit_and_advisories_are_attached_to_exact_versions(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(
        audit,
        "_post_osv_batch",
        lambda batch: [[{"id": "GHSA-test", "summary": "Example issue"}]],
    )

    report = audit.audit_dependencies(tmp_path, query_osv=True)

    assert report.status == "complete"
    assert report.advisory_lookup == "complete"
    assert report.advisories[0].advisory_id == "GHSA-test"
    assert report.advisories[0].dependency.version == "2.31.0"
    assert "GHSA-test" in audit.report_markdown(report)


def test_malformed_lockfile_marks_report_incomplete(tmp_path):
    (tmp_path / "package-lock.json").write_text("{broken", encoding="utf-8")

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "incomplete"
    assert report.errors == ("package-lock.json: could not parse lockfile",)


def test_osv_request_uses_only_package_identifiers_and_checks_response(monkeypatch):
    seen = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            assert limit == audit.MAX_RESPONSE_BYTES + 1
            return b'{"results":[{"vulns":[]}]}'

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["payload"] = json.loads(request.data)
        return Response()

    monkeypatch.setattr(audit.urllib.request, "urlopen", fake_urlopen)
    dependency = audit.Dependency("requests", "2.31.0", "PyPI", "requirements.txt")

    assert audit._post_osv_batch([dependency]) == [[]]
    assert seen["url"] == audit.OSV_QUERY_URL
    assert seen["timeout"] == 5
    assert seen["payload"] == {
        "queries": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}]
    }


@pytest.mark.parametrize("body", [b"x" * (audit.MAX_RESPONSE_BYTES + 1), b'{"results":[]}'])
def test_osv_rejects_oversized_or_mismatched_responses(monkeypatch, body):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return body

    monkeypatch.setattr(audit.urllib.request, "urlopen", lambda *args, **kwargs: Response())
    dependency = audit.Dependency("requests", "2.31.0", "PyPI", "requirements.txt")

    with pytest.raises(ValueError):
        audit._post_osv_batch([dependency])


def test_osv_failure_and_lookup_limit_are_reported(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n", encoding="utf-8")
    monkeypatch.setattr(audit, "MAX_BATCH_SIZE", 1)
    monkeypatch.setattr(audit, "MAX_OSV_BATCHES", 1)
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: (_ for _ in ()).throw(OSError()))

    report = audit.audit_dependencies(tmp_path, query_osv=True)

    assert report.status == "incomplete"
    assert report.advisory_lookup == "incomplete"
    assert any("limited to the first 1" in item for item in report.errors)
    assert any("OSV lookup failed" in item for item in report.errors)


def test_size_and_file_count_limits_mark_report_incomplete(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(audit, "MAX_LOCKFILE_BYTES", 1)

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "incomplete"
    assert report.errors == ("requirements.txt: skipped by size limit",)

    monkeypatch.setattr(audit, "MAX_LOCKFILE_BYTES", 2_000_000)
    monkeypatch.setattr(audit, "MAX_LOCKFILES", 0)
    report = audit.audit_dependencies(tmp_path)
    assert report.status == "incomplete"


def test_time_limit_marks_audit_incomplete(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    monkeypatch.setattr(audit, "MAX_SCAN_SECONDS", 0)

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "incomplete"
    assert "scan time limit reached" in report.errors


def test_symlinked_lockfile_is_not_read(tmp_path):
    external = tmp_path.parent / "outside-requirements.txt"
    external.write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "requirements.txt").symlink_to(external)

    report = audit.audit_dependencies(tmp_path)

    assert report.dependencies == ()
    external.unlink()


def test_invalid_root_and_empty_report_outputs(tmp_path):
    with pytest.raises(OSError):
        audit.audit_dependencies(tmp_path / "missing")

    report = audit.audit_dependencies(tmp_path)

    assert "No supported lockfiles" in audit.report_markdown(report)
    assert json.loads(audit.report_json(report))["dependencies"] == []


def test_dependency_cli_outputs_inventory_json(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")

    assert main(["audit-dependencies", str(tmp_path), "--format", "json"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["advisory_lookup"] == "not_requested"
    assert output["dependencies"][0]["name"] == "requests"


def test_dependency_cli_handles_missing_directory_without_echoing_path(tmp_path, capsys):
    missing = tmp_path / "private-path"

    assert main(["audit-dependencies", str(missing)]) == 2

    result = capsys.readouterr()
    assert result.out == ""
    assert "Unable to audit" in result.err
    assert str(missing) not in result.err



@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are unavailable")
def test_fifo_lockfile_is_skipped_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "requirements.txt")

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert report.errors == ("requirements.txt: could not safely parse lockfile",)


def test_dependency_limit_is_applied_during_requirements_parsing(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 5)
    (tmp_path / "requirements.txt").write_text(
        "".join(f"package-{index}==1.0.0\n" for index in range(7)),
        encoding="utf-8",
    )

    report = audit.audit_dependencies(tmp_path)

    assert len(report.dependencies) == 5
    assert report.status == "incomplete"
    assert "dependency count reached configured limit" in report.errors


def test_directory_traversal_error_marks_report_incomplete(tmp_path, monkeypatch):
    def failing_walk(root, *, followlinks=False, onerror=None):
        if onerror is not None:
            onerror(PermissionError("permission denied", filename=str(tmp_path / "restricted")))
        yield str(root), [], []

    monkeypatch.setattr(audit.os, "walk", failing_walk)

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "incomplete"
    assert report.errors == ("restricted: could not enumerate directory",)



def test_lockfile_limit_marks_report_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_LOCKFILES", 1)
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.0"\n', encoding="utf-8"
    )

    report = audit.audit_dependencies(tmp_path)

    assert report.status == "incomplete"
    assert report.manifests_scanned == 1
    assert "lockfile count reached configured limit" in report.errors


def test_osv_skips_secret_like_package_names(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/github_pat_abcd": {"version": "1.2.3"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        audit.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network request was sent")),
    )

    report = audit.audit_dependencies(tmp_path, query_osv=True)

    assert report.status == "incomplete"
    assert report.advisory_lookup == "incomplete"
    assert any("invalid package identifiers" in item for item in report.errors)


def test_osv_request_payload_has_a_byte_limit(monkeypatch):
    monkeypatch.setattr(audit, "MAX_REQUEST_BYTES", 1)
    monkeypatch.setattr(
        audit.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network request was sent")),
    )
    dependency = audit.Dependency("requests", "2.31.0", "PyPI", "requirements.txt")

    with pytest.raises(ValueError, match="request exceeded"):
        audit._post_osv_batch([dependency])
