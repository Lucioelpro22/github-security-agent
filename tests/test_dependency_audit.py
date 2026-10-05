import json

from github_security_agent import dependency_audit as audit


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

    report = audit.audit_dependencies(tmp_path)

    assert report.manifests_scanned == 2
    assert {(item.name, item.ecosystem) for item in report.dependencies} == {
        ("left-pad", "npm"),
        ("serde", "crates.io"),
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


def test_symlinked_lockfile_is_not_read(tmp_path):
    external = tmp_path.parent / "outside-requirements.txt"
    external.write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "requirements.txt").symlink_to(external)

    report = audit.audit_dependencies(tmp_path)

    assert report.dependencies == ()
    external.unlink()
