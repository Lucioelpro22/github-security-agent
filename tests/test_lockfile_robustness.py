"""Adversarial lock inputs must not establish a complete public inventory."""

import pytest

from github_security_agent import dependency_audit as audit


def ruby_lock(specs, references):
    return (
        "GEM\n  remote: https://rubygems.org/\n  specs:\n"
        + specs
        + "\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n"
        + references
        + "\nBUNDLED WITH\n  2.5.23\n"
    )


def write_ruby_lock(tmp_path, body):
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\n', encoding="utf-8")
    (tmp_path / "Gemfile.lock").write_text(body, encoding="utf-8")


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029"])
def test_ruby_unicode_line_separators_cannot_authorize_osv(tmp_path, monkeypatch, separator):
    body = ruby_lock("    rack (3.1.0)\n", "  rack\n")
    write_ruby_lock(tmp_path, body.replace("\n", separator))
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("malformed lock queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert all(d.source_kind == "unknown" for d in report.dependencies)


@pytest.mark.parametrize("excess", [False, True])
def test_ruby_reference_budget_counts_direct_and_transitive_edges(tmp_path, monkeypatch, excess):
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 12)
    names = [f"gem{i}" for i in range(12)]
    # Nine full dependency lists plus twelve roots consume exactly 120 references.
    specs = ""
    for index, name in enumerate(names):
        specs += f"    {name} (1.0.0)\n"
        if index < 9:
            specs += "".join(f"      {dependency}\n" for dependency in names)
        elif index == 9 and excess:
            specs += "      gem0\n"
    write_ruby_lock(tmp_path, ruby_lock(specs, "".join(f"  {name}\n" for name in names)))
    sent = []
    monkeypatch.setattr(
        audit, "_post_osv_batch", lambda batch: sent.extend(batch) or [[] for _ in batch]
    )
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    if excess:
        assert report.dependencies == ()
        assert report.status == "incomplete"
        assert not sent
        assert all(d.source_kind == "unknown" for d in report.dependencies)
    else:
        assert len(report.dependencies) == 12
        assert report.status == "complete"
        assert len(sent) == 12


def test_ruby_excess_direct_references_stay_incomplete_and_offline(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 1)
    write_ruby_lock(tmp_path, ruby_lock("    rack (3.1.0)\n", "  rack\n" * 11))
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("excess roots queried"))
    report = audit.audit_dependencies(tmp_path, query_osv=True)
    assert report.status == "incomplete"
    assert report.dependencies == ()
    assert all(d.source_kind == "unknown" for d in report.dependencies)


@pytest.mark.parametrize("excess", [False, True])
def test_ruby_checksums_share_the_reference_budget(tmp_path, monkeypatch, excess):
    monkeypatch.setattr(audit, "MAX_DEPENDENCIES", 12)
    names = [f"gem{i}" for i in range(12)]
    specs = ""
    for index, name in enumerate(names):
        specs += f"    {name} (1.0.0)\n"
        if index < 9:
            dependencies = names[:-1] if index == 0 else names
            specs += "".join(f"      {dependency}\n" for dependency in dependencies)
    body = ruby_lock(specs, "".join(f"  {name}\n" for name in names))
    body += "\nCHECKSUMS\n  gem0 (1.0.0)\n"
    if excess:
        body += "  gem1 (1.0.0)\n"
    write_ruby_lock(tmp_path, body)
    monkeypatch.setattr(audit, "_post_osv_batch", lambda _: pytest.fail("offline audit queried"))
    report = audit.audit_dependencies(tmp_path)
    assert report.status == ("incomplete" if excess else "complete")
    assert len(report.dependencies) == (0 if excess else 12)
