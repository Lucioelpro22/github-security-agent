from github_security_agent.repository_scan import (
    report_json,
    report_markdown,
    scan_repository,
)


def test_detects_workflow_risks_and_orders_findings(tmp_path):
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "permissions: write-all\n"
        "on:\n"
        "  pull_request_target:\n"
        "  steps:\n"
        "    - uses: actions/checkout@v4\n"
        "    - uses: actions/setup-python@0123456789abcdef0123456789abcdef01234567\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)
    assert report.status == "complete"
    assert [finding.rule_id for finding in report.findings] == [
        "workflow.permissions_write_all",
        "workflow.pull_request_target",
        "workflow.action_not_sha_pinned",
    ]


def test_redacts_detected_secrets_from_all_reports(tmp_path):
    canary = "github_pat_" + "A" * 40
    (tmp_path / "settings.txt").write_text(
        f"ACCESS_TOKEN={canary}\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)
    serialized = report_json(report)
    markdown = report_markdown(report)
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "secret.github_token"
    assert canary not in serialized
    assert canary not in markdown
    assert "potential credential" in markdown.lower()
    assert '"line": 1' in serialized


def test_skips_symlinks_and_does_not_scan_outside_root(tmp_path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_text("TOKEN=" + "s" * 32, encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked.txt").symlink_to(outside)

    report = scan_repository(repo)
    assert report.findings == ()
    assert report.files_scanned == 0
    outside.unlink()


def test_oversized_and_invalid_utf8_files_make_scan_incomplete(tmp_path, monkeypatch):
    import github_security_agent.repository_scan as repository_scan

    monkeypatch.setattr(repository_scan, "MAX_FILE_BYTES", 4)
    (tmp_path / "large.txt").write_text("12345", encoding="utf-8")
    (tmp_path / "invalid.txt").write_bytes(b"\xff\xfe")

    report = repository_scan.scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert report.files_skipped == 2
    assert report.findings == ()


def test_plain_examples_do_not_trigger_generic_secret_rule(tmp_path):
    (tmp_path / "config.env.example").write_text(
        "API_KEY=your_token_here\nPASSWORD=changeme\n",
        encoding="utf-8",
    )
    assert scan_repository(tmp_path).findings == ()


def test_json_report_is_deterministic(tmp_path):
    (tmp_path / "z.txt").write_text("TOKEN=" + "z" * 32, encoding="utf-8")
    (tmp_path / "a.txt").write_text("TOKEN=" + "a" * 32, encoding="utf-8")
    report = scan_repository(tmp_path)

    assert report_json(report) == report_json(report)
    assert [finding.file for finding in report.findings] == ["a.txt", "z.txt"]



def test_finding_limit_marks_report_incomplete(tmp_path, monkeypatch):
    import github_security_agent.repository_scan as repository_scan

    monkeypatch.setattr(repository_scan, "MAX_FINDINGS", 1)
    token = "github_pat_" + "C" * 40
    (tmp_path / "many.txt").write_text(f"{token}\\n{token}\\n", encoding="utf-8")

    report = repository_scan.scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert len(report.findings) == 1


def test_time_limit_marks_report_incomplete(tmp_path, monkeypatch):
    import github_security_agent.repository_scan as repository_scan

    monkeypatch.setattr(repository_scan, "MAX_SCAN_SECONDS", 30)
    clock = iter((0.0, 0.0, 30.0))
    monkeypatch.setattr(repository_scan.time, "monotonic", lambda: next(clock))
    (tmp_path / "input.txt").write_text("safe", encoding="utf-8")

    report = repository_scan.scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert report.files_scanned == 0
