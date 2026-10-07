from github_security_agent import repository_scan
import json

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
        "on:\n  pull_request_target:\n"
        "  steps:\n    - uses: actions/checkout@v4\n"
        "    - uses: actions/setup-python@0123456789abcdef0123456789abcdef01234567\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)
    rules = [finding.rule_id for finding in report.findings]
    assert report.status == "complete"
    assert rules == [
        "workflow.permissions_write_all",
        "workflow.pull_request_target",
        "workflow.action_not_sha_pinned",
    ]


def test_redacts_detected_secrets_from_all_reports(tmp_path):
    canary = "github_pat_" + "A" * 40
    (tmp_path / "settings.txt").write_text(f"ACCESS_TOKEN={canary}\n", encoding="utf-8")

    report = scan_repository(tmp_path)
    serialized = report_json(report)
    markdown = report_markdown(report)
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "secret.github_token"
    assert canary not in serialized
    assert canary not in markdown
    assert "redacted" in markdown.lower() or "potential credential" in markdown.lower()
    assert json.loads(serialized)["findings"][0]["line"] == 1
    assert json.loads(serialized)["schema_version"] == 1
    assert json.loads(serialized)["report_type"] == "local_scan"


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

    report = scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert report.files_skipped == 2
    assert report.findings == ()


def test_plain_examples_do_not_trigger_generic_secret_rule(tmp_path):
    (tmp_path / "config.env.example").write_text(
        "API_KEY=your_token_here\nPASSWORD=changeme\n", encoding="utf-8"
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
    (tmp_path / "many.txt").write_text(f"{token}\n{token}\n", encoding="utf-8")

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


def test_detects_untrusted_values_interpolated_in_workflow_run(tmp_path):
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "steps:\n"
        '  - run: echo "${{ github.event.pull_request.title }}"\n'
        "  - run: |\n"
        "      printf '%s' \"${{ github.event.issue.body }}\"\n"
        "  - env:\n"
        "      PR_TITLE: ${{ github.event.pull_request.title }}\n"
        '    run: echo "$PR_TITLE"\n',
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)
    matches = [
        finding
        for finding in report.findings
        if finding.rule_id == "workflow.untrusted_event_interpolation"
    ]
    assert [finding.line for finding in matches] == [2, 4]


def test_detects_explicitly_privileged_container_settings(tmp_path):
    manifest = tmp_path / "k8s/deployment.yaml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        "securityContext:\n  privileged: true\n  allowPrivilegeEscalation: true\n  runAsUser: 0\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)
    assert [finding.rule_id for finding in report.findings] == [
        "container.privileged_mode",
        "container.privilege_escalation",
        "container.run_as_root",
    ]


def test_detects_environment_files_but_exempts_examples(tmp_path):
    (tmp_path / ".env").write_text("APP_MODE=production\n", encoding="utf-8")
    (tmp_path / ".env.example").write_text("APP_MODE=development\n", encoding="utf-8")
    (tmp_path / ".env.template").write_text("APP_MODE=development\n", encoding="utf-8")

    report = scan_repository(tmp_path)
    assert [finding.rule_id for finding in report.findings] == ["config.environment_file_present"]
    assert report.findings[0].file == ".env"
    assert report.findings[0].confidence == "low"


def test_detects_explicit_root_user_in_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER root\n", encoding="utf-8")

    report = scan_repository(tmp_path)
    assert [finding.rule_id for finding in report.findings] == ["container.dockerfile_root_user"]


def test_detects_privileged_settings_in_json_container_config(tmp_path):
    config = tmp_path / "compose.json"
    config.write_text('{"privileged": true, "runAsUser": 0}', encoding="utf-8")

    report = scan_repository(tmp_path)
    assert [finding.rule_id for finding in report.findings] == [
        "container.privileged_mode",
        "container.run_as_root",
    ]


def test_growth_after_descriptor_stat_is_bounded(tmp_path, monkeypatch):
    import os

    from github_security_agent import file_reader

    target = tmp_path / "growing.txt"
    target.write_bytes(b"safe")
    original = os.fstat

    def grow_after_stat(fd):
        metadata = original(fd)
        target.write_bytes(b"x" * 101)
        return metadata

    monkeypatch.setattr(repository_scan, "MAX_FILE_BYTES", 100)
    monkeypatch.setattr(file_reader.os, "fstat", grow_after_stat)
    report = repository_scan.scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert report.files_scanned == 0
    assert report.files_skipped == 1


def test_actual_total_budget_is_enforced(tmp_path, monkeypatch):
    (tmp_path / "a.txt").write_bytes(b"a" * 4)
    (tmp_path / "b.txt").write_bytes(b"b" * 4)
    monkeypatch.setattr(repository_scan, "MAX_TOTAL_BYTES", 7)
    report = repository_scan.scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert report.files_scanned == 1
    assert report.files_skipped == 1


def test_unsupported_platform_marks_empty_scan_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(repository_scan.os, "supports_dir_fd", set())
    assert repository_scan.scan_repository(tmp_path).status == "incomplete"


def test_directory_enumeration_error_marks_report_incomplete(tmp_path, monkeypatch):
    def failing_walk(base, *, topdown, followlinks, onerror):
        onerror(PermissionError("private traversal error"))
        return iter(())

    monkeypatch.setattr("github_security_agent.repository_scan.os.walk", failing_walk)
    report = scan_repository(tmp_path)
    assert report.status == "incomplete"
    assert report.files_scanned == 0
