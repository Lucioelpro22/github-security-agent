from github_security_agent.cli import main


def test_cli_json_is_read_only(capsys) -> None:
    assert main(["scan", "--owner", "owner", "--repo", "repo", "--format", "json"]) == 0
    assert '"findings": []' in capsys.readouterr().out


def test_local_cli_outputs_redacted_json(tmp_path, capsys) -> None:
    canary = "github_pat_" + "B" * 40
    (tmp_path / "settings.txt").write_text(
        f"ACCESS_TOKEN={canary}\n",
        encoding="utf-8",
    )

    assert main(["scan-local", str(tmp_path), "--format", "json"]) == 0
    output = capsys.readouterr().out
    assert '"status": "complete"' in output
    assert canary not in output


def test_local_cli_reports_invalid_path_without_echoing_it(capsys) -> None:
    assert main(["scan-local", "/path/that/does/not/exist"]) == 2
    result = capsys.readouterr()
    assert result.out == ""
    assert "Unable to scan" in result.err
