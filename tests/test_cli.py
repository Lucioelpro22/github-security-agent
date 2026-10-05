import json

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


def test_github_provider_requires_token_from_environment(monkeypatch, capsys) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    result = main(["scan", "--owner", "owner", "--repo", "repo", "--provider", "github"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert "GITHUB_TOKEN is not set" in captured.err


def test_github_provider_uses_environment_token_and_keeps_default_offline(
    monkeypatch, capsys
) -> None:
    token = "environment-token-test-only"
    monkeypatch.setenv("GITHUB_TOKEN", token)
    requests = []

    class Response:
        def __init__(self):
            self.headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return b"[]"

    def fake_urlopen(request, timeout):
        requests.append(request)
        return Response()

    monkeypatch.setattr(
        "github_security_agent.github_provider.urllib.request.urlopen", fake_urlopen
    )

    result = main(
        ["scan", "--owner", "owner", "--repo", "repo", "--provider", "github", "--format", "json"]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert len(requests) == 3
    assert all(request.get_method() == "GET" for request in requests)
    assert all(request.get_header("Authorization") == f"Bearer {token}" for request in requests)
    assert token not in captured.out
    assert json.loads(captured.out)["findings"] == []
