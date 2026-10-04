from github_security_agent.cli import main


def test_cli_json_is_read_only(capsys) -> None:
    assert main(["scan", "--owner", "owner", "--repo", "repo", "--format", "json"]) == 0
    assert '"findings": []' in capsys.readouterr().out
