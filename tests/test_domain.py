from github_security_agent.domain import AlertClass, RepositoryTarget, SecurityFinding, Severity


def test_repository_target_full_name() -> None:
    assert RepositoryTarget("owner", "repo").full_name == "owner/repo"


def test_finding_defaults_are_safe() -> None:
    finding = SecurityFinding(AlertClass.DEPENDABOT, "1", "outdated package")
    assert finding.severity is Severity.UNKNOWN
    assert finding.state == "open"
