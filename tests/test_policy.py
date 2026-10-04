import pytest

from github_security_agent.policy import validate_repo_name, validate_url


@pytest.mark.parametrize("url", ["http://api.github.com/x", "https://evil.example/x", "https://api.github.com:8443/x", "https://u:p@api.github.com/x"])
def test_url_policy_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_repo_validation():
    assert validate_repo_name("owner/repo") == "owner/repo"
    with pytest.raises(ValueError):
        validate_repo_name("owner/repo/extra")


def test_client_does_not_allow_secrets_in_url():
    with pytest.raises(ValueError):
        validate_url("https://api.github.com/x#token")
