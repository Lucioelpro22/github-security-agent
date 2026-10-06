# GitHub API provider

The GitHub provider is opt-in. The default `scan` and `plan` commands keep using the offline empty provider.

```bash
export GITHUB_TOKEN="<short-lived or fine-grained token>"
github-security-agent scan --owner OWNER --repo REPOSITORY --provider github --format markdown
```

The token is read from the environment and is never accepted as a command-line value. To use a different environment variable name, pass `--token-env NAME`; the variable value is never printed or included in reports.

## Minimum permissions

Create a fine-grained token scoped to only the target repository and grant these repository permissions as read-only:

- Dependabot alerts: read
- Code scanning alerts: read
- Secret scanning alerts: read

The provider requests all three alert classes. If an endpoint is unavailable, inaccessible, or rate-limited, it fails the scan with exit code 2 and does not emit a partial inventory as if it were complete. This also means repositories without a supported alert feature need that feature enabled or a future selective-class option.

Official permission references:

- [Dependabot alerts API](https://docs.github.com/en/rest/dependabot/alerts)
- [Code scanning API](https://docs.github.com/en/rest/code-scanning/code-scanning)
- [Secret scanning API](https://docs.github.com/en/rest/secret-scanning/secret-scanning)

## Data handling and limits

The provider calls only fixed, read-only alert-list endpoints on `api.github.com`. It does not fetch source code, blobs, or secret locations and has no write methods. Secret scanning requests set `hide_secret=true`; normalized reports include only the alert type, never the literal secret.

Alert text is untrusted remote data. Markdown output escapes HTML and Markdown table syntax before rendering. Keep reports within access-controlled storage.

Requests have a 10-second timeout. Each response is limited to 2 MB, each alert class to 10 pages of 100 results, and pagination links must remain on HTTPS `api.github.com` and the expected endpoint. The provider does not retry or convert errors into zero findings. A limit, malformed response, permission failure, or network failure returns a clear incomplete-scan error.

This provider currently targets GitHub.com. Enterprise Server support and a local dashboard remain future work. The dashboard should be designed only after token handling and alert coverage have been validated.
