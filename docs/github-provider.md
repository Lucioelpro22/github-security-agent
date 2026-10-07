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

Metadata read access is required automatically. No account permissions, organization access, webhook permissions, or write access are needed for these requests.

Failed requests identify the alert class (`dependabot`, `code_scanning`, or `secret_scanning`) without printing the token or raw API response. HTTP 403 alone does not establish whether the token, feature availability, or rate limiting caused the rejection.

Official permission references:

- [Dependabot alerts API](https://docs.github.com/en/rest/dependabot/alerts)
- [Code scanning API](https://docs.github.com/en/rest/code-scanning/code-scanning)
- [Secret scanning API](https://docs.github.com/en/rest/secret-scanning/secret-scanning)

## Data handling and limits

The provider calls only fixed, read-only alert-list endpoints on `api.github.com`. It does not fetch source code, blobs, or secret locations and has no write methods. Secret scanning requests set `hide_secret=true`; normalized reports include only the alert type, never the literal secret.

Alert text is untrusted remote data. Markdown output escapes HTML and Markdown table syntax before rendering. Keep reports within access-controlled storage.

Requests have a 10-second timeout. Each response is limited to 2 MB, each alert class to 10 pages of 100 results, and pagination links must remain on HTTPS `api.github.com` and the expected endpoint. The provider does not retry or convert errors into zero findings. A limit, malformed response, permission failure, or network failure returns a clear incomplete-scan error.

This provider currently targets GitHub.com. Enterprise Server support remains future work. The repository includes a static offline viewer for complete JSON reports; it never receives the API token and makes no network requests.

## Manual authenticated integration test

The `Authenticated GitHub smoke test` workflow runs only when manually dispatched on `main`, targeting this repository. Add the repository Actions secret `SECURITY_AGENT_READ_TOKEN` with a short-lived fine-grained token restricted to `github-security-agent` and the three read-only alert permissions above. Never paste the token into chat or logs. Run the workflow from Actions and revoke the token after testing.

The workflow installs the reviewed agent before making the token available to the scan step. It has only `contents: read`, does not receive the token on pull requests, does not upload reports, and prints only the completion state. A missing secret, denied feature, redirect or incomplete inventory fails the job; do not describe such a run as successful authentication. Authenticated validation completed successfully on 2026-10-07 at commit `ba42fa33b9a4a1adc09a78dd2cb77512984975bb` ([run 37614861333](https://github.com/Lucioelpro22/github-security-agent/actions/runs/37614861333)). All three alert inventories completed; report contents were withheld. This validates that commit and repository configuration, not future code changes or every repository.

All HTTP redirects are blocked for GitHub and OSV requests. This prevents automatic forwarding of authentication headers or dependency-query data. See the [Python urllib documentation](https://docs.python.org/3.13/library/urllib.request.html).

Dependabot pagination uses the API-provided `after` cursor and does not send numbered `page` parameters. Cursor links must retain the fixed HTTPS host, repository endpoint, open-state filter, and page size; unexpected parameters and repeated links fail the scan. Other alert classes keep numbered pagination.
