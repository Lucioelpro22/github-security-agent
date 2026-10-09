# Lockfile robustness validation — 2026-10-09

Scope: Ruby, NuGet and Gradle parsers at the local scanner boundary, based on
v0.3.4 (`9ba3fb02ac270cc3a470568d516393ecbf51a1cf`). Synthetic inputs are read
as data; no repository code, package manager or live OSV request is executed.
OSV tests use a mocked transport, including an explicit opt-in Ruby test.

## Reproduced and corrected

- Ruby accepted U+0085, U+2028 and U+2029 as line delimiters through Python's
  `splitlines()`. Otherwise valid malformed input could produce a complete
  public registry inventory and authorize mocked opt-in OSV calls. Ruby now
  rejects those characters and returns an incomplete inventory.
- Gradle likewise accepted U+2028/U+2029 between records. It now rejects all
  three Unicode separators and splits records at physical LF boundaries.
- Ruby accumulated transitive references, direct references and checksum
  identities without an independent reference budget. Their combined budget
  is now `MAX_DEPENDENCIES * 10` (50,000 by default). An excess discards the
  inventory for that lockfile, marks the report incomplete, and prevents its
  packages from authorizing OSV queries. Other lockfiles can still be scanned.

## Boundary checks

Regression tests cover exact and excess reference budgets, including Ruby
checksum accounting, Gradle configuration edges and NuGet Project graph
references. The reduced budgets in tests make both sides of each boundary
reproducible with small valid graphs. A separate NuGet test uses 5,001 actual
package entries and retains only 5,000 while reporting incompleteness.
Deeply nested NuGet JSON also returns an incomplete report without echoing
the input. Existing tests cover missing references and malformed metadata.

No NuGet production defect was reproduced. The reference limit supplements
existing byte and package limits; this is bounded-input validation, not a
proof of memory usage, installed dependency graphs or absence of vulnerabilities.

Local verification: 432 Python tests passed, coverage 88.73% (required 85%),
Ruff lint, formatting of changed Python files and mypy passed. An independent
subagent reviewed the production diff and regression tests with no blockers.
