# Threat model

Assets include GitHub tokens, repository metadata, security findings, and generated reports. Main threats are credential leakage, over-privileged automation, untrusted repository content, denial of service, and false assurance from incomplete data.

Mitigations: least-privilege permissions, read-only collection, bounded inputs, redacted output, deterministic reports, offline fixtures, human approval for future writes, and explicit unknown/unavailable states.
