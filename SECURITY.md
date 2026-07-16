# Security Policy

ReadSafe's entire purpose is output non-disclosure: raw values from
inspected files must never appear in stdout, stderr, manifests, schemas,
dry-run output, or error messages. A violation of that property is a
security vulnerability even when no attacker is involved.

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/bnap00/readsafe/security/advisories/new).
Do not open a public issue for a disclosure bug, and do not include real
secrets in a report — reproduce with placeholder canary values instead.

You should receive an acknowledgement within a week. Please allow time for
a fix before public disclosure.

## Scope

In scope:

- any raw value, comment text, or value-derived data (exact lengths,
  hashes, examples, enums, patterns) appearing in any ReadSafe output
  channel;
- parser or classifier failures that echo source content;
- unsafe file handling (symlink following, non-atomic writes, temp files
  with loose permissions or left behind on failure).

Out of scope (documented boundaries, see `docs/security-model.md`):

- an agent or human bypassing ReadSafe and reading a file directly;
- secrets already exposed before ReadSafe ran (in prompts, arguments,
  logs);
- compromised operating system, filesystem, or CI infrastructure.

## Supply chain

ReadSafe has no telemetry and performs no network access at runtime.
Dependencies are kept minimal and locked; the dependency tree is audited
in CI.
