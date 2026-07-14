# ReadSafe Security Model

This document defines the intended security boundary for ReadSafe. The project is currently pre-alpha, so this is a design contract rather than a claim about an implemented release.

## Security goal

ReadSafe should allow an agent to learn the structure of a sensitive file, and to request narrow supported updates, without receiving the file's existing raw values.

ReadSafe **does read and parse the file locally**. The security goal is output non-disclosure, not zero access.

## Protected output channels

By default, ReadSafe must prevent raw sensitive values from appearing in:

- stdout;
- stderr;
- structured JSON responses;
- generated manifests;
- generated schemas;
- redacted copies;
- validation results;
- dry-run diffs;
- error messages;
- logs emitted by ReadSafe;
- telemetry, because ReadSafe should have no telemetry.

A regression test suite should include canary secrets and assert that none of these channels contain the canary.

## Threats in scope

ReadSafe is intended to reduce accidental disclosure caused by:

- an agent opening an entire `.env` file to change one key;
- CLI errors echoing invalid values;
- dry-run output including unchanged secret-bearing lines;
- schema inference emitting examples, constants, enums, or defaults from real data;
- comments containing copied credentials or internal details;
- credential-bearing URLs being reported verbatim;
- values appearing in deterministic manifests or debugging output;
- a large JSONL file being loaded entirely into memory when streaming is sufficient.

## Threats outside the boundary

ReadSafe does not protect against:

- an agent or human bypassing ReadSafe and reading the file directly;
- malware or another process with permission to read the file;
- compromised operating-system, filesystem, shell, terminal, or CI infrastructure;
- a new secret already included in an agent prompt, shell command, process argument, or tool-call payload;
- exfiltration by a malicious ReadSafe binary or compromised dependency;
- secrets that have already been committed, logged, uploaded, or copied elsewhere;
- access-control failures outside the ReadSafe process.

ReadSafe is not a secret manager, encryption system, sandbox, DLP product, or authorization layer.

## Input handling

### Existing values

Existing values should remain inside the local process and must not be emitted by default.

### New values

Automated updates should accept new values through stdin, an inherited file descriptor, or a future explicit secret-manager integration.

A `--value` argument is unsafe for secrets because command arguments may appear in:

- shell history;
- process listings;
- CI logs;
- terminal recordings;
- agent traces.

If `--value` exists, it should be documented only for explicitly non-sensitive values and should emit a warning unless the user opts out.

ReadSafe cannot make a new value private after the value has already been sent to an agent.

## Comments and descriptions

Comments are untrusted input. They may contain:

- copied tokens;
- example credentials;
- internal URLs;
- customer names;
- operational notes.

Comments must pass through the same classification and redaction pipeline as values. ReadSafe should not automatically expose comments as descriptions.

A safe implementation may:

- omit comments by default;
- expose only comments that pass a conservative classifier;
- return `descriptionRedacted: true` when a comment is withheld.

## Schema inference

Generated schemas can leak data even without a `value` field.

For sensitive input, the default safe schema subset must omit value-derived:

- `enum`;
- `const`;
- `examples`;
- `default`;
- exact string lengths;
- exact numeric minima and maxima;
- exact regular expressions inferred from values;
- exact hashes or fingerprints.

Allowed output may include coarse structural facts such as object keys, broad scalar types, nullability, array/object shape, and explicit user-authored schema constraints.

Inferred schemas must include sampling and confidence metadata. They must never imply completeness when only a subset of records was inspected.

## Fingerprints and lengths

The MVP should not persist hashes, fingerprints, or exact secret lengths.

Hashes of predictable values may be brute-forced, and lengths can disclose provider or token formats. A future equality-check feature should use a keyed construction and should avoid persisting reusable digests in manifests.

## Redacted diffs

A dry run must describe only the requested structural change.

Safe example:

```json
{
  "operation": "set",
  "path": ".env",
  "key": "SUPPORT_EMAIL",
  "changed": true,
  "valueExposed": false
}
```

Unsafe output includes surrounding unchanged lines, old values, new values, partial values, secret lengths, or reversible fingerprints.

## Error handling

Errors must identify the location and class of failure without echoing sensitive content.

Prefer:

```json
{
  "error": {
    "code": "ENV_VALUE_INVALID",
    "path": ".env",
    "key": "API_PORT",
    "reason": "value is not a valid TCP port",
    "valueExposed": false
  }
}
```

Avoid parser errors that embed raw source lines.

## Determinism

Stable output helps agents and CI, but volatile metadata undermines comparison.

By default:

- omit generation timestamps;
- sort keys where the format contract requires it;
- normalize path separators;
- use stable machine-readable error codes;
- separate `schemaVersion` from `toolVersion`.

Optional timestamps may be enabled explicitly and should live in a metadata object excluded from canonical comparison.

## File writes

Dotenv updates should:

- use atomic replacement where supported;
- preserve file permissions;
- preserve comments, ordering, quoting, and newline style where practical;
- avoid following unexpected symbolic links unless explicitly allowed;
- refuse ambiguous duplicate-key operations by default;
- support a redacted dry run;
- validate before replacing the original file.

Temporary files must use restrictive permissions and be removed after failure.

## Sensitivity classification

Classification should fail closed. Signals may include:

- key names such as `TOKEN`, `SECRET`, `PASSWORD`, `PRIVATE_KEY`, `CREDENTIAL`, `DSN`, and `DATABASE_URL`;
- credential-bearing URLs;
- known token and private-key formats;
- explicit repository policy;
- schema annotations;
- suspicious comments.

Classifier confidence should not be interpreted as permission to expose a value. A low-confidence result should increase protection, not reduce it.

## Supply-chain expectations

Because ReadSafe processes sensitive-adjacent files, releases should aim for:

- a small auditable dependency tree;
- no telemetry;
- no post-install network code download;
- locked dependencies;
- vulnerability and license checks;
- signed release artifacts and checksums;
- reproducible builds where practical;
- a documented vulnerability-reporting process.

## Verification requirements

Before a production release, the project should include:

- canary-secret non-disclosure tests across all outputs;
- malformed-file tests;
- parser error redaction tests;
- comment leakage tests;
- schema inference leakage tests;
- symlink and permission tests;
- atomic-write failure tests;
- large-file memory benchmarks;
- fuzzing for format parsers and redaction paths.
