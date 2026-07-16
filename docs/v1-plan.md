# ReadSafe v1 Plan

This document turns the [vision](vision.md), [security model](security-model.md), and [CLI contract](cli-contract.md) into an ordered execution plan for the first production release. Those documents define *what* v1 must be; this one defines *in what order it gets built*, what each milestone must prove before the next one starts, and what is explicitly deferred.

## Status

| Milestone | State |
| --- | --- |
| M0 scaffolding + contract freeze | Done — Cargo workspace, CI (fmt/clippy/test on Linux/macOS/Windows, cargo-audit), canary fixtures and harness, contract amendments recorded in `docs/cli-contract.md`. |
| M1 lossless dotenv model | Done — byte-for-byte round-trip parser with typed malformed/duplicate handling (`crates/readsafe-core/src/dotenv.rs`). |
| M2 classification + redaction | Done — fail-closed classifier, `&'static str` error reasons, comments withheld with `descriptionRedacted`. |
| M3 `inspect` for dotenv | Done — canonical 0.1 manifest, deterministic output, `.env.example`-based `required`. |
| M4 narrow update engine | Done — set/remove/rename/test, dry runs, atomic writes, symlink policy, exit codes frozen. Value input supports stdin and `--value-fd` (inherited descriptor, Unix). The hidden interactive prompt is dropped from v1 scope: it needs a terminal dependency and agents never use it; stdin/fd cover the agent and parent-process cases. |
| M5 hardening gate | Mostly done — canary non-disclosure suite across stdout/stderr/manifests/schemas, panic-hook redaction, and `cargo-fuzz` targets (dotenv round-trip + safe-schema subset) with a scheduled CI job are all in. Remaining: the exit criterion's one week of scheduled fuzzing with no leak-class findings — the daily cron is now enabled in `fuzz.yml` (1800s/target); the clock starts when this lands on `main`. |
| M6 JSON/JSONL inference | Done as experimental — safe schema subset with denylist test, sampling semantics, `x-readsafe` metadata. |
| M7 validate + skill packaging | Done — `validate --manifest` drift detection, `validate <file> --schema` structural conformance, the distributable `packages/forcing-skill/` with CI-verified examples, and the flagship end-to-end agent-workflow transcript test are all in. |
| M8 release engineering | In progress — license decided (MIT), signing decided (Sigstore, keyless via CI OIDC), and tag-driven `release.yml` added (5-target build, SHA256SUMS, Sigstore keyless signing, audit snapshot, `-rc` prereleases). Remaining: first tagged release, `cargo publish`, and the npm wrapper. |

## Definition of done for v1

v1 is a signed, installable `readsafe` binary that supports the agent-safe dotenv workflow end to end:

- `readsafe inspect` for dotenv files, emitting the `schemaVersion 0.1` manifest;
- `readsafe env set | remove | rename | test` with stdin value input, redacted dry runs, and atomic writes;
- safe JSON/JSONL structure inference (`readsafe inspect`, `readsafe infer`) behind an explicit experimental marker;
- the canary-secret non-disclosure test suite passing across every output channel listed in the security model;
- frozen exit codes and a frozen `0.1` output schema;
- signed release artifacts with checksums and documented installation.

Anything not on that list ships after v1 or not at all (see [Deferred](#deferred-beyond-v1)).

## Scope decisions

| Area | v1 decision |
| --- | --- |
| Dotenv inspect + narrow updates | In. This is the wedge. |
| JSON/JSONL structure inference | In, but marked experimental in output (`"experimental": true` on the file entry) and documentation. |
| `readsafe validate` | In, manifest mode and explicit-schema mode as specified in the CLI contract. |
| `readsafe redact` | Deferred. Highest leak risk relative to its value; ships only after the classifier has real-world mileage. |
| Generic JSON *editing* | Out (README non-goal). |
| `--value` argument | Not implemented in v1. Stdin, inherited file descriptor, and hidden interactive prompt are the only value inputs. Revisit only with the warning behavior the security model requires. |
| Secret-manager integrations | Out. |
| npm wrapper, Homebrew, container image | After the binary interface stabilizes; npm wrapper may land in the v1 release window, the rest follow. |

## Milestones

Each milestone has an exit criterion. A milestone is not done until its exit criterion is demonstrated by CI, not by hand.

### M0 — Scaffolding and contract freeze

Everything downstream depends on the contracts being stable and the leak-detection harness existing *before* any parser is written.

Deliverables:

- Cargo workspace matching the planned repository shape: `crates/readsafe` (CLI) and `crates/readsafe-core` (parsing, classification, redaction, update engine — no I/O with the terminal).
- CI on Linux and macOS: build, test, `cargo clippy -D warnings`, `cargo fmt --check`, `cargo audit`, `cargo deny` (licenses + advisories). Windows CI added in M4 alongside atomic-write work.
- Fixture corpus: dotenv files covering comments, quoting styles, export prefixes, multiline values, CRLF/LF, duplicate keys, empty values, BOM, and non-UTF-8 bytes; each fixture embeds one or more **canary strings** (unique, grep-able tokens standing in for secrets).
- Canary harness: a test utility that runs any CLI invocation and asserts the canary appears in none of stdout, stderr, exit-code messages, created files, or temp-file leftovers. All later tests are written against this harness.
- Freeze pass over `docs/cli-contract.md` and `docs/security-model.md`: resolve open wording, freeze the exit-code table and the `0.1` manifest field set. Contract changes after M0 require a documented amendment, not a silent edit.

Exit criterion: CI is green on a repo that builds an empty `readsafe --version`, and the canary harness fails a deliberately leaky test binary.

### M1 — Lossless dotenv model

Deliverables:

- A lossless dotenv parser in `readsafe-core`: parses to a document model that round-trips byte-for-byte (ordering, comments, whitespace, quoting, newline style, trailing newline).
- Explicit representation of anomalies: duplicate keys, malformed lines, unclosed quotes — parsed into typed nodes, never silently dropped and never echoed in errors.
- Property test: for the whole fixture corpus and for fuzz-generated inputs, `render(parse(x)) == x`.

Exit criterion: round-trip property test and malformed-input tests pass; parser errors verified canary-clean by the M0 harness.

### M2 — Classification and redaction pipeline

Deliverables:

- Sensitivity classifier over key names, value shapes (known token formats, credential-bearing URLs, private-key blocks), and comments, per the security-model signal list. Output is a classification plus confidence; **low confidence maps to more protection, never less**.
- Redaction layer that every outbound string passes through: manifest fields, validation reasons, error messages, and sanitized third-party error strings. No code path constructs user-visible text from raw file content directly; the type system should make this hard (e.g. a `Redacted`/`Safe` string newtype required at the output boundary).
- Comments withheld by default; `descriptionRedacted: true` marker when a comment exists but is not exposed.
- Table-driven classifier tests including deliberately adversarial cases (secret-looking values under innocent key names, secrets in comments).

Exit criterion: classifier test table passes; a mutation-style test that force-feeds canaries through every public `readsafe-core` output type shows zero leaks.

### M3 — `readsafe inspect` for dotenv

Deliverables:

- `readsafe inspect <path>... --json` and `--out`, emitting the canonical manifest: `schemaVersion`, `toolVersion`, per-file `kind`, per-variable `name`, `type`, `required`, `sensitive`, `source`, `confidence`, `valueExposed: false`.
- Human-readable default output sharing the exact same redaction path as JSON output (one emitter, two renderers).
- Determinism guarantees: no timestamps by default, stable ordering, repository-relative forward-slash paths, byte-identical output for identical input across runs and platforms.
- Golden-file tests for the manifest; determinism test runs inspect twice and diffs.

Exit criterion: golden manifests reviewed and committed; determinism and canary tests pass in CI on both platforms.

### M4 — Narrow update engine

Deliverables:

- `readsafe env set` with `--value-from-stdin` and an inherited-file-descriptor input (`--value-fd`); `env remove`, `env rename`, `env test` with the initial validator set (`email`, `url`, `port`, `hostname`, `uuid`, `semver`, `int`, `bool`, `enum(...)`, `regex(...)`). (A hidden interactive prompt was considered and dropped from v1 scope — it needs a terminal dependency and agents never use it.)
- Operation-level `--dry-run` emitting exactly the dry-run contract shape — no diff context, no old/new values, no lengths.
- Atomic writes: write to a same-directory temp file with restrictive permissions, validate, rename over the original, preserve original permissions; temp file removed on any failure path. Symlink targets refused unless explicitly allowed. Duplicate-key operations refused with exit code 6.
- Frozen exit codes (0–6 per the CLI contract) enforced by integration tests.
- Windows CI added; atomic-write semantics verified per platform.
- Fault-injection tests: kill/fail between temp-file write and rename; assert original file intact and no temp residue.

Exit criterion: full dotenv workflow (inspect → dry run → set/remove/rename/test) passes integration tests on Linux, macOS, and Windows, all canary-clean.

### M5 — Hardening gate

This milestone maps one-to-one onto the security model's verification requirements and is the gate for calling anything "beta".

Deliverables:

- Canary non-disclosure tests across all output channels, including `--out` files and panics.
- Fuzzing (`cargo-fuzz`) for the dotenv parser and the redaction path; fuzz targets run in scheduled CI.
- Malformed-file, comment-leakage, symlink, permission, and atomic-write failure tests (extending M1/M4 suites to adversarial inputs).
- Panic policy: any `panic!` path routed through a redacting hook so a crash message cannot embed file content.
- `SECURITY.md` with a vulnerability-reporting process.

Exit criterion: one week of scheduled fuzzing with no leak-class findings; all verification-requirement checkboxes from the security model demonstrably covered by a named test.

### M6 — JSON/JSONL inference (experimental)

Deliverables:

- `readsafe inspect` support for JSON and JSONL: recursive path collection, broad scalar types, nullability, presence frequency, array/object shape.
- `readsafe infer --schema-out`: safe schema subset only — no `enum`, `const`, `examples`, `default`, exact lengths, exact numeric bounds, inferred regexes, hashes, or fingerprints. A denylist test asserts these keywords never appear in generated schemas from sensitive fixtures.
- Streaming JSONL with sampling by default; `scan` block reporting `mode`, `sampledRecords`, `recordCount` (null when sampled), `complete`; explicit `--full-scan` flag; large-file memory benchmark (bounded memory on a multi-GB fixture).
- Experimental marker on JSON/JSONL entries in the manifest and in `--help`.

Exit criterion: schema-keyword denylist test, sampling-semantics tests, and the memory benchmark pass; JSON/JSONL fixtures with canaries are clean.

### M7 — `readsafe validate` and agent instruction packaging

Deliverables:

- `readsafe validate --manifest readsafe.structure.json` (drift detection: keys added/removed/type-changed, reported without values) and `readsafe validate <file> --schema <schema>`.
- The minimal agent instruction from `skills/` packaged for distribution (e.g. `packages/forcing-skill/`), with examples verified against the real CLI output rather than hand-written samples.
- End-to-end agent-workflow test: a scripted session that only ever sees ReadSafe output performs a full dotenv change; the transcript is asserted canary-clean.

Exit criterion: the end-to-end agent-workflow test passes and is the flagship CI job.

### M8 — Release engineering

Deliverables:

- Reproducible-as-practical release builds for Linux (x86_64, aarch64), macOS (x86_64, aarch64), Windows (x86_64).
- GitHub Releases with signed artifacts and checksums (Sigstore, keyless via GitHub Actions OIDC); `cargo publish` for `readsafe` and `readsafe-core`.
- Thin `@readsafe/cli` npm wrapper that downloads the pinned, checksum-verified binary at install time from GitHub Releases only — no post-install arbitrary code download beyond that verified fetch, per the supply-chain posture.
- Dependency audit snapshot published with the release (tree size, `cargo audit`/`cargo deny` reports).
- README rewritten from "planned" to actual installation and usage docs; license chosen and applied (decide between MIT and Apache-2.0/MIT dual before tagging — required before any release, see open decisions).
- Tag `v0.1.0`.

Exit criterion: a clean machine can install via GitHub Releases and via npm, verify the checksum, and run the M7 end-to-end workflow.

## Cross-cutting rules (all milestones)

- **The canary harness is mandatory.** Every new output path gets a canary test in the same PR that introduces it.
- **No contract drift.** Output changes require updating `docs/cli-contract.md` in the same PR; `schemaVersion` bumps for breaking changes only.
- **Small dependency tree.** New runtime dependencies need justification in the PR description; prefer std and small audited crates.
- **No telemetry, ever.** Enforced by review and by the dependency policy.
- **Fail closed.** Any "not sure if this is safe to print" decision defaults to withholding, with exit code 5 where suppression changes the result.

## Deferred beyond v1

- `readsafe redact` (redacted file copies);
- keyed equality-check / fingerprint feature;
- secret-manager integrations;
- Homebrew formula and container image;
- pre-commit and CI integrations beyond documentation;
- repository policy files for marking additional files sensitive (design sketch may land earlier, implementation later);
- TOML/YAML support.

## Open decisions to resolve during the plan

| Decision | Resolve by | Notes |
| --- | --- | --- |
| ~~License (MIT vs Apache-2.0/MIT dual)~~ | Resolved | **MIT** — `LICENSE` at repo root, applied to both crates via `license.workspace`. |
| ~~Signing mechanism (minisign vs Sigstore)~~ | Resolved | **Sigstore** — keyless signing via GitHub Actions OIDC (`cosign sign-blob`); avoids key custody. |
| `required` semantics for dotenv variables | M3 | Inference source (e.g. `.env.example` cross-reference) vs always `source: "inferred", confidence: "low"`. |
| Duplicate-key `env test` behavior | M4 | Contract says refuse ambiguous operations; confirm `test` counts as ambiguous. |
| Experimental-marker field name for JSON/JSONL | M6 | Must be additive within schema `0.1`. |

## Risks this ordering mitigates

- Building the leak-test harness first (M0) means every subsequent feature is born with disclosure tests, instead of retrofitting them — the single biggest failure mode for this product.
- Freezing contracts before code (M0) prevents implementation convenience from eroding the security boundary.
- Keeping JSON/JSONL after the hardening gate (M6 > M5) keeps the highest-leak-risk inference work from shipping on an unproven redaction pipeline.
- Deferring `readsafe redact` removes the one v1-candidate feature whose entire output is derived from sensitive input.
