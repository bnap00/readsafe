# ReadSafe Vision and Architecture

## Product idea

ReadSafe is a local-first open-source CLI that lets AI agents understand the structure of sensitive structured files and request narrow supported updates without receiving raw existing values.

The initial brand and command are:

- product: **ReadSafe**;
- primary CLI: `readsafe`;
- planned npm organization: `@readsafe`.

The shorthand `rds` is intentionally not part of the initial documented interface because it collides conceptually with Amazon RDS and adds avoidable search and support ambiguity.

## Positioning

> ReadSafe parses sensitive files locally and gives agents redacted structure metadata instead of raw values.

The product promise is output non-disclosure. ReadSafe does not claim to inspect a file without locally reading it.

## Core principle

Agents should see the map, not the treasure.

Expose conservatively:

- file path and format;
- key and object paths;
- broad inferred type;
- required or optional state;
- sensitivity classification;
- redacted descriptions;
- schema references;
- scan and sampling metadata;
- inference confidence.

Do not expose by default:

- raw values;
- credential-bearing URLs;
- private keys, tokens, or connection strings;
- unfiltered comments;
- value-derived examples or constants;
- exact hashes, fingerprints, or lengths;
- secrets in stdout, stderr, manifests, diffs, or errors.

## MVP wedge

The sharpest initial product is agent-safe dotenv inspection and mutation:

1. inspect keys without returning values;
2. classify sensitivity conservatively;
3. validate values locally;
4. add, update, remove, and rename one key;
5. show a redacted operation-level dry run;
6. write atomically while preserving surrounding formatting.

JSON and JSONL structure inspection should remain a secondary experimental feature until the safe inferred-schema contract is proven.

## Architecture

```text
CLI
  -> file discovery
  -> format-specific parser
  -> redaction and sensitivity classifier
  -> structure inference
  -> safe manifest emitter
  -> narrow update engine
```

### Core engine

Rust remains a strong fit for:

- a portable native binary;
- streaming JSONL parsing;
- predictable memory use;
- atomic file operations;
- a small runtime surface;
- security-focused testing and fuzzing.

### Workspace layer

A Bun workspace can orchestrate:

- documentation tooling;
- release scripts;
- npm wrappers;
- test fixtures;
- contributor commands.

The JavaScript layer should not be required for the native CLI to run.

## Planned repository shape

```text
readsafe/
  crates/
    readsafe/
    readsafe-core/
  packages/
    cli/
    forcing-skill/
  docs/
    vision.md
    security-model.md
    cli-contract.md
    readsafe-agent-structure-pitch.html
  skills/
    readsafe-minimal-forcing-skill.md
  README.md
  Cargo.toml
  package.json
  bun.lock
```

## Safe-update design

Agents often read a complete file before editing one line. That behavior is reasonable for ordinary source code but unnecessarily exposes unrelated values in dotenv files.

ReadSafe should own the local read-modify-write cycle and return only:

- the operation requested;
- whether a change would occur;
- whether validation passed;
- whether a write was performed;
- `valueExposed: false`.

New secret values should arrive through stdin, a file descriptor, an interactive hidden prompt, or a future secret-manager integration—not a normal command argument.

## JSON and JSONL inference

For JSON:

- collect paths recursively;
- infer broad scalar types;
- detect arrays and object shapes;
- calculate nullability and field presence;
- mark inference confidence.

For JSONL:

- stream records;
- sample by default;
- support explicit full scans;
- distinguish sampled records from exact record count;
- report drift and heterogeneous records;
- avoid value-derived schema keywords that could leak data.

## Deterministic contract

The agent-facing JSON contract should provide:

- separate `schemaVersion` and `toolVersion`;
- stable path formatting;
- stable ordering;
- stable exit codes;
- machine-readable error codes;
- no timestamps by default;
- no raw values in either stdout or stderr;
- deterministic operation-level dry-run results.

## Agent instruction

ReadSafe should ship a minimal instruction that directs agents to use it for known-sensitive files without interfering with normal public JSON workflows.

The instruction should exempt files such as `package.json`, `tsconfig.json`, lockfiles, schemas, `.env.example`, and public fixtures unless repository policy marks them sensitive.

## Dependency and release posture

- minimal runtime dependencies;
- no telemetry;
- no post-install code download;
- locked and auditable dependencies;
- vulnerability and license checks;
- signed checksums and release artifacts;
- reproducible builds where practical;
- tests that assert canary secrets never appear in any output channel.

## Build order

1. Freeze the security and output contracts.
2. Implement dotenv inspection with strict output redaction.
3. Add operation-level dry runs.
4. Add atomic dotenv set, remove, rename, and test.
5. Add canary-secret and parser-error leakage tests.
6. Add safe JSON/JSONL structure inference.
7. Add CI and pre-commit integration.
8. Add distribution wrappers after the binary interface stabilizes.

## Key risks

- False negatives in sensitivity detection can leak data.
- Comments may contain secrets.
- Schema inference can leak examples, constants, lengths, or provider-specific patterns.
- Sampling can create false confidence.
- Passing new values through arguments can leak them before ReadSafe runs.
- A forcing skill that applies to every JSON file can make agents less useful and encourage bypassing the tool.
- Supply-chain compromise is especially serious for software that processes sensitive-adjacent files.
