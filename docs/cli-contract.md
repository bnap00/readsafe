# ReadSafe CLI and Output Contract

This document describes the planned command and machine-output contract. ReadSafe is currently pre-alpha; interfaces may change before the first release.

## Principles

1. Raw values are not emitted by default.
2. Machine-readable output is stable and versioned.
3. New secret values should not be passed as command arguments.
4. Inference is explicitly marked as inference.
5. Dry runs report operations, not surrounding sensitive text.
6. Errors identify paths and reasons without echoing source values.

## Planned commands

### `readsafe inspect`

Inspect sensitive supported files and emit redacted structure metadata.

```bash
readsafe inspect .env --json
readsafe inspect private-config.json events.jsonl --json
readsafe inspect . --out readsafe.structure.json
```

Default human-readable output and `--json` output must share the same redaction guarantees.

### `readsafe env set`

Add or update one dotenv key.

```bash
printf '%s' "$NEW_VALUE" |
  readsafe env set .env KEY --value-from-stdin --dry-run --json
```

The implementation should also support a hidden interactive prompt for human use.

`--value` should not be recommended for secrets. If retained, it should be documented for explicitly non-sensitive values only.

### `readsafe env remove`

Remove one dotenv key without returning its previous value.

```bash
readsafe env remove .env OLD_KEY --dry-run --json
```

### `readsafe env rename`

Rename a key while retaining the existing value inside the local process.

```bash
readsafe env rename .env OLD_KEY NEW_KEY --dry-run --json
```

### `readsafe env test`

Validate an existing dotenv value without returning it.

```bash
readsafe env test .env SUPPORT_EMAIL --type email --json
```

Initial validators may include `email`, `url`, `port`, `hostname`, `uuid`, `semver`, `int`, `bool`, `enum(...)`, and an explicitly supplied `regex(...)`.

Validation reasons must not contain the tested value.

### `readsafe infer`

Infer a safe schema from JSON or JSONL.

```bash
readsafe infer events.jsonl --schema-out schemas/events.schema.json
```

The default inferred schema must exclude value-derived examples, enums, constants, defaults, exact lengths, hashes, and fingerprints.

### `readsafe validate`

Validate current files against a ReadSafe manifest or an explicit schema.

The command surface should distinguish these cases:

```bash
readsafe validate --manifest readsafe.structure.json
readsafe validate config.json --schema schemas/config.schema.json
```

Avoid the ambiguous `--structure` name.

### `readsafe redact`

Create a redacted copy intended for debugging or sharing.

```bash
readsafe redact .env --out .env.redacted
```

Redacted copies are not guaranteed to be harmless merely because values were removed. Comments and metadata must also pass through classification.

## Canonical manifest

```json
{
  "schemaVersion": "0.1",
  "toolVersion": "0.1.0",
  "files": [
    {
      "path": ".env",
      "kind": "dotenv",
      "variables": [
        {
          "name": "DATABASE_URL",
          "type": "url",
          "required": true,
          "sensitive": true,
          "source": "inferred",
          "confidence": "high",
          "valueExposed": false
        }
      ]
    },
    {
      "path": "events.jsonl",
      "kind": "jsonl",
      "scan": {
        "mode": "sample",
        "sampledRecords": 10000,
        "recordCount": null,
        "complete": false
      },
      "recordSchema": "schemas/events.schema.json",
      "valueExposed": false
    }
  ]
}
```

## Version fields

- `schemaVersion` versions the JSON contract.
- `toolVersion` identifies the binary that produced the output.

Consumers must not assume that the two versions move together.

## Volatile metadata

Generation timestamps should be omitted by default. An optional metadata mode may emit:

```json
{
  "metadata": {
    "generatedAt": "2026-07-13T00:00:00Z"
  }
}
```

Canonical comparison should exclude the metadata object.

## JSONL scan semantics

A sampled scan cannot claim an exact total record count unless the implementation also reads the entire file.

Use:

```json
{
  "scan": {
    "mode": "sample",
    "sampledRecords": 10000,
    "recordCount": null,
    "complete": false
  }
}
```

For a full scan:

```json
{
  "scan": {
    "mode": "full",
    "sampledRecords": 1250000,
    "recordCount": 1250000,
    "complete": true
  }
}
```

## Safe inferred-schema subset

For sensitive files, default inference may emit:

- object property names;
- object and array shape;
- broad scalar types;
- nullability;
- field presence frequency;
- required/optional inference;
- explicitly authored descriptions that pass redaction;
- sampling and confidence metadata.

Default inference must not emit value-derived:

- `enum`;
- `const`;
- `examples`;
- `default`;
- exact string lengths;
- exact numeric bounds;
- inferred regular expressions;
- hashes or fingerprints.

## Dry-run contract

```json
{
  "schemaVersion": "0.1",
  "operation": {
    "type": "env.set",
    "path": ".env",
    "key": "SUPPORT_EMAIL",
    "changed": true,
    "wouldWrite": true,
    "valueExposed": false
  }
}
```

A dry run must not include unified-diff context from the raw file.

## Error contract

```json
{
  "schemaVersion": "0.1",
  "error": {
    "code": "ENV_VALUE_INVALID",
    "path": ".env",
    "key": "API_PORT",
    "reason": "value is not a valid TCP port",
    "valueExposed": false
  }
}
```

The parser must sanitize third-party error strings before returning them.

## Planned exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Validation or policy failure |
| `2` | Invalid CLI usage |
| `3` | Unsupported format |
| `4` | File access or write failure |
| `5` | Unsafe output prevented |
| `6` | Ambiguous operation, such as duplicate dotenv keys |

Exact codes should be frozen before the first stable release.

## Paths and ordering

- Manifest paths should use repository-relative forward slashes where possible.
- Output ordering must be stable.
- Input order may be preserved for human output, while canonical JSON follows the documented ordering rule.
- Platform-specific absolute paths should not appear unless explicitly requested.

## Compatibility

Breaking changes to the machine contract require a `schemaVersion` change. Additive optional fields may be introduced within a compatible schema version only when consumers are required to ignore unknown fields.

## Implementation notes (v0.1)

The initial implementation in this repository resolves the following contract details. These are amendments recorded per the v1 plan's no-contract-drift rule.

### Ordering and channels

- Canonical JSON ordering: `files` sorted by path, `variables` sorted by name, `structure` paths in traversal order.
- Success output goes to stdout. Errors go to stderr, JSON-formatted under `--json`.

### Additive optional fields (schema `0.1`)

- `files[].experimental: true` on JSON/JSONL entries while inference is experimental.
- `files[].malformedLines` counts dotenv lines that could not be parsed (their content is preserved on write but never emitted).
- `files[].structure` lists coarse `$.path[]`-style paths with broad types for JSON/JSONL.
- `scan.malformedRecords` counts unparseable JSONL lines.
- `variables[].descriptionRedacted: true` marks a withheld comment.
- Inferred schemas carry an `x-readsafe` metadata object (`schemaVersion`, `toolVersion`, `source`, `confidence`, and `scan` for JSONL).

### Behavior decisions

- `--value` is not implemented; values arrive via `--value-from-stdin` or `--value-fd <N>` (an inherited file descriptor, Unix only; mutually exclusive with `--value-from-stdin`). One trailing newline is stripped from either source so line-buffered producers behave predictably; use `printf '%s'` for exact bytes.
- Symbolic links are refused by default; `--allow-symlink` opts in per invocation.
- Panics are routed through a redacting hook: a crash prints a fixed, content-free line to stderr and never emits a panic payload. This is an internal-error path, not one of the 0–6 contract exit codes.
- `env set` on a missing file creates it. `env remove` of a missing key succeeds with `changed: false`. `env rename` of a missing key and `env test` of a missing key are errors.
- Duplicate dotenv keys make `set`, `remove`, `rename`, and `test` fail with `ENV_DUPLICATE_KEY` (exit 6).
- `required` for dotenv variables is inferred from a sibling `.env.example`: keys listed there are required, everything else is optional.
- Directory arguments to `inspect` are scanned recursively for dotenv files only; JSON/JSONL files must be named explicitly so public-config workflows are not disturbed.
- `validate` implements both manifest mode (`--manifest`, dotenv structure drift) and explicit-schema mode (`<file> --schema <schema>`, JSON/JSONL structural conformance). Schema mode reports violations by path only — `missingRequired`, `unexpected`, and `typeMismatch` — never values; the `x-readsafe` metadata block and any non-constraint schema keys are ignored during comparison. `readsafe redact` remains deferred (see the v1 plan).

### Error codes (implemented)

`ENV_KEY_NOT_FOUND`, `ENV_KEY_EXISTS`, `ENV_DUPLICATE_KEY`, `ENV_VALUE_INVALID`, `ENV_INVALID_KEY`, `FILE_NOT_FOUND`, `FILE_IO`, `FILE_NOT_UTF8`, `SYMLINK_REFUSED`, `UNSUPPORTED_FORMAT`, `PARSE_ERROR`, `INVALID_TYPE_SPEC`, `MANIFEST_INVALID`, `UNSAFE_OUTPUT_PREVENTED`, `USAGE`. Each maps onto the exit-code table above.
