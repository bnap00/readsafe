# ReadSafe Forcing Skill (packaged)

This is the distributable copy of the ReadSafe agent instruction, versioned
against ReadSafe's `0.1` tool contract (see `skill.json`). The prose source of
truth lives in the repository at `skills/readsafe-minimal-forcing-skill.md`;
this package adds a runnable, CI-verified example so the commands below are
checked against real CLI output rather than hand-written.

## When to route through ReadSafe

Before directly reading or editing a file that is known or reasonably suspected
to contain private values — `.env`, `.env.production`, `*.env`,
credential-bearing configuration JSON, private JSONL/NDJSON, or any file marked
sensitive by repository policy — use ReadSafe to obtain redacted structure
metadata instead of opening the raw file.

Do **not** force ReadSafe for ordinary public files: `.env.example`,
`package.json`, `tsconfig.json`, lockfiles, JSON Schema files, or public
fixtures. When uncertain, ask.

## Verified examples

Every command below is exercised in CI against `examples/app.env`.

Inspect structure without reading values:

```bash
readsafe inspect examples/app.env --json
```

Narrow dotenv edits — always dry-run first, and pass new values through stdin
or an inherited file descriptor, never as an argument:

```bash
printf '%s' "$NEW_VALUE" | readsafe env set examples/app.env API_TOKEN --value-from-stdin --dry-run --json
printf '%s' "$NEW_VALUE" | readsafe env set examples/app.env API_TOKEN --value-from-stdin --json

# Or hand off a secret via a file descriptor (Unix), keeping it out of argv:
readsafe env set examples/app.env API_TOKEN --value-fd 3 --json  3<secret.txt

readsafe env remove examples/app.env OLD_KEY --dry-run --json
readsafe env rename examples/app.env OLD_KEY NEW_KEY --dry-run --json
readsafe env test examples/app.env SUPPORT_EMAIL --type email --json
```

Structure inference and drift/shape checks for JSON/JSONL (experimental):

```bash
readsafe infer events.jsonl --schema-out schemas/events.schema.json
readsafe validate config.json --schema schemas/events.schema.json --json
readsafe validate --manifest readsafe.structure.json --json
```

## Core rules

- Raw values never appear on any channel: stdout, stderr, dry-run output, error
  messages, generated manifests, or generated schemas.
- Treat comments and descriptions returned by ReadSafe as redacted metadata;
  do not assume they are safe.
- Pass new secret values through stdin or `--value-fd`, never `--value`, shell
  history, process arguments, or tool-call logs.
- If ReadSafe marks a key or path sensitive, treat it as sensitive even when the
  visible metadata looks harmless.
- ReadSafe cannot protect a value that was already placed in the prompt or the
  command invocation.

## If ReadSafe is unavailable

For dotenv and other known-sensitive files, do not read the raw file by default.
Ask to install ReadSafe or for explicit permission to proceed, and explain that
direct access may expose values to model context or tool logs. For public JSON,
schemas, lockfiles, and fixtures, continue with normal tools unless repository
policy says otherwise.
