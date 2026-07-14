# ReadSafe Minimal Agent Instruction

Use this instruction when an agent needs to inspect or modify a file that is known or reasonably suspected to contain private values.

ReadSafe parses the file locally. Its purpose is to keep raw values out of agent-visible output, not to avoid local file access entirely.

## Files that should trigger ReadSafe

Use `readsafe` before directly reading or editing:

- `.env`;
- environment-specific dotenv files such as `.env.production` or `.env.local`;
- `*.env` files that may contain credentials;
- credential-bearing or production configuration JSON;
- private JSONL or NDJSON datasets;
- any supported file explicitly marked sensitive by repository policy.

Do not automatically force ReadSafe for ordinary public files such as:

- `.env.example`;
- `package.json`;
- `tsconfig.json`;
- lockfiles;
- JSON Schema files;
- public fixtures;
- generated metadata that is already documented as non-sensitive.

When uncertain, inspect repository policy or ask before opening the file directly.

## Core rule

For a sensitive supported file, prefer:

```bash
readsafe inspect <file-or-dir> --json
```

over opening the raw file.

Treat comments and descriptions returned by ReadSafe as redacted metadata. Do not assume comments are safe merely because they are not values.

## Dotenv updates

Do not read an entire dotenv file merely to add, update, remove, rename, or validate one key.

Use a redacted dry run first:

```bash
printf '%s' "$NEW_VALUE" |
  readsafe env set .env KEY --value-from-stdin --dry-run --json

readsafe env remove .env OLD_KEY --dry-run --json
readsafe env rename .env OLD_KEY NEW_KEY --dry-run --json
readsafe env test .env KEY --type email --json
```

Apply the write only after the dry-run result is acceptable.

For automated or agent-driven updates, pass new values through stdin or another non-argument input supported by ReadSafe. Do not place secrets in `--value`, command history, tool-call arguments, or logs.

ReadSafe cannot protect a value that was already included in the agent prompt or command invocation.

## JSON and JSONL

Use structure inspection for JSON or JSONL only when the file is private, credential-bearing, production data, or explicitly governed by repository policy:

```bash
readsafe inspect private-config.json --json
readsafe inspect events.jsonl --json
readsafe infer events.jsonl --schema-out schemas/events.schema.json
```

Generated schemas must not be treated as complete. Inferred schemas may be based on a sample and should include confidence and sampling metadata.

Do not request value-derived examples, constants, enums, defaults, exact lengths, hashes, or fingerprints from sensitive data.

## Secret safety

Do not print, summarize, copy, or store raw secret values.

If ReadSafe marks a key or path as sensitive, treat it as sensitive even when the visible metadata appears harmless.

Do not expose raw values through:

- stdout or stderr;
- patches or dry-run output;
- error messages;
- shell history;
- process arguments;
- agent tool traces;
- generated manifests or schemas.

## If ReadSafe is unavailable

For dotenv and other known-sensitive files:

1. Do not read the raw file by default.
2. Ask to install ReadSafe or request explicit permission to continue without it.
3. Explain that direct access may expose values to model context or tool logs.

For public JSON, schemas, lockfiles, and fixtures, continue with normal file tools unless repository policy says otherwise.

## Minimal instruction

```text
Before reading or editing a file known or suspected to contain private values, use readsafe to obtain redacted structure metadata. Use readsafe env set/remove/rename/test for narrow dotenv operations, and pass new values through stdin rather than command arguments. Do not force readsafe for ordinary public JSON such as package.json, tsconfig.json, lockfiles, schemas, or public fixtures. Never expose raw secret values. If readsafe is unavailable, stop before reading known-sensitive dotenv files and ask for permission.
```
