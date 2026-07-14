# ReadSafe

**Give agents the structure. Keep sensitive values out of their context.**

ReadSafe is a planned open-source, local-first CLI for inspecting and narrowly updating sensitive structured files. It parses files on the developer machine and emits redacted structure metadata instead of raw values.

> **Project status: pre-alpha**
>
> The core dotenv workflow (`inspect`, `env set/remove/rename/test`), experimental JSON/JSONL inference (`infer`), and manifest and schema validation (`validate`) are implemented in this repository with a canary-secret non-disclosure test suite. No release artifacts have been published yet; build from source with `cargo build --release`. Interfaces may still change before the first release. See the [v1 plan](docs/v1-plan.md) for milestone status.

## Why ReadSafe?

AI coding agents often need to understand configuration files before making a change. Opening a raw `.env` file can place credentials in model context, tool traces, shell logs, or debugging output.

ReadSafe is intended to provide a narrower interface:

```text
sensitive file
    -> local parser
    -> redaction and classification
    -> stable structure manifest
    -> agent
```

The file is still read locally by the ReadSafe process. The safety property is that raw values are not emitted to the agent, stdout, stderr, generated manifests, or dry-run output by default.

## CLI

```bash
# Inspect a sensitive file or directory.
readsafe inspect .env --json

# Write a proposed value through stdin rather than a command argument.
printf '%s' "$SUPPORT_EMAIL" |
  readsafe env set .env SUPPORT_EMAIL --value-from-stdin --type email --dry-run --json

# Apply the same narrow update after reviewing the redacted dry run.
printf '%s' "$SUPPORT_EMAIL" |
  readsafe env set .env SUPPORT_EMAIL --value-from-stdin --type email --json

# Validate an existing value without returning it.
readsafe env test .env SUPPORT_EMAIL --type email --json

# Infer a safe schema from a JSONL file.
readsafe infer events.jsonl --schema-out schemas/events.schema.json
```

Using `--value-from-stdin` avoids placing a new value directly in shell history or the process argument list. It does not protect a secret that has already been placed in an agent prompt, tool-call argument, CI log, or shell transcript.

## Initial scope

The first useful release should focus on agent-safe dotenv workflows:

- inspect key names, comments, types, required state, and sensitivity;
- add, update, remove, rename, and test keys without returning existing values;
- preserve ordering, comments, quoting, and newline style where practical;
- return redacted dry-run results;
- use atomic writes.

Redacted JSON and JSONL structure inspection is a secondary capability. Generic JSON editing is not part of the initial safe-update scope.

## Security boundary

ReadSafe is designed to reduce accidental value exposure through its own outputs. It is not a secret manager, sandbox, access-control system, or replacement for operating-system permissions.

Default output must not include:

- raw values;
- credential-bearing URLs;
- private keys, tokens, or connection strings;
- unfiltered comments;
- value-derived examples, enums, constants, or defaults;
- exact hashes, fingerprints, or lengths of secrets;
- secrets in error messages or validation reasons.

ReadSafe should fail closed when sensitivity is uncertain. See [Security model](docs/security-model.md) for the full boundary and threat assumptions.

## Agent integration

The repository includes a proposed [minimal agent instruction](skills/readsafe-minimal-forcing-skill.md). It applies to files that are known or reasonably suspected to contain private values. A distributable copy with CI-verified examples ships in [`packages/forcing-skill/`](packages/forcing-skill/).

It intentionally does **not** force ReadSafe for every JSON file. Public configuration such as `package.json`, `tsconfig.json`, lockfiles, schemas, and ordinary fixtures should remain readable unless the project marks them sensitive.

## Planned output contract

Machine-readable output is the core product. The contract should use:

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
          "valueExposed": false
        }
      ]
    }
  ]
}
```

Volatile fields such as generation timestamps should be omitted by default so identical inputs can produce comparable output. See [CLI contract](docs/cli-contract.md).

## Non-goals

ReadSafe v1 should not:

- own, encrypt, rotate, or distribute secrets;
- upload files to a hosted service;
- expose raw values through a convenience flag;
- become a general configuration-management platform;
- promise that inferred schemas are complete;
- intercept an agent that bypasses the CLI.

## Planned distribution

Possible release channels include GitHub Releases, Cargo, Homebrew, a thin `@readsafe/cli` npm wrapper, and a container image. These commands will be documented as installation instructions only after the corresponding artifacts exist.

## Documentation

- [Vision and architecture](docs/vision.md)
- [v1 plan](docs/v1-plan.md)
- [Security model](docs/security-model.md)
- [CLI and output contract](docs/cli-contract.md)
- [Agent instruction](skills/readsafe-minimal-forcing-skill.md)
- [Pitch document](docs/readsafe-agent-structure-pitch.html)

## Contributing

The project is currently defining its threat model, CLI contract, test fixtures, and MVP boundary. Contributions should prioritize a small auditable dependency tree, deterministic output, explicit redaction rules, and tests for accidental disclosure.

## License

[MIT](LICENSE).
