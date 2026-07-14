//! ReadSafe CLI: redacted structure metadata and narrow updates for
//! sensitive structured files. See docs/cli-contract.md for the frozen
//! machine contract; raw values are never written to stdout or stderr.

mod envops;
mod inferval;
mod inspect;
mod output;

use clap::{Parser, Subcommand};
use readsafe_core::error::{ErrorCode, SafeError};
use readsafe_core::jsonish::DEFAULT_SAMPLE_RECORDS;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "readsafe",
    version,
    about = "Give agents the structure. Keep sensitive values out of their context.",
    after_help = "Raw values are never emitted on any output channel. \
                  New values are supplied via stdin, not command arguments."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit redacted structure metadata for supported files.
    Inspect {
        /// Files or directories (directories are scanned for dotenv files).
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Emit the machine-readable JSON manifest on stdout.
        #[arg(long)]
        json: bool,
        /// Write the JSON manifest to a file instead of stdout.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
        /// Follow symbolic links (refused by default).
        #[arg(long)]
        allow_symlink: bool,
    },
    /// Narrow dotenv operations that never return existing values.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Infer a safe schema (no value-derived keywords) from JSON or JSONL.
    Infer {
        path: PathBuf,
        /// Write the schema to a file instead of stdout.
        #[arg(long, value_name = "FILE")]
        schema_out: Option<PathBuf>,
        /// Read every record instead of sampling.
        #[arg(long)]
        full_scan: bool,
        /// Maximum records to sample (ignored with --full-scan).
        #[arg(long, default_value_t = DEFAULT_SAMPLE_RECORDS)]
        sample: u64,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_symlink: bool,
    },
    /// Check current files against a manifest or an explicit schema.
    Validate {
        /// File to validate against an explicit schema (with --schema).
        #[arg(required_unless_present = "manifest", conflicts_with = "manifest")]
        file: Option<PathBuf>,
        /// Manifest produced by `readsafe inspect --out` (drift detection).
        #[arg(long, value_name = "FILE")]
        manifest: Option<PathBuf>,
        /// Schema produced by `readsafe infer` to validate <file> against.
        #[arg(long, value_name = "FILE", requires = "file")]
        schema: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_symlink: bool,
    },
}

#[derive(Subcommand)]
enum EnvCommand {
    /// Add or update one key. The value is read from stdin or an fd.
    Set {
        file: PathBuf,
        key: String,
        /// Read the new value from stdin (values must not be passed as
        /// command arguments). Mutually exclusive with --value-fd.
        #[arg(long)]
        value_from_stdin: bool,
        /// Read the new value from an inherited file descriptor (Unix only).
        /// Lets a parent process hand off a secret without argv exposure.
        #[arg(long, value_name = "FD", conflicts_with = "value_from_stdin")]
        value_fd: Option<i32>,
        /// Validate the new value before writing (email, url, port,
        /// hostname, uuid, semver, int, bool, enum(...), regex(...)).
        #[arg(long, value_name = "TYPE")]
        r#type: Option<String>,
        /// Report the operation without writing.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_symlink: bool,
    },
    /// Remove one key without returning its previous value.
    Remove {
        file: PathBuf,
        key: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_symlink: bool,
    },
    /// Rename a key; the value stays inside the local process.
    Rename {
        file: PathBuf,
        old_key: String,
        new_key: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_symlink: bool,
    },
    /// Validate an existing value without returning it.
    Test {
        file: PathBuf,
        key: String,
        #[arg(long, value_name = "TYPE", required = true)]
        r#type: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allow_symlink: bool,
    },
}

fn main() {
    install_redacting_panic_hook();
    let cli = Cli::parse();
    let (result, json) = run(cli.command);
    let exit = match result {
        Ok(code) => code,
        Err(error) => output::print_error(&error, json),
    };
    std::process::exit(exit);
}

/// Replace the default panic handler so a crash can never print a panic
/// payload. A payload is a formatted string, and some upstream code could in
/// principle interpolate file content into one; the default hook would send
/// that to stderr. We emit a fixed, content-free line instead. The source
/// location (file:line of ReadSafe's own code) carries no file content, so we
/// let the runtime's default abort/exit behaviour follow.
fn install_redacting_panic_hook() {
    std::panic::set_hook(Box::new(|_info| {
        eprintln!(
            "readsafe: error: internal error; aborting. \
             No file content is included in this message. \
             Please report this at the SECURITY.md contact if it reproduces."
        );
    }));
}

fn run(command: Command) -> (Result<i32, SafeError>, bool) {
    match command {
        Command::Inspect {
            paths,
            json,
            out,
            allow_symlink,
        } => (
            inspect::run(&paths, json, out.as_deref(), allow_symlink),
            json,
        ),
        Command::Infer {
            path,
            schema_out,
            full_scan,
            sample,
            json,
            allow_symlink,
        } => (
            inferval::infer(
                &path,
                schema_out.as_deref(),
                full_scan,
                sample,
                json,
                allow_symlink,
            ),
            json,
        ),
        Command::Validate {
            file,
            manifest,
            schema,
            json,
            allow_symlink,
        } => {
            let result = match (manifest, file, schema) {
                (Some(manifest), _, _) => inferval::validate_manifest(&manifest, json),
                (None, Some(file), Some(schema)) => {
                    inferval::validate_schema(&file, &schema, json, allow_symlink)
                }
                (None, Some(_), None) => Err(SafeError::new(
                    ErrorCode::Usage,
                    "validate <file> requires --schema, or use --manifest",
                )),
                (None, None, _) => Err(SafeError::new(
                    ErrorCode::Usage,
                    "validate requires --manifest or a <file> with --schema",
                )),
            };
            (result, json)
        }
        Command::Env { command } => run_env(command),
    }
}

fn run_env(command: EnvCommand) -> (Result<i32, SafeError>, bool) {
    match command {
        EnvCommand::Set {
            file,
            key,
            value_from_stdin,
            value_fd,
            r#type,
            dry_run,
            json,
            allow_symlink,
        } => {
            let result = (|| {
                let value = match (value_from_stdin, value_fd) {
                    (true, _) => envops::value_from_stdin()?,
                    (false, Some(fd)) => envops::value_from_fd(fd)?,
                    (false, None) => {
                        return Err(SafeError::new(
                            ErrorCode::Usage,
                            "env set requires --value-from-stdin or --value-fd; values must not be passed as command arguments",
                        ));
                    }
                };
                let flags = envops::WriteFlags {
                    dry_run,
                    allow_symlink,
                };
                let operation = envops::set(&file, &key, &value, r#type.as_deref(), &flags)?;
                output::print_operation(operation, json);
                Ok(0)
            })();
            (result, json)
        }
        EnvCommand::Remove {
            file,
            key,
            dry_run,
            json,
            allow_symlink,
        } => {
            let flags = envops::WriteFlags {
                dry_run,
                allow_symlink,
            };
            let result = envops::remove(&file, &key, &flags).map(|operation| {
                output::print_operation(operation, json);
                0
            });
            (result, json)
        }
        EnvCommand::Rename {
            file,
            old_key,
            new_key,
            dry_run,
            json,
            allow_symlink,
        } => {
            let flags = envops::WriteFlags {
                dry_run,
                allow_symlink,
            };
            let result = envops::rename(&file, &old_key, &new_key, &flags).map(|operation| {
                output::print_operation(operation, json);
                0
            });
            (result, json)
        }
        EnvCommand::Test {
            file,
            key,
            r#type,
            json,
            allow_symlink,
        } => {
            let result =
                envops::test(&file, &key, &r#type, allow_symlink).map(|(operation, exit)| {
                    output::print_operation(operation, json);
                    exit
                });
            (result, json)
        }
    }
}
