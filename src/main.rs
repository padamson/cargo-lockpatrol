use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::process::ExitCode;

use cargo_lockpatrol::check::{self, EXIT_BROKEN, EXIT_CLEAN, Locked, Options, UnknownLocked};

const USAGE: &str = "\
Check every tracked Cargo.lock for RustSec advisories with cargo-deny.

Usage: cargo lockpatrol check [--config <PATH>] [--locked <root|none|all>]

Options:
  --config <PATH>   the deny.toml every tree is checked against
                    [default: deny.toml at the repository root]
  --locked <WHICH>  which trees must match their Cargo.lock: root, none or all
                    [default: root]
  -h, --help        print this help
  -V, --version     print the version

Exit status: 0 clean, 1 an advisory found, 2 a check broke, 3 both.";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Help,
    Version,
    Check {
        config: Option<PathBuf>,
        locked: Locked,
    },
}

/// A command line that asks for nothing this binary does. Each variant
/// carries the argument at fault.
#[derive(Debug, PartialEq, Eq)]
enum UsageError {
    NoCommand,
    UnknownCommand(String),
    UnexpectedArgument(String),
    MissingValue(&'static str),
    Locked(UnknownLocked),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::NoCommand => write!(f, "no command given"),
            UsageError::UnknownCommand(c) => write!(f, "unknown command {c:?}"),
            UsageError::UnexpectedArgument(a) => write!(f, "unexpected argument {a:?}"),
            UsageError::MissingValue(flag) => write!(f, "{flag} needs a value"),
            UsageError::Locked(e) => write!(f, "{e}"),
        }
    }
}

/// Parse the arguments after the program name. Cargo runs a subcommand
/// as `cargo-lockpatrol lockpatrol ...`, so a leading `lockpatrol` is
/// dropped.
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Request, UsageError> {
    let mut args = args.into_iter().peekable();
    if args.peek().is_some_and(|a| a == "lockpatrol") {
        args.next();
    }
    let command = args.next().ok_or(UsageError::NoCommand)?;
    match command.to_str() {
        Some("-h" | "--help" | "help") => return Ok(Request::Help),
        Some("-V" | "--version") => return Ok(Request::Version),
        Some("check") => {}
        _ => {
            return Err(UsageError::UnknownCommand(
                command.to_string_lossy().into_owned(),
            ));
        }
    }
    let (mut config, mut locked) = (None, Locked::default());
    while let Some(arg) = args.next() {
        let mut value = |flag| args.next().ok_or(UsageError::MissingValue(flag));
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(Request::Help),
            Some("--config") => config = Some(PathBuf::from(value("--config")?)),
            Some("--locked") => {
                let v = value("--locked")?;
                locked = v.to_string_lossy().parse().map_err(UsageError::Locked)?;
            }
            _ => {
                return Err(UsageError::UnexpectedArgument(
                    arg.to_string_lossy().into_owned(),
                ));
            }
        }
    }
    Ok(Request::Check { config, locked })
}

fn main() -> ExitCode {
    let code = match parse(std::env::args_os().skip(1)) {
        Ok(Request::Help) => {
            println!("{USAGE}");
            EXIT_CLEAN
        }
        Ok(Request::Version) => {
            println!("cargo-lockpatrol {}", env!("CARGO_PKG_VERSION"));
            EXIT_CLEAN
        }
        Ok(Request::Check { config, locked }) => run_check(config, locked),
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            EXIT_BROKEN
        }
    };
    ExitCode::from(code)
}

fn run_check(config: Option<PathBuf>, locked: Locked) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: no current directory: {e}");
            return EXIT_BROKEN;
        }
    };
    let root = match check::repo_root(&cwd) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return EXIT_BROKEN;
        }
    };
    let config = config.map_or_else(|| root.join("deny.toml"), |c| cwd.join(c));
    let opts = Options {
        root,
        config,
        locked,
        cargo: check::cargo_program(|k| std::env::var_os(k)),
    };
    check::run(
        &opts,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
    .unwrap_or_else(|e| {
        eprintln!("error: could not write the report: {e}");
        EXIT_BROKEN
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_bare_check_uses_the_defaults() {
        assert_eq!(
            parse(args(&["check"])),
            Ok(Request::Check {
                config: None,
                locked: Locked::Root
            })
        );
    }

    #[test]
    fn the_name_cargo_passes_first_is_dropped() {
        assert_eq!(
            parse(args(&["lockpatrol", "check", "--locked", "all"])),
            Ok(Request::Check {
                config: None,
                locked: Locked::All
            })
        );
    }

    #[test]
    fn config_takes_a_path() {
        assert_eq!(
            parse(args(&["check", "--config", "ci/deny.toml"])),
            Ok(Request::Check {
                config: Some(PathBuf::from("ci/deny.toml")),
                locked: Locked::Root
            })
        );
    }

    #[test]
    fn a_flag_without_its_value_is_an_error_naming_the_flag() {
        assert_eq!(
            parse(args(&["check", "--locked"])),
            Err(UsageError::MissingValue("--locked"))
        );
    }

    #[test]
    fn a_bad_locked_value_is_an_error_carrying_the_value() {
        assert_eq!(
            parse(args(&["check", "--locked", "some"])),
            Err(UsageError::Locked(UnknownLocked("some".into())))
        );
    }

    #[test]
    fn an_unknown_argument_is_an_error_naming_it() {
        assert_eq!(
            parse(args(&["check", "--frozen"])),
            Err(UsageError::UnexpectedArgument("--frozen".into()))
        );
    }

    #[test]
    fn an_unknown_command_is_an_error_naming_it() {
        assert_eq!(
            parse(args(&["audit"])),
            Err(UsageError::UnknownCommand("audit".into()))
        );
    }

    #[test]
    fn no_command_is_an_error() {
        assert_eq!(parse(args(&[])), Err(UsageError::NoCommand));
    }

    #[test]
    fn lockpatrol_alone_is_no_command() {
        assert_eq!(parse(args(&["lockpatrol"])), Err(UsageError::NoCommand));
    }

    #[test]
    fn help_is_a_request_not_an_error() {
        assert_eq!(parse(args(&["--help"])), Ok(Request::Help));
    }

    #[test]
    fn help_after_check_is_still_help() {
        assert_eq!(parse(args(&["check", "-h"])), Ok(Request::Help));
    }

    #[test]
    fn version_is_a_request_not_an_error() {
        assert_eq!(parse(args(&["-V"])), Ok(Request::Version));
    }

    #[test]
    fn a_usage_error_message_names_the_argument_at_fault() {
        for (err, token) in [
            (UsageError::UnknownCommand("audit".into()), "audit"),
            (
                UsageError::UnexpectedArgument("--frozen".into()),
                "--frozen",
            ),
            (UsageError::MissingValue("--config"), "--config"),
            (UsageError::Locked(UnknownLocked("x".into())), "\"x\""),
        ] {
            let msg = err.to_string();
            assert!(
                msg.contains(token),
                "{err:?} should name {token}; got {msg}"
            );
        }
    }
}
