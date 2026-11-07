use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cargo_lockpatrol::check::{self, EXIT_BROKEN, EXIT_CLEAN, Locked, Options, UnknownLocked};
use cargo_lockpatrol::render;

const USAGE: &str = "\
Check every tracked Cargo.lock for RustSec advisories with cargo-deny, and
keep a tracking issue's body current with the findings.

Usage: cargo lockpatrol check [--config <PATH>] [--locked <root|none|all>]
       cargo lockpatrol render <OLD> <REPORT> <OUT> <COMMENT> [--run-url <URL>]

check writes a report to stdout. Exit status: 0 clean, 1 an advisory found,
2 a check broke, 3 both.

  --config <PATH>   the deny.toml every tree is checked against
                    [default: deny.toml at the repository root]
  --locked <WHICH>  which trees must match their Cargo.lock: root, none or all
                    [default: root]

render reads the issue's old body from OLD (an empty file when there is no
issue) and a check report from REPORT, writes the new body to OUT and a
comment to COMMENT, and prints what an open issue needs: changed (edit the
body and post the comment), refreshed (edit the body) or unchanged.

  --run-url <URL>   the run log the comment links to

  -h, --help        print this help
  -V, --version     print the version";

/// What the command line asked for.
#[derive(Debug, PartialEq, Eq)]
enum Request {
    Help,
    Version,
    Check {
        config: Option<PathBuf>,
        locked: Locked,
    },
    Render {
        old: PathBuf,
        report: PathBuf,
        out: PathBuf,
        comment: PathBuf,
        run_url: Option<String>,
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
    MissingArgument(&'static str),
    Locked(UnknownLocked),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::NoCommand => write!(f, "no command given"),
            UsageError::UnknownCommand(c) => write!(f, "unknown command {c:?}"),
            UsageError::UnexpectedArgument(a) => write!(f, "unexpected argument {a:?}"),
            UsageError::MissingValue(flag) => write!(f, "{flag} needs a value"),
            UsageError::MissingArgument(name) => write!(f, "missing {name}"),
            UsageError::Locked(e) => write!(f, "{e}"),
        }
    }
}

fn unexpected(arg: &std::ffi::OsStr) -> UsageError {
    UsageError::UnexpectedArgument(arg.to_string_lossy().into_owned())
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
        Some("-h" | "--help" | "help") => Ok(Request::Help),
        Some("-V" | "--version") => Ok(Request::Version),
        Some("check") => parse_check(args),
        Some("render") => parse_render(args),
        _ => Err(UsageError::UnknownCommand(
            command.to_string_lossy().into_owned(),
        )),
    }
}

fn parse_check(mut args: impl Iterator<Item = OsString>) -> Result<Request, UsageError> {
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
            _ => return Err(unexpected(&arg)),
        }
    }
    Ok(Request::Check { config, locked })
}

fn parse_render(mut args: impl Iterator<Item = OsString>) -> Result<Request, UsageError> {
    const NAMES: [&str; 4] = ["OLD", "REPORT", "OUT", "COMMENT"];
    let (mut paths, mut run_url) = (Vec::new(), None);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-h" | "--help") => return Ok(Request::Help),
            Some("--run-url") => {
                // An empty value, as from an unset variable, is no link
                // rather than a link to nowhere.
                let v = args.next().ok_or(UsageError::MissingValue("--run-url"))?;
                run_url = Some(v.to_string_lossy().into_owned()).filter(|u| !u.is_empty());
            }
            Some(flag) if flag.starts_with('-') => return Err(unexpected(&arg)),
            _ => paths.push(PathBuf::from(arg)),
        }
    }
    match <[PathBuf; 4]>::try_from(paths) {
        Ok([old, report, out, comment]) => Ok(Request::Render {
            old,
            report,
            out,
            comment,
            run_url,
        }),
        Err(paths) => Err(match NAMES.get(paths.len()) {
            Some(name) => UsageError::MissingArgument(name),
            None => unexpected(paths[NAMES.len()].as_os_str()),
        }),
    }
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
        Ok(Request::Render {
            old,
            report,
            out,
            comment,
            run_url,
        }) => run_render(&old, &report, &out, &comment, run_url.as_deref()),
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

fn run_render(old: &Path, report: &Path, out: &Path, comment: &Path, run_url: Option<&str>) -> u8 {
    match render_files(old, report, out, comment, run_url) {
        Ok(status) => {
            println!("{status}");
            EXIT_CLEAN
        }
        Err(e) => {
            eprintln!("error: {e}");
            EXIT_BROKEN
        }
    }
}

/// Read the old body and the report, write the new body and the comment,
/// and return what the issue needs. Each error names the file at fault.
fn render_files(
    old: &Path,
    report: &Path,
    out: &Path,
    comment: &Path,
    run_url: Option<&str>,
) -> Result<render::Status, String> {
    let read = |p: &Path| {
        std::fs::read_to_string(p).map_err(|e| format!("could not read {}: {e}", p.display()))
    };
    let write = |p: &Path, text: &str| {
        std::fs::write(p, text).map_err(|e| format!("could not write {}: {e}", p.display()))
    };
    let rendered = render::render(&read(old)?, &read(report)?);
    write(out, &rendered.body)?;
    write(
        comment,
        &render::comment(&rendered.resolved, &rendered.new, run_url),
    )?;
    Ok(rendered.status)
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

    fn render_request(run_url: Option<&str>) -> Request {
        Request::Render {
            old: "old.md".into(),
            report: "report.txt".into(),
            out: "body.md".into(),
            comment: "comment.md".into(),
            run_url: run_url.map(str::to_owned),
        }
    }

    #[test]
    fn render_takes_its_four_paths_in_order() {
        assert_eq!(
            parse(args(&[
                "render",
                "old.md",
                "report.txt",
                "body.md",
                "comment.md"
            ])),
            Ok(render_request(None))
        );
    }

    #[test]
    fn the_run_url_may_come_anywhere_among_the_paths() {
        assert_eq!(
            parse(args(&[
                "render",
                "old.md",
                "--run-url",
                "https://example.invalid/run",
                "report.txt",
                "body.md",
                "comment.md"
            ])),
            Ok(render_request(Some("https://example.invalid/run")))
        );
    }

    #[test]
    fn render_without_all_four_paths_names_the_first_one_missing() {
        assert_eq!(
            parse(args(&["render", "old.md", "report.txt"])),
            Err(UsageError::MissingArgument("OUT"))
        );
    }

    #[test]
    fn a_fifth_path_is_unexpected() {
        assert_eq!(
            parse(args(&["render", "a", "b", "c", "d", "e"])),
            Err(UsageError::UnexpectedArgument("e".into()))
        );
    }

    #[test]
    fn a_check_flag_is_unexpected_under_render() {
        assert_eq!(
            parse(args(&["render", "a", "--locked", "all"])),
            Err(UsageError::UnexpectedArgument("--locked".into()))
        );
    }

    #[test]
    fn an_empty_run_url_is_no_link() {
        assert_eq!(
            parse(args(&[
                "render",
                "old.md",
                "report.txt",
                "body.md",
                "comment.md",
                "--run-url",
                ""
            ])),
            Ok(render_request(None))
        );
    }

    #[test]
    fn a_run_url_flag_without_its_value_is_an_error_naming_it() {
        assert_eq!(
            parse(args(&["render", "a", "b", "c", "d", "--run-url"])),
            Err(UsageError::MissingValue("--run-url"))
        );
    }

    #[test]
    fn help_as_a_flags_value_is_the_value() {
        assert_eq!(
            parse(args(&["check", "--config", "--help"])),
            Ok(Request::Check {
                config: Some(PathBuf::from("--help")),
                locked: Locked::Root
            })
        );
    }

    #[test]
    fn help_after_render_is_still_help() {
        assert_eq!(parse(args(&["render", "a", "--help"])), Ok(Request::Help));
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
            (UsageError::MissingArgument("COMMENT"), "COMMENT"),
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
