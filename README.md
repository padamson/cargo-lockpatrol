<!-- Replace "Project Name" with your project name. -->
# Project Name

<!-- Replace this line with a one-sentence description of your project. -->

<!--
Template users: after creating your repo from this template, see SETUP.md
for the full onboarding checklist. At minimum, replace every occurrence of
`my-project` and `Project Name` throughout this file, and update
`Cargo.toml` (name, description, repository, authors, keywords, categories).
-->

## Installation

<!-- Replace `my-project` with your crate name. -->
```bash
cargo install my-project
```

## Usage

<!-- Replace `my-project` with your binary name, or replace this section
     entirely with library usage examples if this is a library crate. -->
```bash
my-project --help
```

## Agent skill

<!-- Template users: keep this block if the crate ships a skill under
     `skills/`; delete it (and the skills/ directory) if not. SETUP.md has
     the checklist. -->
[![skills.sh](https://skills.sh/b/OWNER/REPO)](https://skills.sh/OWNER/REPO)

```bash
npx skills add OWNER/REPO
```

Works with [Claude Code](https://claude.ai/code),
[Codex](https://openai.com/codex/), [Cursor](https://cursor.com), and any
other [compatible agent](https://agentskills.io/clients). The install copies
the skill into your repo and records its source in `skills-lock.json`.

## Development

See [CLAUDE.md](CLAUDE.md) for development commands.

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (MSRV: 1.88)
- [prek](https://github.com/j178/prek) for pre-commit hooks: `cargo install prek && prek install`

### Build and test

```bash
cargo build
cargo nextest run
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
