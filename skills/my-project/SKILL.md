---
name: my-project
description: Use when working with my-project — replace this line with the one-sentence trigger that tells an agent when to load this skill, naming the files, commands, or tasks that identify the situation.
license: MIT OR Apache-2.0
metadata:
  version: "0.1.1"
  internal: true
---

# my-project

<!--
Template users: this directory is the shape of a skill that
`npx skills add OWNER/REPO` would install into a consumer's repo. It is
scaffolding, not a skill: `metadata.internal: true` hides it from the
skills CLI, so nobody can install it from this repo, and nothing in this
repo loads it. SETUP.md "Agent skill" says how to ship it or delete it.

When you ship it: remove the `internal` line, write this file for an agent
that has never seen your crate (what it does, the two or three ways it is
used, the mistakes a first use makes), and put long reference material
(CLI surface, directive tables, API listings) under `references/`, linked
from here, so the body stays short enough to load on every trigger. Bump
`metadata.version` on every later content change; the pre-commit hook and
the `Skill version guard` CI job both refuse an edit that leaves it alone.
-->

## When to use

Describe the trigger conditions.

## How it works

Describe the crate's model in a few paragraphs, then link the details:

- [`references/usage.md`](references/usage.md): the API or CLI surface.
