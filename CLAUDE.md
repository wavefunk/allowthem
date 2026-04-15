# Project Overview : allowthem
An embeddable authentication system for all wavefunk projects (speakwith, immersiq, substrukt, is-still-online, transfer-these-files, sendword). Can be used as a library (where the integrator controls tables, data, and configuration) or as a standalone service with its own frontend and auth endpoints. Consuming projects code against an `AuthClient` trait so they can flip between embedded and external mode without code changes.

## Tech Stack
Web framework = Axum
Database = SQLite via SQLx
Async runtime = Tokio
Rust toolchain = nightly-2026-01-05 (pinned in rust-toolchain.toml)

## Local development

Nix, direnv and flake to manage local dev environment
just to run often used commands
Migrations live in `crates/core/migrations/`. Run `just sqlx-prepare` after changing queries to update the .sqlx/ offline cache.

## Commits
Do not add Co-Authored-By or any Claude/AI attribution to commit messages.

## Work Structure
1. Create a plan
2. Review the plan
3. Apply review feedback
4. Create an implementation plan
5. Review the implementation plan
6. Apply implementation review feedback
7. Write code

Always create a git branch for the work.
Create atomic commits for coherent work done.
Branch does not get merged unless the feature has tests that are passing.
Integration tests (if required, not mandatory) should be in rust as well.

## Planning Style
- Small milestones - never more than 5-10 tasks per milestone.
- Use `bd` for task tracking. Run `bd ready` to find available work.
- Plan and implement each task separately — don't batch planning across milestones.
- Design spec: `docs/superpowers/specs/2026-03-19-allowthem-design.md`

## Code Style

- Idiomatic rust code
- Workspace isolation of responsibilities.
- Optimized for readability first
- Avoid long format!() chains and other allocations. Be memory efficient.
- Write tests immediately after a feature.
- Do not write "ceremony" tests that actually just test the library being used.
- Do not use unwrap or expect unless its an invariant.
- Read the docs for the libraries to plan the implementation.
- The crates folders within the project are NOT prefixed with allowthem-, but the package names are. The path in the crate is always to the name of the folder.. so crates/core/core.rs is the main file, and Cargo.toml reflects that with `[lib] path = "./core.rs"`

## Repository Structure
allowthem/
├── crates/
│   ├── core/              # Core types, database, auth logic
│   ├── server/            # HTTP server, routes, middleware, extractors
├── binaries/              # Standalone server binary
├── docs/                  # Design specs and documentation
├── justfile               # commonly used local dev commands
├── .dir-locals.el         # emacs environment controls
├── flake.nix              # local devshell flake
├── rust-toolchain.toml    # current rust toolchain version and components
├── sqlx.toml              # sqlx configuration
└── CLAUDE.md

## Key Architecture Decisions
- **AuthClient trait**: Consuming projects use this trait, not AllowThem handle directly. Enables embedded-to-external mode switch via config flag.
- **Login is mode-aware**: Embedded mode renders own login form + direct call. External mode redirects to OIDC. Login is NOT part of the AuthClient trait (security: external mode never handles passwords).
- **JWT validation for external mode**: RS256 tokens validated locally via JWKS. No round-trip per request.
- **Table prefix**: `allowthem_` prefix in embedded mode (configurable). No prefix in standalone mode.

## Commands
```
just build        # cargo build --workspace
just check        # cargo check --workspace
just test         # cargo test --workspace
just clippy       # cargo clippy --workspace -- -D warnings
just fmt          # cargo fmt --all
just watch        # bacon (watch mode)
just dev          # run standalone server
just migrate      # run SQLx migrations
just migrate-new NAME  # create new migration
just sqlx-prepare # regenerate .sqlx/ offline cache
just sqlx-reset   # delete dev DB and re-migrate
```
Add frequently used commands to the justfile.
