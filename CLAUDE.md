# Project Overview : allowthem
An embeddable authentication system. Can be used as a library (where the integrator controls tables, data, and configuration) or as a standalone service with its own frontend and auth endpoints.

## Tech Stack
Web framework = Axum
Database = SQLite via SQLx
Async runtime = Tokio

## Local development

Nix, direnv and flake to manage local dev environment
just to run often used commands

## Work Structure
Always create a plan,
then review the plan,
then apply the reviews to the plan,
then create an implementation plan,
review the implementation plan
then apply the implentation reviews
AND then actually start writing code.

Always create a git branch for the work.
Create atomic commits for coherent work done.
Branch does not get merged unless the feature has tests that are passing.
Integration tests (if required, not mandatory) should be in rust as well.

## Planning Style
- Small milestones - never more than 5-10 tasks per milestone.
- use `bd` for task tracking

## Code Style

- Idiotmatic rust code
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

## Available commands
The just file has available commands. Be mindful of commands that you run often, add it to the justfile. Adjust the justfile to match commands that you use often.
