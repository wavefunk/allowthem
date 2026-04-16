default:
    @just --list

# Build everything
build:
    cargo build --workspace

# Type-check without building
check:
    cargo check --workspace

# Run all tests
test:
    cargo test --workspace

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Format code
fmt:
    cargo fmt --all

# Watch for changes and check (uses bacon)
watch:
    bacon

# Run the standalone server
dev:
    cargo run -p allowthem

# Run SQLx migrations
migrate:
    cargo sqlx migrate run --source crates/core/migrations

# Create a new migration
migrate-new NAME:
    cargo sqlx migrate add -r {{NAME}} --source crates/core/migrations

# Regenerate .sqlx/ offline cache
sqlx-prepare:
    cargo sqlx prepare --workspace

# Build production CSS with Tailwind CLI (v4)
build-css:
    tailwindcss -i binaries/static/css/input.css -o binaries/static/css/style.css --minify

# Reset dev database
sqlx-reset:
    rm -f data/allowthem.db data/allowthem.db-wal data/allowthem.db-shm
    just migrate
