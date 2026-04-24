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
    cargo run -p allowthem --bin allowthem

# Run SQLx migrations
migrate:
    cargo sqlx migrate run --source crates/core/migrations

# Create a new migration
migrate-new NAME:
    cargo sqlx migrate add -r {{NAME}} --source crates/core/migrations

# Regenerate .sqlx/ offline cache
sqlx-prepare:
    cargo sqlx prepare --workspace

# Reset dev database
sqlx-reset:
    rm -f data/allowthem.db data/allowthem.db-wal data/allowthem.db-shm
    just migrate

# Run Playwright e2e tests
test-e2e:
    cd tests/e2e && npx playwright test

# Run Playwright e2e across chromium, firefox, webkit (manual; no CI)
test-e2e-all-browsers:
    cd tests/e2e && npx playwright test --project=main --project=firefox --project=webkit
