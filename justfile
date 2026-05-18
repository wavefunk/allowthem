default:
    @just --list

# Build everything
build:
    cargo build --workspace
    cargo build -p allowthem-server --features browser-templates
    cargo build -p allowthem --bin allowthem-saas --features saas-dashboard-templates

# Type-check without building
check:
    cargo check --workspace
    cargo check -p allowthem-server --features browser-templates
    cargo check -p allowthem --bin allowthem-saas --features saas-dashboard-templates

# Run all tests
test:
    cargo test --workspace
    cargo test -p allowthem-server --features browser-templates
    cargo test -p allowthem --bin allowthem-saas --features saas-dashboard-templates

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings
    cargo clippy -p allowthem-server --features browser-templates -- -D warnings
    cargo clippy -p allowthem --bin allowthem-saas --features saas-dashboard-templates -- -D warnings

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

# Build the documentation website
docs-build:
    cd website && eigen build

# Run the documentation website dev server
docs-dev:
    cd website && eigen dev --port 3001
