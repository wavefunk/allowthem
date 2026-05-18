#!/usr/bin/env sh
set -eu

packages="${ALLOWTHEM_PUBLISH_PACKAGES:-allowthem-core allowthem-client allowthem-teams allowthem-saas allowthem-server}"
dry_run="${PUBLISH_CRATES_DRY_RUN:-false}"
allow_dirty="${PUBLISH_CRATES_ALLOW_DIRTY:-false}"
retry_count="${PUBLISH_CRATES_RETRY_COUNT:-5}"
retry_delay_seconds="${PUBLISH_CRATES_RETRY_DELAY_SECONDS:-30}"

version="$(
    awk '
        /^\[workspace\.package\]/ { in_workspace_package = 1; next }
        /^\[/ { in_workspace_package = 0 }
        in_workspace_package && $1 == "version" {
            gsub(/"/, "", $3)
            print $3
            exit
        }
    ' Cargo.toml
)"

workspace_dependency_version() {
    dependency="$1"
    awk -v dependency="$dependency" '
        /^\[workspace\.dependencies\]/ { in_workspace_dependencies = 1; next }
        /^\[/ { in_workspace_dependencies = 0 }
        in_workspace_dependencies && $1 == dependency {
            line = $0
            sub(/.*version[[:space:]]*=[[:space:]]*"/, "", line)
            sub(/".*/, "", line)
            print line
            exit
        }
    ' Cargo.toml
}

if [ -z "$version" ]; then
    echo "Could not read [workspace.package] version from Cargo.toml" >&2
    exit 1
fi

for dependency in allowthem-core allowthem-saas allowthem-server; do
    dependency_version="$(workspace_dependency_version "$dependency")"

    if [ -z "$dependency_version" ]; then
        echo "Could not read [workspace.dependencies] version for $dependency" >&2
        exit 1
    fi

    if [ "$dependency_version" != "$version" ]; then
        echo "[workspace.dependencies] $dependency version $dependency_version does not match workspace package version $version" >&2
        exit 1
    fi
done

tag="${RELEASE_TAG:-${CI_COMMIT_TAG:-}}"
if [ -z "$tag" ]; then
    case "${CI_COMMIT_REF:-}" in
        refs/tags/*) tag="${CI_COMMIT_REF#refs/tags/}" ;;
    esac
fi

expected_tag="v$version"
if [ "$tag" != "$expected_tag" ]; then
    echo "Release tag ${tag:-<empty>} does not match Cargo.toml workspace version $version; expected $expected_tag" >&2
    exit 1
fi

if [ "$dry_run" != "true" ] && [ -z "${CARGO_REGISTRY_TOKEN:-}" ]; then
    echo "CARGO_REGISTRY_TOKEN is required to publish to crates.io" >&2
    exit 1
fi

for package in $packages; do
    package_version="$(cargo pkgid -p "$package" | sed 's/.*@//')"
    if [ "$package_version" != "$version" ]; then
        echo "Package $package has version $package_version; expected workspace version $version" >&2
        exit 1
    fi
done

publish_package() {
    package="$1"
    attempt=1

    while :; do
        set -- -p "$package" --locked
        if [ "$dry_run" = "true" ]; then
            set -- "$@" --dry-run
        fi
        if [ "$allow_dirty" = "true" ]; then
            set -- "$@" --allow-dirty
        fi

        if cargo publish "$@"; then
            return 0
        fi

        if [ "$dry_run" = "true" ] || [ "$attempt" -ge "$retry_count" ]; then
            return 1
        fi

        echo "Publishing $package failed; retrying in ${retry_delay_seconds}s ($attempt/$retry_count)" >&2
        sleep "$retry_delay_seconds"
        attempt=$((attempt + 1))
    done
}

for package in $packages; do
    publish_package "$package"
done
