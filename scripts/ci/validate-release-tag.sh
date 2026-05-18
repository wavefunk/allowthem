#!/usr/bin/env sh
set -eu

tag="${CI_COMMIT_TAG:-}"
if [ -z "$tag" ]; then
    case "${CI_COMMIT_REF:-}" in
        refs/tags/*) tag="${CI_COMMIT_REF#refs/tags/}" ;;
    esac
fi
if [ -z "$tag" ] && [ "$#" -gt 0 ]; then
    tag="$1"
fi

case "$tag" in
    v*) ;;
    *)
        echo "Release pipeline only accepts v* tags; got '${tag:-<empty>}'" >&2
        exit 1
        ;;
esac

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

expected_tag="v$version"
if [ "$tag" != "$expected_tag" ]; then
    echo "Tag $tag does not match Cargo.toml workspace version $expected_tag" >&2
    exit 1
fi

mkdir -p target/release-upload
{
    echo "RELEASE_TAG=$tag"
    echo "RELEASE_VERSION=$version"
    echo "PUBLISH_PACKAGES=${ALLOWTHEM_PUBLISH_PACKAGES:-allowthem-core allowthem-client allowthem-teams allowthem-saas allowthem-server}"
} > target/release-upload/release.env

echo "Validated release tag $tag for workspace package version $version"
