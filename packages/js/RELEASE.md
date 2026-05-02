# Releasing @allowthem/js

Maintainer ritual for the JS package. **Not** included in the published
tarball (excluded via `.npmignore`; not in `files`).

1. **On a clean checkout of the release commit:**
   - Bump `version` in `packages/js/package.json`.
   - Move the `[Unreleased]` entry to a dated release section in
     `packages/js/CHANGELOG.md` and replace the `2026-05-XX` placeholder
     with the publish date.
   - Commit: `chore(js): release vX.Y.Z`.

2. **From `packages/js/`:**
   ```sh
   npm ci
   npm run typecheck
   npm test
   npm run build
   npm run size
   npm publish        # 2FA prompt
   ```

   `prepublishOnly` runs build + tests one more time as a safety net
   before the registry sees anything.

3. **Tag the release:**
   ```sh
   git tag js-vX.Y.Z
   git push origin js-vX.Y.Z
   ```

4. **Verify on npmjs.com** that the package shows the new version and
   the tarball contains `dist/`, `README.md`, `CHANGELOG.md`, and
   `LICENSE` (no source files, no tests).

## v2 follow-up — CI publish + provenance

When the GitHub Actions release workflow lands, set
`publishConfig.provenance: true` in `package.json` in the same change.
Manual `npm publish` will fail after that (no OIDC env outside CI), so
the workflow becomes the only publish path. Until then, keep
`provenance` unset.

## Self-import troubleshooting

`npm test` uses `npm link` to make `import "@allowthem/js"` resolve to
the local build. If a fresh clone fails with `Cannot find module
'@allowthem/js'`, run `npm link && npm link @allowthem/js` once from
`packages/js/`.
