# wavefunk-ui Template Migration Readiness

Date: 2026-05-17

This is the pre-migration gap list for replacing AllowThem's shipped UI
templates with typed Askama components from the `wavefunk-ui` crate.

The local checkout at `/home/nambiar/projects/wavefunk/ui` is the canonical
truth for this audit. It is version `0.1.2` at commit `769a7ba`, and that is
the API/assets baseline this list uses.

The dependency shape should stay release-safe while still using that local
checkout during development:

- Manifests depend on `wavefunk-ui = "0.1.2"` through workspace dependencies.
- Local development overrides the crate with `.cargo/config.toml`:
  `paths = ["../ui"]`.
- `.cargo/config.toml` is ignored so local path overrides do not leak into
  release or consumer manifests.

## Audit Scope

AllowThem UI surfaces currently reviewed:

- Core embedded/hosted auth templates in `crates/server/templates/`.
- Standalone admin templates in `binaries/standalone/templates/`.
- SaaS dashboard templates in `binaries/saas/dashboard/templates/`.
- Website/docs templates in `website/templates/`, treated as lower-priority
  unless the migration explicitly includes the docs site.

The local `wavefunk-ui` checkout's coverage is broad for generic primitives:
app shell,
buttons, alerts, badges, tags, form controls, form sections, repeatable arrays,
tables, data tables, filter bars, pagination, panels, definition lists,
breadcrumbs, page headers, tabs, menus, modals, drawers, toasts, minibuffer,
cards, grids, marketing sections, and static asset helpers.

A class inventory found 104 `wf-*` classes shared between AllowThem templates
and `wavefunk-ui`, and 47 AllowThem classes not present in the current
`wavefunk-ui` checkout. That is a signal, not a migration contract: some of
the 47 are legacy aliases that should be rewritten to existing components.

## Component Boundary

The migration should keep a clean product boundary:

- `wavefunk-ui` owns generic UI primitives and reusable Wave Funk patterns:
  shells, navigation, form controls, table/list machinery, status chrome,
  overlays, feedback, asset helpers, and small interaction hooks.
- AllowThem owns auth-specific composition, domain view models, copy, routing,
  policy decisions, and unique screens such as login, consent, MFA, tenant
  settings, and admin workflows.
- A component belongs in `wavefunk-ui` only when another Wave Funk product
  could plausibly use it without depending on AllowThem's auth concepts.
- If a pattern is generic but the current need is auth-flavored, add the
  generic primitive to `wavefunk-ui` and compose the AllowThem-specific
  version inside AllowThem.

## Missing or Blocking Pieces

### 1. Auth Shell Components

Needed for: `login`, `register`, password reset, MFA setup/challenge/recovery,
consent, invite/signup pages.

Existing coverage: `wavefunk-ui` has auth CSS (`wf-auth`, `wf-auth-form`,
`wf-auth-splash`, `wf-auth-top`, `wf-auth-wrap`) and generic form/button/alert
components.

Generic additions to consider in `wavefunk-ui`:

- Split/form shell primitives with splash slot, form/content slot, forced-mode
  attrs, and configurable asset base path.
- A reusable narrow form panel for the repeated right-column structure.
- Generic tab, provider-button-grid, and legal/footer helpers if they can be
  named without auth-specific concepts.
- HTMX-aware link/trigger attributes without requiring raw HTML in every
  consumer template.

AllowThem-owned composition:

- The login/register/password/MFA/consent page structs, copy, routes, OAuth
  provider semantics, and terms/privacy policy choices.

### 2. Branded Splash Runtime

Needed for: `_partials/_splash.html` and branded hosted login pages.

Existing coverage: `wavefunk-ui` has `.wf-auth-splash` and `.wf-ascii` CSS.

Generic additions to consider in `wavefunk-ui`:

- Typed split-panel splash or media panel component for iframe, image,
  primitive, and text modes.
- Runtime support for `canvas[data-shader-ascii]`, or a deliberate decision
  that AllowThem owns this as an app-specific add-on.
- Asset wiring for the current `shader-ascii.js` behavior if it moves into
  `wavefunk-ui`.

AllowThem-owned composition:

- Branding precedence, hosted-login splash defaults, and app-name fallback
  choices.

### 3. Mode-Aware App Shell

Needed for: standalone admin pages, user settings, and SaaS dashboard pages.

Existing coverage: `AppShell`, `SidebarProfile`, `NavSection`, `NavItem`,
`Topbar`, `PageHeader`, `Breadcrumbs`, `Statusbar`, and asset helpers.

Generic additions to consider in `wavefunk-ui`:

- App shell slots or configuration for `html` attrs such as `data-mode` and
  `data-mode-locked`.
- Brand link support. AllowThem's sidebar brand is an anchor, not only text.
- Main layout modifiers such as `has-header` and `has-tablewrap`.
- Page header slots that match AllowThem's current `pagetitle`, `crumbs`,
  `page_meta`, and `topbar` block contract.
- A footer layout that can render modeline plus minibuffer instead of the
  current single `Statusbar`.

AllowThem-owned composition:

- Which sidebar items appear for each role, the exact page hierarchy, and
  route-specific shell context.

### 4. Modeline Component

Needed for: `_partials/_modeline.html` across auth and app shells.

Existing coverage: `Minibuffer` and `MinibufferEcho` exist; modeline CSS exists.

Generic additions to consider in `wavefunk-ui`:

- `Modeline` and `ModelineSegment` typed components.
- Optional logout/action segment support.
- Mode-toggle segment support, including the `[data-mode-toggle]` contract.
- Minibuffer history rendering parity if AllowThem keeps the hover history.

AllowThem-owned composition:

- Segment labels such as `AT`, session/logout behavior, and auth environment
  status text.

### 5. Workspace Switcher and Dashboard Side Nav

Needed for: SaaS dashboard tenant navigation.

Existing coverage: `NavSection` and `NavItem` cover simple app navigation.

Generic additions to consider in `wavefunk-ui`:

- A generic workspace/project switcher for `<details>`-style sidebar switching.
- `Sidenav`, `SidenavSection`, and `SidenavItem` for the current
  `wf-sidenav-*` structure, including muted and coming-soon states.

AllowThem-owned composition:

- Tenant/workspace role labels, tenant route construction, and permission-based
  nav filtering.

### 6. Auth and CRUD Form Patterns

Needed for: application forms, role/permission forms, signup/custom fields,
settings forms, and invite forms.

Existing coverage: `Form`, `Field`, `Input`, `Textarea`, `Select`, `CheckRow`,
`Switch`, `FormSection`, `FormActions`, `RepeatableArray`, `RepeatableItem`,
and `InlineFormRow`.

Generic additions or migration decisions:

- Replace legacy `wf-formfield` and `wf-form-row` markup with existing typed
  components, or add compatibility aliases if preserving old markup matters.
- A password-strength component for the current `wf-pw-*` meter.
- Repeatable redirect URI controls can probably use existing repeatable
  components, but the add/remove behavior needs a runtime decision.

AllowThem-owned composition:

- Dynamic custom-field rendering, field schema interpretation, redirect URI
  validation, and form copy.

### 7. Consent and Security-Specific Displays

Needed for: OAuth consent, MFA recovery codes, API credentials, and secret
panels.

Existing coverage: `Framed`, `DefinitionList`, `CopyableValue`,
`CredentialStatusList`, `CurrentUpload`, `Kbd`, `Alert`, `Tag`, and `Panel`.

Generic additions or migration decisions:

- A generic check-list display that AllowThem can use for OAuth scopes.
- A first-class secret/credential reveal or copy pattern if the current
  application secret panel should be reusable outside AllowThem.
- Recovery-code grid/list styling if MFA recovery remains a generic auth UI
  pattern.

AllowThem-owned composition:

- OAuth consent semantics, credential labels, recovery-code lifecycle, and
  security copy.

### 8. Table, Filter, and Pager Compatibility

Needed for: admin users/sessions/audit/applications and SaaS lists.

Existing coverage: `DataTable`, `Table`, `TableWrap`, `FilterBar`,
`BulkActionBar`, `TableFooter`, `RowSelect`, and `Pagination`.

Missing additions or migration decisions:

- The old `wf-pager*`, `wf-filter-form`, and `wf-tablefoot` markup should
  migrate to existing components rather than drive new API unless exact class
  compatibility is required.
- A composite "resource index" helper could reduce repeated list pages, but it
  is not required before the migration starts.

### 9. Link and Legacy Alias Cleanup

Needed for: broad template cleanup.

Existing coverage: buttons and nav components handle most links.

Missing additions or migration decisions:

- AllowThem uses `wf-link`, `wf-link-quiet`, `wf-btn-primary`, `wf-flash`,
  `wf-flash-warn`, `wf-bar`, `wf-help`, `wf-hint`, and `wf-muted`.
- These should usually be migrated to existing `Button`, `Alert`, `Field`,
  `Tag`, `Badge`, and utility classes.
- Add `wavefunk-ui` aliases only if preserving old rendered HTML is a hard
  backwards-compatibility requirement.

### 10. Docs and Marketing Components

Needed for: `website/templates/`, if the docs website is in migration scope.

Existing coverage: CSS exists for marketing hero, marketing nav, docs shell,
docs side nav, prose, footer, cards, grids, and marketing sections.

Missing additions:

- `MarketingNav` and `MarketingFooter`.
- `DocsShell`, `DocsSidebar`, `DocsTocHost`, and `DocsPager`.
- A typed prose page wrapper. This can wait if the docs site stays on Eigen
  templates during the auth/admin migration.

## Suggested Migration Order

1. Keep the new dependency and local override in place, then smoke-test that
   `wavefunk-ui` assets can be mounted under AllowThem's static prefix.
2. Add only the generic auth-adjacent primitives to `wavefunk-ui`.
3. Add app shell/modeline/workspace navigation primitives to `wavefunk-ui`.
4. Compose AllowThem-specific auth templates from those primitives as Askama
   structs.
5. Migrate standalone admin and SaaS dashboard table/form pages.
6. Decide separately whether the docs website joins this migration.

## Open Questions

- Is the docs/marketing website part of "actual UI templates", or should this
  migration focus on hosted auth, admin, and SaaS dashboard screens first?
- Should the shader splash runtime live in `wavefunk-ui`, or should AllowThem
  keep it as an app-specific branded login extension?
- Do integrators still need MiniJinja template override compatibility after
  the default AllowThem templates move to Askama?
