# worktree-gc

`worktree-gc` triages and cleans stale Git worktrees.

It is conservative by default:

- the current worktree is never removed
- dirty worktrees are kept for a second pass
- detached worktrees are kept to preserve commit reachability
- tracked files inside generated directories prevent deletion
- cleanup writes a JSON manifest under the repository Git common dir before executing

## Usage

Install from source with Cargo:

```sh
cargo install --locked worktree-gc
```

After a version has been published to crates.io and its matching `vX.Y.Z`
GitHub release has completed, `cargo-binstall` can install the prebuilt binary:

```sh
cargo binstall worktree-gc
```

Run from a local checkout:

```sh
cargo run -- triage --repo /path/to/repo
cargo run -- cleanup --repo /path/to/repo
cargo run -- cleanup --repo /path/to/repo --execute
```

`triage` reports prunable metadata, dirty worktrees, stale clean worktree removal candidates, and generated directory cleanup candidates. `audit` is kept as an alias for `triage`.

By default, stale clean worktrees are removal candidates after 30 days, and generated directories are considered stale after 7 days:

```sh
cargo run -- triage --repo /path/to/repo --stale-days 45 --generated-days 14
```

Generated directory cleanup also considers recent worktree activity. When disk
is tight and you want rebuildable generated directories judged only by their own
activity, use `--generated-activity-only` with a shorter generated window:

```sh
cargo run -- cleanup --repo /path/to/repo --generated-days 3 --generated-activity-only --execute
```

Activity detection samples mtimes up to two levels deep inside each generated
directory, not just the directory itself. A build cache whose top-level mtime
is old but whose nested entries (`.next/cache/...`) are churning is treated as
active and kept.

Build caches are cheaper to rebuild than installs, so `.next`, `.turbo`, and
`target` default to a tighter 3-day window while other names use
`--generated-days`. Override any name's window explicitly with
`--generated-window NAME=DAYS`:

```sh
cargo run -- cleanup --repo /path/to/repo --generated-window .next=1 --generated-window node_modules=14
```

To also skip directories that a running process holds open (a live dev server
or package manager), add `--check-in-use`. The probe uses `lsof` on the
directory and its immediate children; on platforms without `lsof` it silently
degrades to mtime-only judgment:

```sh
cargo run -- cleanup --repo /path/to/repo --generated-activity-only --check-in-use --execute
```

Generated directory defaults are:

- delete candidates: `node_modules`, `.next`, `.turbo`, `target`
- report-only candidates: `dist`

You can add repo-specific generated directory names:

```sh
cargo run -- triage --repo /path/to/repo --delete-generated coverage,.cache --report-generated build
```

Or start from an empty generated-directory policy:

```sh
cargo run -- triage --repo /path/to/repo --no-default-generated --delete-generated coverage
```

## Releases

The first crate version must be published manually. After that, configure
crates.io Trusted Publishing for this repository:

- repository owner: `wycats`
- repository name: `worktree-gc`
- workflow filename: `publish.yml`
- environment: `release`

Once trusted publishing is configured, bumping `package.version` on `main`
publishes that version to crates.io automatically. The publish workflow skips
Cargo metadata-only changes when the version is unchanged, and also skips a
version that is already present on crates.io.

After a successful publish, the workflow creates and pushes the matching Git
tag, such as:

```sh
v0.1.0
```

That tag triggers the release workflow, which builds Linux, macOS, and Windows
archives for GitHub Releases.

The release workflow builds Linux, macOS, and Windows archives using
`cargo-binstall`'s default GitHub release layout, with asset names like
`worktree-gc-x86_64-unknown-linux-gnu-v0.1.0.tgz`.
