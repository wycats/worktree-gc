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
cargo install worktree-gc
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

Release builds are produced by GitHub Actions when a tag matching the package
version is pushed:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds Linux, macOS, and Windows archives using
`cargo-binstall`'s default GitHub release layout, with asset names like
`worktree-gc-x86_64-unknown-linux-gnu-v0.1.0.tgz`.
