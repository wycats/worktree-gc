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

`worktree-gc` requires Rust 1.89 or newer.

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

Use repeatable `--root` options to discover and clean every repository under
one or more directory trees:

```sh
cargo run -- cleanup \\
  --root /path/to/code \\
  --root /path/to/another/repository
```

Discovery stops descending when it reaches a Git repository, skips generated
directories and materialized backups, and deduplicates linked worktrees by
their Git common directory. Each owning repository contributes all of its
linked worktrees, including worktrees located outside the discovery roots.
`--root` and the single-repository `--repo` mode are mutually exclusive.
Multi-root cleanup writes the ordinary per-repository manifests plus an
aggregate manifest under `$XDG_STATE_HOME/worktree-gc` or
`~/.local/state/worktree-gc`.

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

Activity detection samples mtimes up to six levels deep inside each generated
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

Active Rust `target` directories receive a built-in incremental-cache sweep
during ordinary cleanup planning. They also receive an atomic profile-reset
pass. Rustc incremental roots with no session activity for 14 days are
selected for in-place pruning; host Cargo profiles such as `debug` and
`release` that have been inactive for 7 days are reset as a unit while holding
their Cargo profile locks. A whole `target` directory that has been inactive for
3 days remains a wholesale deletion candidate. The dry run records every
incremental root and Cargo profile, including its path, newest activity, age,
and planned action.

Override the built-in incremental window with an explicit strategy:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=rustc-incremental:7 --execute
```

Override the Cargo profile window independently:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=cargo-profile-reset:14 --execute
```

Profile reset deliberately works at Cargo's profile boundary instead
of interpreting private fingerprint JSON or reconstructing artifact hashes.
This reclaims the profile's `deps`, `.fingerprint`, `build`, and incremental
outputs together while preserving other profiles. Cross-target profiles are
reported and retained until Cargo exposes enough stable invocation metadata to
map their output directory back to the exact target specification.

Before pruning, `worktree-gc` verifies the directory against `cargo metadata`
and leaves shared or external build directories untouched. Execution waits for
Cargo's profile lock, rechecks activity, atomically moves the stale profile into a
tool-owned quarantine, releases the lock, and then deletes the quarantine. A
later execution recovers quarantine left by an interrupted run.

The legacy `cargo-sweep` backend remains available as an additional explicit
strategy for fingerprint-associated outputs. It can prune by age or keep an
active target within a size budget:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=cargo-sweep:3 --execute
cargo run -- cleanup --repo /path/to/repo --sweep target=cargo-sweep:max-size=50GB --execute
```

When multiple strategies are configured, the built-in incremental sweep runs
first, followed by Cargo profile reset and then the legacy backend.
`cargo-sweep` intentionally leaves rustc's `incremental/` cache
directories alone and requires `cargo-sweep` on `PATH`
(`cargo install cargo-sweep`). Before invoking it, `worktree-gc` verifies the
Cargo build directory and waits until it holds every existing host and
cross-target profile lock. If the external command cannot run, an error is
reported for the directory and cleanup continues.

Use `--no-default-sweeps` to retain the generated-directory defaults without
the built-in incremental sweep. `--no-default-generated` starts from an empty
generated-directory policy and also disables default sweeps. Explicit
`--sweep` entries remain available with either flag.

Generated directory defaults are:

- delete candidates: `node_modules`, `.next`, `.turbo`, `target`
- report-only candidates: `dist`
- in-place sweeps: `target=rustc-incremental:14`
- Atomic Cargo profile reset: `target=cargo-profile-reset:7`

You can add repo-specific generated directory names:

```sh
cargo run -- triage --repo /path/to/repo --delete-generated coverage,.cache --report-generated build
```

Or start from an empty generated-directory policy:

```sh
cargo run -- triage --repo /path/to/repo --no-default-generated --delete-generated coverage
```

## Storage inventory

Use `inventory` to find the directories that account for a root's disk usage
before deciding which domain-specific cleanup policy should own them:

```sh
worktree-gc inventory ~/Code ~/.codex --depth 2 --top 20
worktree-gc inventory ~/Library/Application\ Support --depth 1 --json > inventory.json
worktree-gc inventory ~/Library/Application\ Support/local-sandbox/vfkit/base.img --json
```

Directory roots are visited once and retain only the requested shallow
aggregates, so `--depth` controls report detail rather than making totals
partial. Exact file roots are measured directly without enumerating their
parent directory, which makes indexed large-file results cheap to verify.
`--top` keeps the largest children beneath each displayed directory.
`--max-entries` (default 2,000,000 across all requested roots) is a hard work
bound; a report says `incomplete` if it reaches that limit. Traversal stays on
each root's filesystem unless `--cross-filesystems` is explicit, never follows
symlinks, and deduplicates hard-linked files.

On macOS, directory enumeration and file accounting use `getattrlistbulk`;
exact file roots use `getattrlist`.
Alongside logical and allocated size, APFS reports
`ATTR_CMNEXT_PRIVATESIZE` as `private_reclaimable_bytes`: a conservative floor
for space immediately private to the visited files. APFS clones can share
extents, so deleting an entire clone family can reclaim more than this floor;
ordinary path allocation can substantially overstate the space freed by
deleting only one clone or one pnpm-linked dependency tree. Other platforms
report logical and allocated bytes and mark private-byte accounting incomplete.

Inventory is read-only and deliberately separate from scheduled cleanup in
this first version. Its structured output is the evidence surface for adding
domain collectors and, later, cached physical-reclaim estimates to pressure
ordering without turning scheduled runs into broad recursive scans.
For multi-root scans, the global entry budget is divided fairly across the
remaining roots and unused shares flow forward, so one large tree cannot hide
every later storage domain. Within a root, queued sibling directories share the
remaining root budget for the same reason: a wide early subtree is reported as
incomplete instead of hiding every later sibling.
The durable collector contract and incremental delivery order are documented
in [`STORAGE.md`](STORAGE.md).

## Expiring protections

Use an expiring protection when a worktree or cache is intentionally idle but
still belongs to active work:

```sh
worktree-gc protect add /path/to/worktree --ttl 7d --reason "release rehearsal"
worktree-gc protect list
worktree-gc protect renew p-0123456789abcdef --ttl 7d
worktree-gc protect remove p-0123456789abcdef
```

Protections are recursive. Protecting a worktree also protects generated
directories and Cargo sweeps below it; protecting a generated directory keeps
an enclosing worktree from being removed. The default TTL is 7 days, and a
single lease is capped at 30 days so forgotten protections expire. Renew a
lease when the underlying intent is still active.

The registry is stored atomically at
`$XDG_STATE_HOME/worktree-gc/protections.json` (or
`~/.local/state/worktree-gc/protections.json`). Active protections and their
expiry are included in cleanup manifests. Cleanup reloads the registry before
each deletion or sweep and holds the registry lock through that mutation. A
protection created after planning but before the mutation lock is acquired
takes precedence; a concurrent `protect add` waits for an operation that has
already started.

## Scheduled cleanup

`worktree-gc scheduled` reads its roots and cleanup policy from
`$XDG_CONFIG_HOME/worktree-gc/config.toml` or
`~/.config/worktree-gc/config.toml`. Scheduled mode executes cleanup by
default; use `--dry-run` when validating a new configuration.

```toml
roots = [
  "/Users/me/Code",
  "/Users/me/Documents/sandboxd",
  "/Users/me/plugins",
]

[cleanup]
stale_days = 14
generated_days = 7
# Per-directory entries override generated_days and any tighter built-in window.
generated_windows = { ".next" = 7, ".turbo" = 7, target = 7, node_modules = 7 }
generated_activity_only = true
check_in_use = true
cargo_lock_timeout_minutes = 30
# Requires cargo-sweep; omit to use only the built-in Cargo sweeps.
cargo_sweep_max_size = "50GB"

[pressure]
# Optional hysteresis controller. Routine TTL cleanup still runs above this.
enter_free_space = "100GiB"
target_free_space = "150GiB"
generated_days = 1
stale_days = 7

[history]
retention_days = 90
repository_refresh_days = 7
```

`generated_windows` has the same meaning as repeated CLI
`--generated-window NAME=DAYS` arguments and applies to any configured generated
directory name. Build caches (`.next`, `.turbo`, and `target`) otherwise use a
tighter built-in window; other names use `generated_days`.

The Cargo lock timeout applies to each generated `target` directory. A
contended target is deferred to a later run, recorded under
`$XDG_STATE_HOME/worktree-gc/inbox` (or
`~/.local/state/worktree-gc/inbox`), and does not prevent the remaining
worktrees from being cleaned.

When `[pressure]` is configured, a scheduled run enters pressure mode when any
configured root has less than `enter_free_space` available. It continues
reclaiming pressure-only candidates until their filesystem reaches
`target_free_space`, which provides hysteresis instead of repeatedly crossing a
single threshold. Routine TTL candidates still run regardless of free space.

Pressure mode lowers generated-directory and clean-worktree windows to the
configured values. Dirty, detached, current, tracked, open, and explicitly
protected content keeps the same safety rules. Rebuildable directories are
ordered by expected rebuild cost (`.turbo`, `.next`, `target`, then
`node_modules`) across all repositories. Inside each rebuild-cost class, the
controller prefers the largest conservative APFS-private reclaim, then the
largest observed allocation, then the oldest activity. It refreshes and
executes one exact candidate at a time; clean worktrees come last.
The aggregate manifest records the policy, initial free-space observations,
which decisions exist only because of pressure, and final free space after an
executing run. Generated delete decisions also record logical, allocated, and
APFS-private bytes, filesystem identity, evidence time, entries visited, and
whether the measurement completed. One sequential two-million-entry budget is
shared across the entire initial plan, with at most 250,000 entries spent on
one candidate, so very large candidate sets remain bounded, fair, and visibly
partial. The controller checks live filesystem
availability after each deletion and stops once the target is reached.

Each scheduled run writes the normal per-repository manifests and a structured
aggregate manifest. Aggregate manifests are retained for the configured
history window. Query them with:

```sh
worktree-gc history
worktree-gc inbox
```

The inbox reports deferred Cargo sweeps, old dirty worktrees, and generated
directories protected by open handles or tracked files. It is intentionally a
review surface; cleanup decisions remain manifest-driven.

Repository discovery uses `.git` markers while pruning generated trees, then
caches the owning-repository index for `repository_refresh_days`. Use
`worktree-gc scheduled --refresh-repositories --dry-run` after adding or moving
repositories when you want the index refreshed immediately. Generated
directory discovery uses Git's index and collapsed ignored/untracked directory
views; it does not recursively stat every file in a worktree.

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
