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

Manual `triage` and `cleanup` scans default to one worker. Use
`--max-parallelism N` when an interactive scan may trade more CPU for lower
elapsed time. The limit covers nested repository, worktree, and generated-root
planning; root discovery passes the same bound to ripgrep.

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
`release` that have been inactive for 3 workdays are reset as a unit while
holding their Cargo profile locks. Workdays use the machine's local calendar,
exclude Saturdays and Sundays, and currently do not exclude holidays. Scheduled
cleanup also treats a whole `target` directory as a wholesale deletion candidate
after 3 workdays; explicit CLI day windows retain elapsed-day meaning. The dry
run records every incremental root and Cargo profile, including its path, newest
activity, age, and planned action. Cargo profile records include the timezone,
local activity and observation dates, UTC offsets, workday-calendar identifier,
and both elapsed- and workday-age evidence so a reviewed decision can be
reproduced.

Override the built-in incremental window with an explicit strategy:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=rustc-incremental:7 --execute
```

Override the Cargo profile window independently. The `wd` suffix selects the
workday calendar; a bare number retains the existing elapsed-day meaning:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=cargo-profile-reset:5wd --execute
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
- atomic Cargo profile reset: `target=cargo-profile-reset:3wd`

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
symlinks, and deduplicates hard-linked files. Fair resumption keeps wide trees
from monopolizing the budget, while a fixed live-reader cap prevents resumable
directory cursors from exhausting process file descriptors.

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

### Generated build-state inventory

Use the report-only `generated` collector when a broad inventory shows that
repository storage is large but does not explain how much belongs to
rebuildable state:

```sh
worktree-gc collect generated --discover-under ~/Code --max-entries 2000000
```

The collector discovers Git repositories below each explicit
`--discover-under` root and then expands their linked worktrees with one worker.
Exact repository or worktree paths may instead be passed positionally. It
takes one machine-wide open-handle snapshot using `lsof`, and reuses cleanup's
tracked-file, ignore, activity, and recursive-protection classification. It
then APFS-measures each discovered `target`, `.next`, `.turbo`, `node_modules`,
and report-only `dist` root under one fair global entry budget.

Measurement is retained even when a root is active or protected because size
evidence is not deletion permission. The manifest separately reports
**rebuildable-now opportunities**: configured roots with no tracked files,
recursive protection, or open owner and a complete handle snapshot. These are
not described as stale. They are explicit rebuild trades grouped into low
(`.next`, `.turbo`), medium (`target`), and high (`node_modules` and other)
cost tiers, with a cumulative APFS-private reclaim floor per filesystem.
Incomplete ownership evidence fails closed. The collector remains report-only;
run a fresh `cleanup` dry-run before proposing any mutation.

The collector also records the scheduled three-workday retention window for
`target`, `.next`, and `.turbo`, including timezone/calendar evidence.
`--generated-days` retains elapsed-day meaning for other artifact classes.

## pnpm shared-store collection

The first machine-wide owner collector wraps pnpm's maintained prune operation.
A plain invocation is read-only:

```sh
worktree-gc collect pnpm
worktree-gc collect pnpm --dlx-days 7 --max-entries 2000000 --scan-threads 1
worktree-gc collect pnpm --fresh --max-entries 2000000
```

The collector asks pnpm for its canonical store, resolves pnpm's cache, and
records a bounded advisory estimate of content, metadata, temporary, and
expired/orphaned dlx surfaces maintained by `pnpm store prune`. The estimate is
not deletion authority: pnpm's command decides what it removes. Because pnpm
does not expose a dry-run or structured prune plan, the planner is tied to the
locally reviewed pnpm 10.32.1 semantics and remains report-only for any other
version. The manifest records this provenance beside the executable/version,
eligibility digest, measurements, filesystem observations, protections, and
active pnpm owners.

Content prefixes are independent and support bounded parallelism. One scan
thread is the deliberately low-load default. The global entry budget is divided
deterministically across the active prefix batch, so concurrency cannot expand
the scan. Completed prefixes are retained in an atomic evidence cache under the
collector state directory. Later bounded runs reuse unchanged prefix
observations and spend their budget on remaining prefixes, allowing a low-load
schedule to converge. Prefix evidence expires after 24 hours.

Cached coverage is advisory only. A project can add or remove a hard link to a
content file without changing the store prefix directory, so cached evidence
never authorizes deletion. `--fresh` bypasses the cache and produces one
point-in-time plan plus an approval digest binding the exact candidate set,
policy, owner paths, filesystem identities, and reclaim measurements.

Execution remains explicit and digest-bound:

```sh
worktree-gc collect pnpm --fresh --dlx-days 7
worktree-gc collect pnpm --dlx-days 7 --execute \
  --approved-digest sha256:<digest-from-reviewed-fresh-manifest>
```

Execution creates a new fully fresh plan and refuses to continue unless its
approval digest exactly matches the reviewed one. Under the collector and
protection guards it reloads protections, repeats the bounded eligibility
snapshot, and aborts if anything changed. Only then does it run pnpm's official
`store prune` with the configured dlx TTL and record realized free-space change.
An unsupported pnpm version, active owner, incomplete scan, active protection,
or pnpm global virtual-store layout keeps the operation report-only.

This collector is manual rather than scheduled: pnpm does not offer an
interprocess prune lock that worktree-gc can acquire atomically with its owner
checks. Manifests live under `$XDG_STATE_HOME/worktree-gc/collectors` (or
`~/.local/state/worktree-gc/collectors`).

## Lima download-cache collection

The Lima collector asks Lima which cached downloads are unreferenced. Because
`limactl prune` does not expose a dry run, planning uses an APFS clone of the
download cache plus only the instance `lima.yaml` and custom template YAML that
Lima 2.1.0's prune implementation reads. It runs `limactl prune
--keep-referred` against that isolated home and maps clone
removals back to exact real cache entries. VM disks and instance data are never
copied or selected. Existing instances are nevertheless measured with the same
bounded APFS inventory and shown as advisory storage, so a stopped legacy VM is
visible without making instance deletion part of the collector.

```sh
worktree-gc collect lima
```

Each candidate is measured at its real path so the manifest distinguishes
logical allocation from APFS-private reclaim. Running instances, Lima owner
processes, incomplete clone simulation, and active protections keep the plan
non-executable. On platforms without APFS clonefile support the collector is
report-only rather than copying the cache to simulate a plan. Candidate
provenance retains only a SHA-256 URL digest, never the raw download URL;
process evidence retains only PID and executable basename.

When the user knows Lima itself is retired, an explicit mode turns the measured
stopped instances and complete download cache into one owner-domain plan:

```sh
worktree-gc collect lima --retire
```

Retirement is never inferred from age. The flag records the missing fact the
filesystem cannot supply: these stopped instances are no longer wanted. A
complete plan delegates instance removal to `limactl delete --tty=false`, then
delegates full download cleanup to `limactl prune --tty=false`. Omitting
`--force` makes Lima refuse if an instance starts after the final replan.
Running, errored, or owner-protected instances, owner processes, incomplete
APFS measurements, and worktree-gc protections keep retirement non-executable.

Explicit execution requires the full approval digest from a reviewed dry-run,
revalidates the Lima identity and exact candidate plan, and delegates to the
owner operation:

```sh
worktree-gc collect lima --execute --approved-digest sha256:<digest>
worktree-gc collect lima --retire --execute --approved-digest sha256:<digest>
```

Execution remains manual because Lima does not provide an interprocess lock
spanning instance/download activity and prune. Any identity, candidate,
provenance, measurement, process, instance, mode, or protection change
invalidates the approved digest before owner commands run. Ordinary collection
never deletes instances; only an exact reviewed `--retire` plan can do so. The
owner commands are sequential rather than transactional, so the manifest keeps
each command's result and exact post-operation verification if Lima reports a
failure after an earlier instance was already removed.

## Chromium on-device component inventory

Chromium user-data roots mix durable browser state with large re-downloadable
component models. The manual collector requires explicit initialized profile
roots with a regular, non-symlink `Local State` marker and uses a closed
component-name list rather than inferring disposability from location or age:

```sh
worktree-gc collect chromium-components \
  --profile "$HOME/Library/Application Support/Google/Chrome"
```

The list is limited to optimization-guide models, the on-device head-suggest
model, and the downloaded WASM text-to-speech engine. `Default`, `Local State`,
cookies, history, sessions, service workers, extension state, and every
unrecognized directory are excluded. Each component root is APFS-measured.
Profile-specific Chromium process trees, one bounded global `lsof` snapshot,
and recursive protections must all be complete before a claim becomes
approval-ready. An active profile-owning browser, open component path,
protection, or incomplete inventory fails closed.

This is a whole-component cache reset, not stale-revision pruning: it removes
the currently installed model revision and accepts the full re-download cost.
The collector never runs unattended. After reviewing a dry-run, execute only
its digest-bound plan:

```sh
worktree-gc collect chromium-components \
  --profile "$HOME/Library/Application Support/Google/Chrome" \
  --execute --approved-digest sha256:<reviewed-digest>
```

Execution replans the same explicit profiles under a protection guard, checks
component identity and liveness again, and atomically renames only closed-list
roots into private same-profile quarantines. It repeats browser/open-file
checks before recursively removing only the quarantined roots. Interrupted
quarantine blocks later plans for explicit recovery review.

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
# Total worker budget across repository, worktree, and generated scans.
max_parallelism = 1
stale_days = 14
generated_days = 7
# Scheduled build-cache retention uses local workdays. Explicit elapsed-day
# entries keep the legacy generated_windows/CLI meaning and override this map.
generated_workday_windows = { ".next" = 3, ".turbo" = 3, target = 3 }
generated_windows = { node_modules = 7 }
generated_activity_only = true
check_in_use = true
cargo_lock_timeout_minutes = 30
# Routine host debug/release reset window, measured in local workdays.
cargo_profile_workdays = 3
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
directory name. `generated_workday_windows` is scheduled-mode-only and records
local timezone/date/calendar evidence in the cleanup manifest. Explicit elapsed
windows win when a name appears in both maps. Build caches (`.next`, `.turbo`,
and `target`) default to three local workdays; other names use `generated_days`.

`max_parallelism` bounds the entire scheduled planning pool, including nested
repository, worktree, and generated-directory scans; repository-index refresh
passes the same limit to ripgrep. It defaults to `1` so an unattended run
favors low background impact over elapsed time. This does not limit owning-tool
subprocesses after they are started, so Cargo locks and the configured
per-target timeout remain separate coordination boundaries.

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
directory discovery walks worktree directory entries directly, stops at
configured generated roots and nested repositories, then asks Git only whether
the exact roots are ignored or contain tracked files. This avoids repeatedly
enumerating large Git indexes while preserving Git as the deletion-safety
authority.

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
