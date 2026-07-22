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
or package manager), add `--check-in-use`. On macOS, planning uses a bounded
native `libproc` PID snapshot of cwd/root vnode paths, file-backed memory
mappings, and vnode descriptors, then matches every path recursively against
all generated candidates in memory. Other Unix platforms, or a native
capability/API failure, use one machine-readable global `lsof` snapshot with
NUL-delimited byte paths, so non-UTF-8 names are not silently dropped. Native
time or resource-budget exhaustion instead fails closed without starting that
second global scan. Every execution pass takes fresh evidence and rechecks each
candidate before mutation. If neither backend is available or the snapshot is
indeterminate, an explicitly requested ownership check retains all candidates
rather than granting mtime-only deletion authority:

```sh
cargo run -- cleanup --repo /path/to/repo --generated-activity-only --check-in-use --execute
```

Active Rust `target` directories receive a built-in incremental-cache sweep
during ordinary cleanup planning. They also receive an atomic profile-reset
pass. Rustc incremental roots with no session activity for 14 days are
selected for in-place pruning; host and cross-target Cargo profiles such as
`debug` and `release` that have been inactive for 7 days are reset as a unit
while holding every Cargo profile lock. A whole `target` directory that has
been inactive for 3 days remains a wholesale deletion candidate. The dry run
records every incremental root and Cargo profile, including its path, Cargo
target when present, newest activity, age, and planned action.

Override the built-in incremental window with an explicit strategy:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=rustc-incremental:7 --execute
```

Override the Cargo profile window independently:

```sh
cargo run -- cleanup --repo /path/to/repo --sweep target=cargo-profile-reset:14 --execute
```

Restrict an explicit sweep to one exact generated tree when a repository family
contains linked worktrees or nested Cargo projects:

```sh
cargo run -- cleanup --repo /path/to/repo --no-default-generated \
  --sweep target=rustc-incremental:14 \
  --sweep target=cargo-profile-reset:1 \
  --sweep-path /path/to/repo/target
```

`--sweep-path` only narrows in-place sweep planning. It never makes a generated
tree eligible for wholesale deletion, and unmatched generated trees are not
traversed looking for a nested match.

Profile reset deliberately works at Cargo's profile boundary instead
of interpreting private fingerprint JSON or reconstructing artifact hashes.
This reclaims the profile's `deps`, `.fingerprint`, `build`, and incremental
outputs together while preserving other profiles. Cross-target profiles are
reset at the same Cargo-owned boundary when their layout is
`target/<target-spec-name>/<debug|release>` and the profile contains Cargo's
`.cargo-lock`. Custom profile names and deeper or otherwise unclassified
layouts remain report-only.

Before pruning, `worktree-gc` verifies the directory against `cargo metadata`
and leaves shared or external build directories untouched. Planning and
execution require complete ownership evidence and retain profiles with an open
file, mapped executable, or other live process path. Execution waits for Cargo's
profile lock, rechecks activity and ownership, atomically moves the stale
profile into a tool-owned quarantine, releases the lock, and then deletes the
quarantine. A later execution recovers quarantine left by an interrupted run.
This candidate-scoped ownership requirement always applies to profile reset;
`--check-in-use` controls the broader generated-directory and worktree checks.

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

### Gateway owner reports

`gateway-storage-report` correlates a saved inventory with one or more
extension-issued `GatewayStorageInventoryV1` reports. It is a standalone,
report-only adapter: it cannot clean storage, emit an execution command, or
turn filesystem observations into owner activity, protection, export, or
eligibility claims.

```sh
worktree-gc gateway-storage-report \
  --inventory-manifest inventory.json \
  --gateway-manifest gateway-code.json \
  --gateway-manifest-dir "$CODE_GLOBAL_STORAGE/storage-inventory-v1" \
  --json > gateway-storage-report.json
```

Explicit manifests and repeatable manifest directories may be combined.
Directory discovery is non-recursive, accepts only regular `.json` files,
sorts and deduplicates canonical paths, and has fixed file-count and byte
budgets. Owner `file:///` URIs are validated and canonically contained before
correlation. If the saved inventory did not retain an exact unit path, the
adapter runs one exact-path, one-filesystem inventory subpass under a shared
global and per-unit entry budget; it never substitutes an ancestor's total.

Stable and Insiders observations remain independent and non-additive. A shared
`rootId` at the same canonical root is reported as such. If the same `rootId`
names different owner root URIs, filesystem correlation is suppressed instead
of guessing which owner identity is authoritative. Different root IDs that
resolve to the same physical root receive a separate non-additive overlap
group. Each unit explicitly selects `inventory-manifest-exact`,
`exact-unit-subpass`, or `unavailable` as its filesystem evidence source.
For closed owner snapshots, the correlated unit also exposes
`derived_closed_age_ms` with basis `owner-snapshot-plus-manifest-elapsed`. This
adds elapsed time since the immutable owner report to its original
`closedAgeMs`; the source value remains unchanged under `owner_report`, and the
derived value does not upgrade liveness or cleanup eligibility.
JSON output intentionally retains the owner-issued local URIs for local
reconciliation and is not a support-safe export artifact.

### Generated opportunity coverage

`collect generated` is the report-only repository drill-down used after broad
inventory identifies a large development root:

```sh
worktree-gc collect generated \
  ~/Code ~/plugins ~/.codex/worktrees ~/Documents/Codex ~/Documents/sandboxd \
  --max-discovery-entries 1000000 \
  --max-entries 2000000
```

Repository discovery is hidden-file aware, recognizes linked-worktree `.git`
files, stops at repository and generated-tree boundaries, and shares a bounded
entry budget across the requested roots. Classification takes one complete
ownership snapshot and reuses cleanup's Git, activity, tracked-content, and
recursive-protection rules. APFS measurement then gives each generated root a
fair slice of the global measurement budget instead of letting an early large
tree hide later opportunities.

The manifest reports discovery and measurement completeness per requested
root, repositories and linked worktrees found, safe/active/protected/tracked/
incomplete/report-only counts, and cumulative private reclaim by generated
kind and rebuild-cost class. Overlapping requested roots retain independent,
explicitly non-additive coverage totals. This command has no execution
surface: deletion still requires a fresh cleanup manifest and the exact
manifest/digest-bound executor.

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
# Set true for a focused supervised cycle that should consider only the names
# listed in delete_generated. The default is false.
no_default_generated = false
# Add coarse rebuildable roots that are specific to your tools or workflows.
delete_generated = ["node_modules.partial-install"]
# Per-directory entries override generated_days and any tighter built-in window.
generated_windows = { ".next" = 7, ".turbo" = 7, target = 7, node_modules = 7, "node_modules.partial-install" = 7 }
generated_activity_only = true
check_in_use = true
cargo_lock_timeout_minutes = 30
# Requires cargo-sweep; omit to use only the built-in Cargo sweeps.
cargo_sweep_max_size = "50GB"

[cleanup.pull_requests]
# Optional GitHub lifecycle signal for whole-worktree retention. Requires an
# authenticated `gh` CLI and cleanup.check_in_use = true.
provider = "github"
merged_grace_days = 1

[pressure]
# Optional hysteresis controller. Routine TTL cleanup still runs above this.
enter_free_space = "100GiB"
target_free_space = "150GiB"
generated_days = 1
stale_days = 7
# Opt in to age-independent coarse cleanup only when ownership evidence is
# complete and the whole source worktree is owner-free.
owner_free_generated = true

[history]
retention_days = 90
repository_refresh_days = 7
```

`no_default_generated = true` has the same meaning as the CLI
`--no-default-generated` flag: scheduled cleanup considers only explicitly
configured `delete_generated` roots and disables built-in sweeps. This is useful
for bounded supervised pressure cycles that need to concentrate measurement on
a small set of high-value roots. `delete_generated` has the same meaning as
repeated CLI `--delete-generated` arguments. Every entry must be one literal
directory-name component.
`generated_windows` has the same meaning as repeated CLI
`--generated-window NAME=DAYS` arguments and applies to any active built-in
delete root or explicitly configured generated directory name. Build caches
(`.next`, `.turbo`, and `target`) otherwise use a tighter built-in window; other
names use `generated_days`.

When `[cleanup.pull_requests]` is enabled, `worktree-gc` batches GitHub PR
queries by retained head-branch metadata through the authenticated `gh` CLI,
then requires an exact PR head-OID match. This finds squash- and rebase-merged
PRs without granting branch names deletion authority. An exact-head open pull
request retains its worktree even after the ordinary age window. A clean,
attached, non-current exact-head worktree becomes routine-removal eligible
after its pull request has been merged for `merged_grace_days`. The manifest
records the repository, PR number and URL, PR head name and OID, merge time,
observation time, and evidence completeness. Incomplete GitHub or
process-ownership evidence keeps the worktree. Execution freshly revalidates
Git identity, source status, PR state, ownership, and protections before `git
worktree remove`; it never uses `--force` and never deletes the local branch.
The equivalent one-off cleanup flag is `--github-merged-pr-grace-days DAYS`,
together with `--check-in-use`.

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
configured values. With `owner_free_generated = true`, pressure cleanup may
also remove a complete generated tree without waiting for its age window when
the ownership snapshot is complete and finds no open file, mapped file,
process cwd/root, or other vnode anywhere in the owning worktree. Incomplete
ownership evidence fails closed. This option requires
`cleanup.check_in_use = true`.

Dirty source does not by itself retain an ignored or untracked generated tree,
but tracked content and every existing recursive protection still do. Current
broad protections therefore remain broad until they are explicitly migrated
to the scoped model described in the RFC. Rebuildable directories are ordered
by expected rebuild cost (`.turbo`, `.next`, `target`, then `node_modules`)
across all repositories. Inside each rebuild-cost class, the controller prefers
the largest conservative APFS-private reclaim, then the largest observed
allocation, then the oldest activity. It refreshes and executes one exact
candidate at a time; clean worktrees come last.
The aggregate manifest records the policy, initial free-space observations,
which decisions exist only because of pressure, and final free space after an
executing run. Generated delete decisions also record logical, allocated, and
APFS-private bytes, filesystem identity, evidence time, entries visited, and
whether the measurement completed. One sequential two-million-entry budget is
shared across the entire initial plan, with at most 250,000 entries spent on
one candidate, so very large candidate sets remain bounded, fair, and visibly
partial. The controller checks live filesystem
availability after each deletion and stops once the target is reached.

For a supervised recovery, `execute-generated` consumes one dry-run manifest
and one exact candidate instead of translating approval into an ad hoc removal
command. The approval digest is the SHA-256 of the manifest bytes:

```sh
worktree-gc execute-generated \
  --manifest /absolute/path/to/dry-run.json \
  --approval-digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --candidate /absolute/path/to/worktree/chat/.next
```

The command accepts a measured owner-free routine or pressure deletion. It requires
complete ownership and APFS-private evidence, revalidates the candidate's
canonical path and filesystem identity, verifies the exact Git HEAD and
porcelain status digest, rejects tracked content and current protections, and
takes a fresh ownership snapshot inside the protection guard immediately
before mutation. It atomically
renames the candidate into a digest-bound quarantine below the repository Git
common directory, verifies the renamed inode, removes only that quarantine,
and writes a structured execution result next to the approved manifest.
Pressure candidates additionally recheck live free space immediately before
quarantine and remain in place when the approved pressure target is already
satisfied. Routine candidates must already be delete decisions in the approved
manifest and do not depend on an active pressure policy.
Ownership refusals write a timestamped structured sidecar beside the requested
execution result. The sidecar preserves the snapshot backend, completeness,
matched worktree or candidate path, refusal stage, and PID and evidence kind
when the backend provides them, so a short-lived owner remains diagnosable
after it exits.
An intact digest-bound quarantine interrupted after rename and before removal
can be resumed with the same command and approval. Identity or measurement
drift, including partial removal, fails closed and requires a new recovery
boundary. A `target/` candidate additionally requires the dry-run manifest's
Cargo lock timeout and existing Cargo profile locks. Its guarded ownership
snapshot is taken immediately before waiting for those locks, which are then
held across the final identity, measurement, source, and pressure
revalidation, quarantine, and deletion. While those locks are held, process
ownership is matched to the exact `target/` candidate: a process using a
sibling generated tree does not pin this target. Generated trees without an
equivalent toolchain lock retain the conservative worktree-wide ownership
guard.

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
