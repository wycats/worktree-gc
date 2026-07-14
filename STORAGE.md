# Storage inventory and collector design

`worktree-gc` is growing from repository cleanup into a storage manager for
rebuildable development artifacts. The design keeps two questions separate:

1. **What consumes physical space?** The inventory layer answers this without
   changing the filesystem.
2. **What is safe and worthwhile to reclaim?** A domain collector answers this
   using the owning tool's liveness and recovery rules.

This separation lets inventory inspect broad roots while cleanup remains
manifest-driven, approval-friendly, and specific to content whose meaning the
tool understands.

## Inventory contract

An inventory scan visits each requested directory root once and aggregates
descendants into a shallow report tree. An exact file root is measured directly
without enumerating its parent directory. `display_depth` and `top` bound
retained report state; `max_entries` bounds filesystem work. The scanner stays
on one filesystem by default, does not follow symlinks, and deduplicates hard
links.
Multi-root scans divide the remaining global budget across the remaining roots;
small roots return unused entries to the pool for later roots. Queued sibling
directories likewise share the remaining root budget, so a wide early subtree
cannot consume all work before later siblings receive a sample.

Each aggregate reports:

- logical bytes: file contents as applications see them;
- allocated bytes: blocks charged to the file paths, deduplicated by inode;
- private reclaimable bytes: on APFS, the conservative bytes private to the
  files that would be unlinked together;
- completeness, file/directory/error counts, and hard-link duplicates.

Allocated path size is not a deletion estimate on a copy-on-write filesystem.
APFS clones can share most extents, while pnpm worktrees can expose many paths
backed by a shared content store. `ATTR_CMNEXT_PRIVATESIZE` gives the scanner a
direct, low-cost reclaim floor. Hard-linked data is attributed only to the
lowest reported ancestor containing every link observed for that inode; a link
whose siblings remain outside the root contributes no reclaimable bytes.

The macOS backend uses `getattrlistbulk`, which returns directory names, types,
file IDs, logical/allocated sizes, link counts, and APFS private size in batches.
Exact file roots use `getattrlist` for the same APFS private-size attribute.
Other platforms use a portable directory iterator and mark private accounting
incomplete. A filesystem that rejects the extended macOS attributes falls back
to the portable path.

The report-only generated-root collector is the repository-oriented drill-down
between a broad inventory and a mutation manifest. It reuses cleanup's Git,
activity, process, and protection classification and measures every configured
generated root even when cleanup retains it. Complete owner-free roots are
reported as explicit rebuild opportunities rather than relabeled as stale.
Their cumulative low, medium, and high rebuild-cost curves are calculated per
filesystem; incomplete open-handle evidence fails closed. A fresh cleanup dry
run remains the only path to an executable candidate set.

## Collector contract

A collector owns one storage domain. It progresses through five explicit
phases:

1. **Discover** canonical domain roots using the owning tool's public interface
   or stable filesystem contract.
2. **Classify** candidates with ownership, liveness, protections, age, and
   recovery cost. Unclassified content remains advisory.
3. **Plan** exact candidate identities and expected physical reclaim in a
   structured manifest. Planning is read-only.
4. **Execute** only manifest-matching candidates after revalidating ownership,
   liveness, containment, and protections. Prefer an owning-tool operation or
   same-filesystem quarantine.
5. **Verify** candidate/quarantine absence, realized `df` change, and retained
   protected state. Record differences between estimated and realized reclaim
   for later policy decisions.

Every candidate therefore needs more than a path:

- collector and stable candidate kind;
- canonical path and filesystem identity;
- logical, allocated, and private-reclaimable measurements;
- evidence timestamp and completeness;
- liveness/ownership evidence and active protection;
- recovery mechanism and qualitative rebuild cost;
- exact execution operation and revalidation requirements.

Collectors do not infer safety from size. Inventory results can prioritize a
collector's already-safe candidates, but cannot turn user data into a cache.

## Retention and activity policy

Staleness is not one clock. Source worktrees, explicit protections, and
rebuildable artifacts express different kinds of intent and must not inherit
one shared day count.

- **Source worktrees** use conservative elapsed inactivity only after Git state,
  reachability, task ownership, current-worktree status, and protections permit
  removal. A short rebuildable-artifact window never makes source removable.
- **Protection leases** express human intent and continue to expire in elapsed
  wall-clock time. Their default and maximum duration are a separate ergonomic
  decision; the existing seven-day default is not canonized by the artifact
  policy.
- **Rebuildable artifacts** use owner activity and a workday-aware retention
  window. Routine cleanup starts with three workdays for ordinary rebuildable
  outputs, while each collector may choose a longer window for expensive
  release, cross-target, dependency, or remotely acquired state.

Workday age is based on local calendar dates rather than 24-hour durations. The
planner resolves and records a timezone, converts the activity and observation
timestamps to dates, and counts weekdays after the activity date through the
observation date. Activity and observation on the same local date have workday
age zero. Activity observed on Friday is therefore one workday old on Monday,
two on Tuesday, and three on Wednesday. The initial calendar excludes Saturday
and Sunday but does not attempt to model regional holidays. If the timezone or
activity evidence is unavailable, the candidate remains advisory.

Worktree activity alone does not refresh every artifact beneath that worktree.
Collectors should prefer owner-specific evidence such as build output activity,
open handles, process ownership, or tool metadata. An active checkout may keep
the files participating in current work while older build generations become
eligible. Unknown ownership or incomplete liveness evidence still fails closed.

Routine retention is artifact-class policy, not a pressure response. It runs
when free space is healthy so stale rebuild output does not accumulate until the
machine is nearly full. Pressure policy may shorten a class's routine window or
approve a higher rebuild-cost class, but it never bypasses source protections,
open-handle checks, owner locks, containment, or execution-time revalidation.

Every age-based manifest records enough evidence to reproduce the decision:

- raw activity and observation timestamps;
- elapsed age and computed workday age;
- timezone and calendar identifier;
- artifact class, rebuild-cost class, and applicable routine/pressure window;
- the owner evidence that selected the activity timestamp;
- whether the decision is routine, pressure-only, or advisory.

Existing `--stale-days`, `--generated-days`, `--generated-window`, and sweep
age syntax retain elapsed-day semantics for compatibility. Workday-aware policy
must use explicit configuration and a versioned manifest representation rather
than silently changing the meaning of existing commands.

The first implementation intentionally does not change the clean-worktree
removal window or the protection-lease default. Those values should follow
observed development-task and renewal behavior in a separate source-intent
decision. Regional holiday calendars and class-specific windows beyond the
initial Cargo profile policy also remain follow-up work.

## Pressure policy

Routine policy can remove uncontroversially stale, recoverable content even
when free space is healthy. Pressure policy answers a different question: how
much additional rebuild cost should the machine spend to reach a free-space
target such as 100 or 150 GiB?

Once candidate measurements are cached, pressure order should prefer:

1. candidates already eligible under routine retention policy;
2. lower recovery cost;
3. lower probability of near-term reuse;
4. larger private reclaim;
5. older evidence/activity as a stable tie-breaker.

The controller continues to check live free space after each operation. APFS
private bytes improve ordering and planning; realized filesystem availability
remains the stop condition.

Generated-directory cleanup applies the inventory primitive only after safety
classification. Delete candidates share one sequential global entry budget
and a smaller per-candidate slice; their complete or partial measurements are
persisted in manifest version 6. When the evidence budget cannot cover every
candidate, pressure candidates and lower rebuild-cost classes are measured
first.
Pressure execution preserves rebuild-cost classes, orders exact candidates
machine-wide by private reclaim and observed allocation, refreshes safety, and
executes one candidate before checking free space again. Routine elapsed-day
order remains in effect until a collector adopts the explicit workday policy;
adopted artifact classes order by workday age.

## Incremental delivery

The implementation order is intentionally useful after every merge:

1. **APFS-aware inventory CLI.** Safely map large roots and export structured
   evidence without changing scheduled cleanup.
2. **Measured generated candidates.** Reuse inventory measurements for the
   existing `target`, `.next`, `.turbo`, and `node_modules` collectors. Store
   measurements in manifests and rank safe pressure candidates by physical
   benefit inside their rebuild-cost class. Separately report complete,
   owner-free generated roots as explicit rebuild opportunities even when the
   routine retention policy keeps them, grouped into cumulative per-filesystem
   rebuild-cost tiers.
3. **Workday-aware artifact retention.** Add explicit timezone, calendar,
   elapsed-age, and workday-age evidence without changing existing elapsed-day
   flags. Apply the three-workday routine default to owner-free `target`,
   `.next`, and `.turbo` roots. Keep dependency installs and other higher-cost
   classes on their explicit elapsed or owner-specific windows until their
   recovery contracts become equally reliable.
4. **Bounded scheduling and first activation.** Make repository concurrency an
   explicit scheduled-mode setting, retain hard inventory/measurement budgets,
   and validate a complete dry-run manifest before enabling execution. Roots
   such as Codex-managed Git worktrees can then reuse the existing generated
   collectors; task metadata is advisory, while protections, Git state, open
   handles, Cargo locks, and execution-time revalidation remain authoritative.
5. **Shared package-store collectors.** Discover pnpm's canonical content store
   through pnpm and wrap official prune semantics with preflight, protections,
   measurement, and verification. Treat pnpm's metadata and `dlx` caches as a
   separate candidate domain: their path allocation can be mostly shared on
   APFS, and their retention contract is not the content store's prune contract.
6. **Container/VM collectors.** Treat Docker/OrbStack, Lima, and Parallels as
   separate domains. Use their public inventory/prune/compact interfaces and
   surface running or suspended state. VM deletion or archival remains an
   explicit user decision.
7. **Owner-mediated advisors and collectors.** Large IDE, browser, session-log,
   and application stores begin report-only. Activity must come from the
   owning application's task/database model rather than generic file mtimes
   when the owner rewrites or reindexes old content. A domain graduates to
   cleanup only after it has a stable liveness model, a recoverable-content or
   durable-export boundary, and an owner-approved execution operation.

This sequence starts reclaiming better-ranked repository artifacts in step 2,
makes their routine retention explicit in step 3, bounds unattended activation
in step 4, and then adds machine-wide domains one at a time. Inventory caches
can later make scheduled discovery incremental, but cached measurements must
always include their observation time and be revalidated before mutation.
