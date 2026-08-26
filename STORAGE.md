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

The accepted [source-safe rebuildable-state controller RFC](docs/rfcs/0001-rebuildable-state-controller.md)
separates conservative worktree retention from aggressive generated-artifact
recovery. Current releases execute owner-free pressure cleanup independently
of source recency; routine generated cleanup still uses configured age windows.
The migration keeps age as cooldown and ranking evidence rather than durability
authority. The implementation plan below now centers complete machine evidence
and active-target control.

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
- traversal completeness, file/directory/error counts, and hard-link
  duplicates;
- private-measurement completeness, independently of traversal completeness.

Traversal completeness and byte-measurement completeness answer different
questions. A scan that exhausts `max_entries` has measured the files it visited
correctly, but it has not measured the whole requested root. An exhausted root
records a structured completion reason, its configured and consumed fair-share
entry budget, and the number of directories still pending. Retained aggregates
record both whether their own descendant traversal completed and the
entry-local causes when it did not, so a completed sibling can remain exact
while the capped branch and its ancestors are partial.

Every logical, allocated, and private-reclaimable total whose only incomplete
cause is an exhausted entry budget is an observed lower bound. Scan errors and
unresolved cross-branch hardlink attribution are incomplete observations
because a complete scan can move their totals in either direction. A
private-byte total is independently a lower bound when the platform cannot
provide complete private-size attributes. Human and JSON reports preserve
these completeness dimensions instead of allowing an exact measurement of a
partial traversal to look like a complete census.

Allocated path size is not a deletion estimate on a copy-on-write filesystem.
APFS clones can share most extents, while pnpm worktrees can expose many paths
backed by a shared content store. `ATTR_CMNEXT_PRIVATESIZE` gives the scanner a
direct, low-cost reclaim floor. Hard-linked data is attributed only to the
lowest reported ancestor containing every link observed for that inode; a link
whose siblings remain outside the root contributes no reclaimable bytes. If a
bounded scan cannot determine whether another link lies in an unvisited
branch, the observed branch is explicitly incomplete until an exact subpass
settles the common ancestor.

The macOS backend uses `getattrlistbulk`, which returns directory names, types,
file IDs, logical/allocated sizes, link counts, and APFS private size in batches.
Exact file roots use `getattrlist` for the same APFS private-size attribute.
Other platforms use a portable directory iterator and mark private accounting
incomplete. A filesystem that rejects the extended macOS attributes falls back
to the portable path.

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

### Gateway storage inventory adapter

Vercel AI Gateway owns the liveness, pin/export, and eligibility model for its
workspace PGlite databases and investigation logs. `worktree-gc` consumes the
owner's `GatewayStorageInventoryV1` reports without reinterpreting those
claims. The adapter retains the complete owner report alongside separately
labelled filesystem evidence; logical, allocated, and APFS-private currencies
and their completeness remain distinct.

The adapter accepts explicit report files and bounded, non-recursive manifest
directories. Owner-issued `localRootUri` and `localUnitUri` values must be
canonical local `file:///` URIs. Existing paths are canonicalized, and each
unit must remain under its declared canonical root before any APFS correlation
occurs. Missing paths are reported as unavailable. Symlink escapes and a
shared `rootId` that resolves to different roots fail closed for measurement.

A shallow machine inventory may have visited a Gateway unit without retaining
its exact path. Ancestor totals are not unit evidence. When exact complete
evidence is absent, the adapter performs one bounded exact-path inventory
subpass across all validated unique units, sharing both global and per-unit
entry budgets and staying on one filesystem. This subpass is operationally
useful without teaching a later broad survey about VS Code workspace hashes.

Reports from Stable and Insiders are preserved independently and are never
summed. Same-root observations receive an advisory duplicate grouping;
conflicting owner URIs for one root identity suppress filesystem correlation.
Different root IDs resolving to the same physical root receive a distinct
non-additive overlap grouping. Neither grouping changes extension-issued
activity, protection, export, or eligibility state. Each unit explicitly
records whether its selected evidence came from an exact retained inventory
node, the exact-unit subpass, or is unavailable; incomplete broad evidence is
preserved alongside that selection.
The adapter exposes no generic execution command and is not a collector
execution surface. Its versioned JSON report is independently readable so a
later machine-wide survey can compose the completed correlation without
copying Gateway schema knowledge or repeating the exact-path subpass.

### Machine coverage ledger

The generated-opportunity collector owns repository discovery and report-only
classification for these requested roots:

| Domain | Contract |
| --- | --- |
| `~/Code` | Repository-generated discovery and exact cleanup manifests |
| `~/plugins` | Repository-generated discovery and exact cleanup manifests |
| `~/.codex/worktrees` | Hidden linked-worktree discovery and exact cleanup manifests |
| `~/Documents/Codex` | Nested repository discovery and exact cleanup manifests |
| `~/Documents/sandboxd` | Repository-generated discovery and exact cleanup manifests |

Each root records its own discovery errors, entry consumption, repositories,
linked worktrees, generated classifications, and measurement completeness.
The top-level artifact set is deduplicated. Per-root byte totals are retained
for coverage diagnosis but are explicitly non-additive because requested roots
can discover the same repository or linked worktree.

Generated opportunity reporting ranks complete APFS-private measurements
before incomplete lower bounds. Complete owner-free roots, complete retained
or blocked roots, and incomplete measurements remain separate report queues so
summed path allocation cannot masquerade as reclaim evidence. A generated
collector manifest can seed a later bounded pass: incomplete observations
prioritize which roots receive the next per-artifact completion budget, while
complete roots receive a fresh recursive measurement. The report preserves
structured traversal causes so clean entry-budget exhaustion is an observed
lower bound and scan failures remain incomplete observations. It also records
current versus resumed observations. This is an observation ledger, not
mutation authority; an exact cleanup manifest always measures and revalidates
its candidate again.

These domains remain owner-report-only: `~/.cache/local-sandbox`,
`~/.codex/sessions` plus `~/.codex/archived_sessions`, and VS Code/Gateway
storage. The `collect codex-sessions` adapter correlates Codex's task index
with plain and natively compressed task files, reports compression
configuration and marker health, and APFS-measures the physical store without
reading transcript contents. It grants no archive, retention, compression, or
deletion authority; Codex's native task-store compression remains the recovery
mechanism.

Generic inventory may expose these domains' physical size but cannot infer
liveness, pin/export state, eligibility, or deletion authority. Parallels is
explicitly excluded from this controller. Any other large inventory domain
remains unclassified until a repository or owner adapter gives it a recovery
contract. Unrelated inventory may proceed while a Parallels VM runs; concrete
disk contention can serialize a broad scan without granting this controller
authority over the VM.

Coverage precedes control claims. The machine ledger must distinguish a
complete census from a bounded lower bound before the controller describes how
much space it can govern. For each requested root and useful first-level
family, the ledger retains the observation time, entry limit and consumption,
traversal completion, file and directory counts, logical/allocated/private
currencies with their completeness, and one of these authority classes:

- **managed:** an owner or repository adapter can issue exact cleanup
  candidates;
- **report-only:** the domain is measured but its owner retains mutation
  authority;
- **excluded:** the domain is outside this controller, including Parallels;
- **unclassified:** inventory exposed material usage but no recovery contract
  exists yet.

Worktree-family containers such as `v0.worktrees` and
`local-sandbox.worktrees` serve as discovery domains. Cleanup authority
attaches only to their independently classified generated roots or source
worktrees. Generated roots can route to granular active cleanup or owner-free
coarse cleanup, while source worktrees remain under conservative source
retention. Large log trees remain report-only until the producing application
defines retention, export, and recovery behavior.

The first bounded `~/Code` census on 2026-08-03 demonstrates why this
distinction is operationally important. It exhausted the 2,000,000-entry cap
after observing 1,207,830 files and 526,988 directories. Its 89.46 GiB private,
98.18 GiB allocated, and 95.12 GiB logical totals are therefore lower bounds,
not a complete machine baseline. Within that partial traversal,
`v0.worktrees` accounted for at least 17.36 GiB private,
`local-sandbox.worktrees` 10.69 GiB, `locald.worktrees` 6.87 GiB, and
`v0-worktree-gc.worktrees` 3.31 GiB. The generated
`locald-b23-generated-json-files-recovery/target` accounted for at least
16.53 GiB, while `vscode-ai-gateway/.logs` accounted for at least 7.94 GiB.
The worktree families route into generated discovery; the `target/` needs
current ownership to choose granular or coarse cleanup; the log tree remains
owner-mediated.

### Codex task-store adapter

Codex owns task identity, lineage, archive state, resumption, retention, and
compression. Filesystem age cannot reproduce that authority. The report-only
adapter therefore reads the owner index from `state_5.sqlite` and correlates
each indexed task with one physical `.jsonl` or `.jsonl.zst` file under the
expected live or archived root. The transcript payload is never opened.

Compression changes the physical filename while an index may retain the
logical `.jsonl` spelling. The adapter accepts that exact owner-known pair but
fails closed when both spellings exist, neither exists, the path changes
roots, identity is missing from the filename, or a symlink/noncanonical path
intervenes. Unindexed files and indexed tasks with no physical file remain
explicit correlation failures.

The report records:

- explicitly configured `local_thread_store_compression` state from the base
  config plus an explicitly selected `--profile` layer;
- compression-marker presence, type, size, modification time, and age;
- temporary compression artifacts;
- live and archived counts and physical-byte currencies;
- separately labeled physical metrics for unindexed rollout files;
- plain and compressed counts and metrics;
- age buckets derived from owner-index activity timestamps;
- bounded traversal, correlation, and APFS-measurement completeness.

This is health and coverage evidence, not an eligibility reconstruction.
Worktree-gc does not decide which tasks are safe to compress, mutate Codex
configuration, restart the application, alter archive state, or expose a
session cleanup command.

## Source and rebuildable-state policy

Worktree source and generated artifacts have different durability. Source can
contain unique human work and context; generated state spends only a known
recovery operation. The controller therefore has three ordered cleanup tiers:

1. **Granular active cleanup.** Prune superseded generations inside actively
   owned build trees while preserving the locked current working set.
2. **Coarse owner-free cleanup.** Remove complete `target`, `.next`, `.turbo`,
   project-local `node_modules`, and equivalent trees when complete ownership
   evidence finds no current owner. The source worktree may be recent or dirty.
3. **Conservative worktree cleanup.** Remove the worktree only after separate
   source-safety, reachability, lifecycle, ownership, and protection checks.
   Exact-head GitHub PR evidence strengthens this tier: open PRs retain their
   worktrees, while merged PRs can shorten the cleanup grace period without
   weakening dirty, detached, current, owned, or protected-source guards.

Current ownership is positive evidence such as open handles, process cwd or
mapped files, owner locks, a live runtime, or an explicit artifact lease. A
recent commit or worktree mtime is not ownership. Age remains useful as an
anti-thrash cooldown and ranking tie-breaker, but it is not the primary
authority for retaining rebuildable state.

This separation also applies to protections. A source lease should prevent
whole-worktree removal without implicitly pinning every generated descendant.
Artifact and runtime leases protect exact warm or live outputs. Existing
recursive leases remain broad until explicitly migrated; the controller never
silently weakens them.

## Pressure policy

Routine policy prevents generated state from accreting until the machine is
already full. Pressure policy decides how much additional rebuild cost to
spend to restore a free-space target, initially entering below 100 GiB and
recovering toward 150 GiB.

Safety gates determine eligibility. Within a filesystem, pressure order is:

1. granular superseded-state cleanup in actively owned artifacts;
2. owner-free coarse cleanup from low through higher rebuild-cost classes;
3. conservative source-safe worktree cleanup;
4. owner-mediated or durable domains only through their own contracts.

Within a tier and rebuild-cost class, prefer larger complete APFS-private
reclaim, then lower near-term reuse evidence, then older artifact activity as
a stable tie-breaker. Source-worktree age is not a primary generated-artifact
ranking key.

Pressure may admit young owner-free artifacts, including output created the
previous day. It never bypasses canonical containment, tracked-file checks,
complete ownership evidence, locks, protection scope, exact identity, or
execution-time revalidation.

The controller checks live free space after every exact operation and stops at
the configured target. APFS-private bytes improve ordering; realized
filesystem availability remains authoritative. If safe rebuildable candidates
cannot reach the target, the controller reports the remaining durable or
owner-mediated domains rather than widening deletion authority automatically.
That outcome must also say whether the safe pool is genuinely exhausted or
whether incomplete coverage prevented the controller from seeing enough of
the rebuildable pool. Reaching the end of a capped scan records a coverage gap
and leaves the unvisited bytes unresolved.

## Incremental delivery

The implementation order is intentionally useful after every merge. Landed
foundations remain valuable even where their original TTL-first policy needs
revision.

1. **Landed: APFS-aware inventory and exact candidate evidence.** Broad scans,
   hard-link and clone-aware measurements, manifest identities, and live `df`
   verification establish physical evidence without granting deletion
   authority.
2. **Landed: measured generated candidates, exact routine execution, and owner
   adapters.** Generated roots can be ranked by private reclaim and executed
   through one manifest-bound path, while Gateway and other durable domains
   preserve owner-issued liveness and remain report-only.
3. **Next: split source, artifact, runtime, and legacy protection scopes.** A
   source lease must be able to protect worktree context without indefinitely
   retaining rebuildable descendants. Existing recursive leases stay broad
   until explicitly migrated.
4. **Landed: owner-free coarse generated cleanup and bounded machine
   coverage.** Current ownership and recoverability are the eligibility
   boundary for complete generated-tree deletion. Generated discovery covers
   configured repository roots, exact execution is manifest-bound, and
   bounded ownership epochs can use complete privileged evidence. The daily
   controller is running against a partial root set; machine-wide acceptance
   remains pending.
5. **In delivery: completion-aware machine evidence.** Preserve structured
   cap/error reasons, budgets, pending-directory counts, and per-aggregate
   traversal completeness so capped currencies are visibly lower bounds and
   error-affected currencies are visibly incomplete observations. Generated
   opportunity manifests now carry completed observations and incomplete
   prioritization hints into a later bounded pass without upgrading either to
   deletion authority. Next, segment oversized broad inventory roots into
   resumable census units and reconcile their non-overlapping results into
   family and long-tail totals.
6. **Next: active-target granular budgets.** Extend incremental pruning and
   coherent Cargo profile reset with a reviewed active-target size policy so
   current worktrees do not accrete indefinitely.
7. **Controller calibration.** Retain bounded repository concurrency, global
   measurement budgets, bounded pressure waves, per-path safety guards, and
   live free-space stop checks. Compare supervised plans with manual disk-map
   judgments and require the explained safe pool to plausibly close the
   configured pressure deficit.
8. **Shared package-store collectors.** Discover pnpm's canonical content store
   through pnpm and wrap official prune semantics with preflight, protections,
   measurement, and verification. Keep store, metadata, and `dlx` contracts
   separate from project-local `node_modules` cleanup.
9. **Other owner-mediated domains.** Docker/OrbStack, IDE diagnostics, browser
   state, and similar domains use owner operations. Application databases,
   evidence, and VM storage remain report-only until explicit retention or
   export contracts exist. Parallels deletion is outside generic cleanup.

The immediate center of gravity is an accurate generated-opportunity loop:
discover rebuildable roots, complete their APFS-private measurements over
bounded passes, and compare one exact candidate's projected reclaim with its
realized `df` change. That closes the shortest path to owner-free coarse
recovery while routing large owned roots into active-target pruning. Broad
machine census resumption and active-target budgets stay next in that order;
whole-worktree removal stays conservative and separate.

Resumable inventory is the next measurement slice. It should partition
oversized roots into stable non-overlapping segments, persist observation time
and completion state, resume without recounting finished segments, and
revalidate any cached evidence before mutation. Exact cleanup authority
continues to come from a fresh domain manifest and execution guards.
