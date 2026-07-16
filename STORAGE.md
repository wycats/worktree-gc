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
recovery. Current releases still contain TTL-first behavior in places; the
implementation plan below identifies the migration to ownership-first policy.

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
   source-safety, reachability, inactivity, and protection checks.

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

## Incremental delivery

The implementation order is intentionally useful after every merge. Landed
foundations remain valuable even where their original TTL-first policy needs
revision.

1. **Landed: APFS-aware inventory and exact candidate evidence.** Broad scans,
   hard-link and clone-aware measurements, manifest identities, and live `df`
   verification establish physical evidence without granting deletion
   authority.
2. **Landed: measured generated candidates and owner adapters.** Generated
   roots can be ranked by private reclaim, while Gateway and other durable
   domains preserve owner-issued liveness and remain report-only.
3. **Next: split source, artifact, runtime, and legacy protection scopes.** A
   source lease must be able to protect worktree context without indefinitely
   retaining rebuildable descendants. Existing recursive leases stay broad
   until explicitly migrated.
4. **Next: owner-free coarse generated cleanup.** Make current ownership and
   recoverability the eligibility boundary for complete generated-tree
   deletion. Treat elapsed/workday age as cooldown and ranking evidence. Admit
   project-local `node_modules` after lower rebuild-cost classes.
5. **Next: active-target granular budgets.** Extend incremental pruning and
   coherent Cargo profile reset with a reviewed active-target size policy so
   current worktrees do not accrete indefinitely.
6. **Controller activation.** Retain bounded repository concurrency, global
   measurement budgets, bounded pressure waves, per-path safety guards, and
   live free-space stop checks. Compare supervised plans with manual disk-map
   judgments before enabling unattended execution.
7. **Shared package-store collectors.** Discover pnpm's canonical content store
   through pnpm and wrap official prune semantics with preflight, protections,
   measurement, and verification. Keep store, metadata, and `dlx` contracts
   separate from project-local `node_modules` cleanup.
8. **Other owner-mediated domains.** Docker/OrbStack, IDE diagnostics, browser
   state, and similar domains use owner operations. Application databases,
   evidence, and VM storage remain report-only until explicit retention or
   export contracts exist. Parallels deletion is outside generic cleanup.

The immediate center of gravity is step 4: deleting whole rebuildable trees
from owner-free worktrees without spending source-state risk. Step 5 prevents
the same long tail from regrowing inside active worktrees. Whole-worktree
removal remains conservative and is not the primary disk-recovery mechanism.

Inventory caches can later make discovery incremental, but cached evidence
must retain its observation time and be revalidated before mutation.
