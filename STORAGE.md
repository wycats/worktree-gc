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

An inventory scan visits each requested root once and aggregates descendants
into a shallow report tree. `display_depth` and `top` bound retained report
state; `max_entries` bounds filesystem work. The scanner stays on one
filesystem by default, does not follow symlinks, and deduplicates hard links.

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

## Pressure policy

Routine policy can remove uncontroversially stale, recoverable content even
when free space is healthy. Pressure policy answers a different question: how
much additional rebuild cost should the machine spend to reach a free-space
target such as 100 or 150 GiB?

Once candidate measurements are cached, pressure order should prefer:

1. candidates already eligible under routine TTL policy;
2. lower recovery cost;
3. lower probability of near-term reuse;
4. larger private reclaim;
5. older evidence/activity as a stable tie-breaker.

The controller continues to check live free space after each operation. APFS
private bytes improve ordering and planning; realized filesystem availability
remains the stop condition.

## Incremental delivery

The implementation order is intentionally useful after every merge:

1. **APFS-aware inventory CLI.** Safely map large roots and export structured
   evidence without changing scheduled cleanup.
2. **Measured generated candidates.** Reuse inventory measurements for the
   existing `target`, `.next`, `.turbo`, and `node_modules` collectors. Store
   measurements in manifests and rank safe pressure candidates by physical
   benefit inside their rebuild-cost class.
3. **Shared package-store collector.** Discover pnpm's canonical store through
   pnpm, distinguish project links from store allocation, and wrap official
   prune semantics with preflight, protections, measurement, and verification.
4. **Container/VM collectors.** Treat Docker/OrbStack and Parallels as separate
   domains. Use their public inventory/prune/compact interfaces and surface
   running or suspended state. VM deletion or archival remains an explicit
   user decision.
5. **Application-cache advisors and collectors.** Large IDE/browser/application
   stores begin report-only. A domain graduates to cleanup only after it has a
   stable ownership model and a recoverable-content boundary.

This sequence starts reclaiming better-ranked repository artifacts in step 2,
then adds machine-wide domains one at a time. Inventory caches can later make
scheduled discovery incremental, but cached measurements must always include
their observation time and be revalidated before mutation.
