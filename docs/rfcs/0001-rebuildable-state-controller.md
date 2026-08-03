# RFC 0001: Source-safe rebuildable-state control

- **Status:** Accepted for implementation
- **Date:** 2026-07-16
- **Updates:** The retention, protection, and pressure policy in `STORAGE.md`

## Decision

The project will organize storage policy around source durability and artifact
recoverability rather than one shared inactivity threshold. The immediate
implementation priority is coarse deletion of owner-free generated trees.
Granular pruning of actively owned trees prevents renewed accretion, while
whole-worktree removal remains a separate conservative source-retention step.

Three- and seven-day evidence may remain as cooldowns, compatibility inputs,
or ranking signals. It is not the primary authority for retaining rebuildable
state.

## Implementation status

| Capability | State | Direction |
| --- | --- | --- |
| APFS-aware inventory and exact physical measurement | Landed | Retain |
| Measured pressure candidates and exact execution manifests | Landed | Retain |
| Report-only owner adapters for durable domains | Landed | Retain |
| Bounded scheduling and pressure waves | Landed | Retain |
| Bounded generated-root discovery and opportunity coverage | Landed | Extend coverage with completion-aware, resumable census evidence |
| Completion-aware broad inventory evidence | In delivery | Qualify capped roots and affected aggregates as lower bounds |
| Workday-aware artifact age | Validated on an unpublished stack | Retain as evidence and optional cooldown; remove as primary eligibility authority |
| Scoped source, artifact, runtime, and legacy protections | Not implemented | Build before weakening broad worktree protection |
| Owner-free coarse cleanup independent of source recency | Landed | Expand explained machine coverage without weakening broad protections |
| Granular active Cargo-target pruning | Partially landed | Extend with measured size policy after owner-free coarse cleanup |
| Exact-head PR lifecycle retention | Landed | Retain open PR worktrees and reclaim clean merged-PR worktrees after a short grace period |
| Unattended 100–150 GiB controller | Running on partial coverage; acceptance unmet | Calibrate against a completion-aware machine ledger and target-band evidence |

The generated-retention stack has been selectively reconciled against this
table. Discovery, measurement, reporting, exact owner-free execution, PR
lifecycle evidence, bounded scheduling, and privileged ownership evidence are
landed. Owner-free pressure cleanup does not depend on source recency. Routine
generated cleanup still uses configured age windows while the migration moves
age toward cooldown and ranking evidence rather than durability authority.

## Summary

`worktree-gc` should preserve source state conservatively while reclaiming
rebuildable state aggressively. Git worktrees and the generated artifacts
inside them have different durability, recovery cost, and evidence. They must
not share one age threshold or one undifferentiated protection decision.

The controller uses three complementary cleanup tiers:

1. granularly prune superseded artifacts inside actively owned worktrees;
2. remove complete generated trees from owner-free worktrees, even when the
   source worktree is recent or dirty;
3. remove entire worktrees only after conservative source-safety checks.

Age remains useful as a cooldown and ranking signal. It is not the primary
authority for retaining a rebuildable tree. Live ownership, exact source
containment, recoverability, protection scope, rebuild cost, and physical
reclaim determine the action.

## Motivation

The current policy gives generated directories three- or seven-day retention
windows. That is safer than deleting unknown content, but it does not match the
machine's storage dynamics.

The largest recoverable pool is a long tail of `target/`, `node_modules/`,
`.next/`, and `.turbo/` trees spread across many worktrees. Many belong to
worktrees touched inside the retention window but unlikely to be revisited
before their outputs become obsolete. Rebuilding one of those trees on the
rare return is cheaper than carrying every tree continuously and repeatedly
reaching critical disk pressure.

Active worktrees create a second accumulation problem. A single `target/` can
retain months of obsolete incremental sessions, dependency versions, feature
combinations, profiles, fingerprints, and cross-target outputs. Preserving the
whole directory because the checkout is active allows unbounded growth.

Manual storage recovery has repeatedly found tens of GiB by deleting obviously
rebuildable trees. Those recoveries did not damage ongoing source work. This is
evidence that source recency is a weak proxy for artifact value and that the
controller is leaving the dominant reclaim pool untouched.

The design goal is therefore not to reproduce a more precise seven-day TTL.
It is to automate the judgment behind the effective manual workflow while
retaining stronger safety evidence and exact execution boundaries.

### Measured machine evidence

The first bounded `~/Code` census on 2026-08-03 reached its 2,000,000-entry
limit after observing 1,207,830 files and 526,988 directories. The reported
89.46 GiB private, 98.18 GiB allocated, and 95.12 GiB logical totals are
therefore lower bounds rather than a complete baseline.

Even that partial traversal changed the priority picture. Four worktree-family
containers accounted for at least 38.23 GiB private: `v0.worktrees`
17.36 GiB, `local-sandbox.worktrees` 10.69 GiB, `locald.worktrees` 6.87 GiB,
and `v0-worktree-gc.worktrees` 3.31 GiB. The generated
`locald-b23-generated-json-files-recovery/target` accounted for at least
16.53 GiB, while `vscode-ai-gateway/.logs` accounted for at least 7.94 GiB.

These observations route work to the appropriate authority. A worktree-family
container is a discovery domain whose generated descendants and source
worktrees have different authority. The large `target/` routes to granular or
owner-free generated cleanup according to current ownership. The log tree
remains owner-mediated until its producer supplies a retention and recovery
contract.

## Goals

- Keep the Data volume in a healthy free-space band, initially 100–150 GiB,
  without recurring manual disk-map cleanup.
- Preserve tracked, uncommitted, detached, or otherwise valuable source state.
- Reclaim owner-free rebuildable trees without requiring the source worktree
  itself to become stale.
- Prevent active build trees from accumulating superseded generations without
  deleting the current working set.
- Measure and rank candidates using APFS-private reclaim rather than path size
  alone.
- Revalidate ownership, containment, locks, and protection immediately before
  mutation and stop when the live free-space target is reached.
- Keep every destructive action attributable to a domain recovery contract.
- Make bounded or failed traversal explicit in every affected aggregate, so
  no lower-bound total is presented as a complete machine census.
- Account for long-tail entry counts and first-level storage families, not
  only the largest retained paths.
- Classify every material machine domain as managed, report-only, excluded, or
  unclassified before calling controller coverage sufficient.

## Non-goals

- Inferring that arbitrary large data is disposable.
- Deleting dirty worktrees automatically.
- Treating application databases, conversations, evidence, VMs, or shared
  package stores as generic generated directories.
- Deleting or compacting Parallels virtual machines through this policy.
- Guaranteeing that an artifact will never need to be rebuilt.
- Preserving every cache that might make a future command faster.

## Terminology

### Source state

Source state is the worktree, tracked and untracked project content, Git
identity, branch or detached-commit reachability, and human task context. Its
loss can be irreversible or expensive to reconstruct.

### Rebuildable state

Rebuildable state is output whose recovery operation is understood: compiler
artifacts, framework caches, project-local dependency installations, and
similar generated trees. Its deletion spends time or network access but does
not delete the source inputs needed to recreate it.

### Active ownership

Active ownership is positive evidence that a process or task currently relies
on an artifact. Examples include open handles, process cwd or mapped files,
Cargo locks, a live dev server, an owning-tool transaction, or an explicit
artifact-retention lease.

A recent commit, source mtime, or worktree creation date is not active
ownership by itself.

### Owner-free

An artifact is owner-free when ownership evidence is complete and no current
owner, lock, or artifact-specific protection applies. Unknown or incomplete
ownership fails closed.

## Design principles

### Source durability and artifact recoverability are independent

A dirty worktree is not eligible for whole-worktree removal. An ignored,
untracked, owner-free `target/` inside that worktree may still be eligible for
artifact cleanup. Conversely, a clean old worktree does not make an unknown
application database disposable.

### Current use matters more than recent use

The controller should protect a build that is running now. It should not pin
many GiB merely because a repository was touched yesterday. Recency can reduce
priority or provide a short anti-thrash grace period, but it does not establish
ownership.

### Expected recovery cost matters more than cache possibility

Almost every cache might be useful again. The relevant tradeoff is the
expected cost of rebuilding it: the likelihood of near-term reuse multiplied
by rebuild cost, compared with its certain disk cost and the operational cost
of recurring pressure.

The controller does not need a perfect probability model. Live ownership,
rebuild-cost class, recent artifact activity, and physical reclaim provide a
better ordering than a binary age threshold.

### Pressure changes willingness to rebuild, not safety

Pressure may admit younger or more expensive rebuildable candidates. It never
bypasses source containment, tracked-file checks, ownership completeness,
locks, protections, or execution-time revalidation.

### Coverage precedes control claims

The controller can govern only the storage domains it has both observed and
routed to an authority contract. Entry-budget exhaustion leaves the affected
totals as observed lower bounds. A scan error leaves an incomplete observation
because concurrent change can move a total in either direction. The default
one-filesystem boundary defines the requested scope rather than silently
granting authority beyond it. A precise APFS-private measurement of the visited
files does not make a partial traversal complete.

Coverage reporting therefore preserves traversal completion independently
from byte-measurement completion. It also retains file and directory counts
and first-level family totals so millions of small paths remain visible even
when no single child dominates the report. Worktree containers are discovery
domains rather than reclaim estimates; owner-mediated and unclassified domains
remain visible without receiving deletion authority.

If the eligible safe pool cannot close a configured pressure deficit, the
controller must distinguish a durable-space limit from a coverage gap. A
capped census cannot prove that the remaining space is durable.

## Three-tier cleanup strategy

### Tier 1: granular cleanup of actively owned worktrees

An active worktree may retain its current generated working set while
superseded generations are pruned in place.

For Cargo targets, the initial strategies are:

- remove stale rustc incremental sessions;
- reset inactive host and cross-target profiles as coherent units;
- retain profiles with live or incomplete process-ownership evidence;
- prune fingerprint-associated outputs through a verified owner operation;
- enforce an optional size budget while preserving locked or recently active
  profiles;
- retain shared, external, custom-profile, or otherwise unclassified layouts.

Other domains need equally explicit owner contracts. Granular pruning must not
be approximated by deleting arbitrary old files from private layouts.
Cargo profile reset therefore retains this candidate-scoped ownership check
even when broad generated-directory ownership checking is disabled.

### Tier 2: coarse cleanup of owner-free generated trees

When a worktree has no current artifact owner, complete generated roots become
eligible for wholesale removal even if the source worktree is recent or dirty.

An exact root is eligible only when:

- it is canonically contained by the owning worktree;
- it is a non-symlink directory and cannot escape through a nested repository
  boundary;
- Git proves it contains no tracked files;
- its generated kind has a documented recovery operation;
- open-handle and owning-tool evidence is complete and owner-free;
- no artifact-scoped or legacy broad protection applies;
- execution can quarantine or remove the exact revalidated identity.

Initial rebuild-cost classes are:

- **low:** `.turbo`, `.next`, framework caches, and equivalent derived state;
- **medium:** project-local `target/` trees with verified Cargo ownership;
- **higher:** project-local `node_modules/` trees whose package-manager inputs
  remain available.

The higher class is still rebuildable and eligible under sufficient pressure.
Shared pnpm stores, download caches, Docker data, and VM disks remain separate
owner-mediated domains.

### Tier 3: conservative whole-worktree cleanup

Whole-worktree removal remains governed by source-state evidence:

- never remove the current worktree;
- retain dirty or otherwise uncommitted source;
- retain detached worktrees unless reachability is explicitly preserved;
- honor source protections and active task ownership;
- treat an exact-head open pull request as positive retention evidence;
- allow an exact-head merged pull request to replace the ordinary inactivity
  window only after a short grace period and complete GitHub evidence;
- require conservative source inactivity when no terminal lifecycle signal is
  available, plus a fresh Git recheck;
- preserve the branch or commit independently of artifact policy.

PR association uses retained PR head-branch metadata for discovery and an exact
head-OID match for authority. This preserves squash- and rebase-merge evidence
without letting a branch-name match authorize removal. Planning records the
GitHub repository, PR number, state, PR head name and OID, merge time,
observation time, and completeness. A force-pushed, locally advanced, reused,
or otherwise different branch head does not inherit an older PR's terminal
state. Any exact open PR wins over merged evidence. GitHub outages, pagination,
unknown states, or incomplete process ownership retain the worktree.
Immediately before removal, the controller rechecks the Git common directory,
worktree HEAD, branch, status digest, PR evidence, process ownership, and
protections. Removal does not use force and does not delete the local branch.

Artifact cleanup should usually reclaim the expensive part long before a
worktree reaches this tier.

## Protection scopes

The existing recursive protection model protects a path and every descendant.
That is safe, but a worktree lease consequently pins every rebuildable tree and
reintroduces the source/artifact conflation this RFC removes.

The protection model should gain explicit scopes:

- **source protection:** prevents worktree removal and metadata pruning but
  does not implicitly retain rebuildable descendants;
- **artifact protection:** retains an exact generated root or artifact class,
  typically to preserve a warm validation or release cache;
- **runtime protection:** short-lived ownership for a running operation and its
  outputs;
- **legacy broad protection:** preserves today's recursive semantics during
  migration.

Existing leases remain broad until explicitly migrated. The tool must never
silently weaken an existing protection. New workflows should create source and
artifact leases separately so source safety does not pin unrelated caches.

## Controller behavior

### Healthy-space routine

Routine operation prevents accretion before pressure becomes urgent:

1. inventory configured repository roots with a bounded worker and entry
   budget, retaining completion and lower-bound evidence for every displayed
   aggregate;
2. granularly prune superseded state in actively owned artifacts;
3. rank owner-free generated roots by rebuild-cost class, APFS-private reclaim,
   artifact activity, and age;
4. remove enough low-cost idle state to maintain a healthy reserve without
   attempting to empty every cache;
5. verify realized free-space change and record rebuild decisions.

A short cooldown may avoid deleting output immediately after a completed
build. The cooldown is anti-thrash behavior, not a durability promise.

### Pressure recovery

When free space falls below the entry threshold, initially 100 GiB, the
controller proceeds through rebuild-cost classes until live free space reaches
the target, initially 150 GiB:

1. finish routine-eligible actions;
2. admit owner-free low-cost roots regardless of ordinary artifact age;
3. admit medium and then higher-cost roots as needed;
4. consider conservatively stale whole worktrees only after rebuildable state;
5. stop and report the remaining owner-mediated or durable domains rather than
   widening deletion authority automatically.

If traversal was incomplete, the stop report records a coverage gap rather
than describing the observed eligible pool as exhaustive. The next measurement
slice may subdivide and resume the affected root, but it cannot turn cached
inventory into mutation authority; exact execution still performs its own
fresh guards.

Candidates are processed in bounded waves. Each wave refreshes the repository
plan and ownership evidence; each exact path retains its own measurement,
protection guard, identity check, and live free-space stop check.

### Ranking

Safety gates determine eligibility. Ranking determines which eligible rebuild
cost to spend first.

Within a filesystem, order by:

1. operation tier: superseded-state granular cleanup, then owner-free coarse
   cleanup, then source-safe whole-worktree cleanup;
2. qualitative rebuild-cost class within the tier;
3. larger complete APFS-private reclaim;
4. lower evidence of likely near-term reuse;
5. older artifact activity as a stable tie-breaker.

Source-worktree age is not a primary generated-artifact ranking key.

## Configuration direction

Artifact policy should describe behavior rather than overload one day count.
The eventual configuration needs separate concepts for:

- free-space entry and target thresholds;
- active-artifact granular strategies and size budgets;
- owner-free coarse deletion by artifact class;
- optional anti-thrash cooldowns;
- source-worktree retention;
- source, artifact, runtime, and legacy protection scopes;
- rebuild-cost ordering and per-domain execution limits.

Existing elapsed-day and workday settings remain readable during migration.
They can continue to supply evidence or cooldowns, but should not be the sole
authority for owner-free rebuildable-state retention.

## Observability and learning

Every generic inventory observation should record:

- requested root, observation time, and consumed entry budget;
- configured fair-share budget and pending directories when the budget is
  exhausted;
- structured traversal outcome and scan errors;
- per-aggregate traversal completeness, independently from private-byte
  measurement completeness;
- observed file and directory counts plus logical, allocated, and
  APFS-private totals with their completion semantics.

The composed machine coverage ledger and owner collectors should additionally
classify material families as managed, report-only, excluded, or unclassified.
Generic inventory supplies physical evidence and never assigns cleanup
authority.

Every planned or executed action should record:

- source and artifact ownership classification;
- protection scope and matching lease;
- recovery operation and rebuild-cost class;
- activity, cooldown, and ranking evidence;
- logical, allocated, and APFS-private measurements with completeness;
- exact execution identity and preflight result;
- estimated and realized reclaim;
- later rebuild evidence when the owning tool naturally recreates the tree.

Rebuild observations let the policy improve empirically. Frequent immediate
rebuilds indicate excessive churn or an insufficient cooldown. Large trees
that remain absent validate aggressive coarse cleanup. The controller should
optimize the machine's steady state from this evidence rather than canonizing
an arbitrary TTL.

### Privileged ownership evidence

The deletion controller remains unprivileged. On macOS, a separate minimal
LaunchDaemon may provide process-path evidence that the current user cannot
observe. The root-owned service captures one machine-readable global
`/usr/sbin/lsof` snapshot and fails closed on nonzero status or warning output,
then filters that complete evidence to canonical roots from a root-owned
allowlist. Its protocol is versioned, bounded, and authenticated by peer UID.
The helper returns only ownership evidence; it has no protection, planning,
quarantine, or deletion operation.

The helper ships independently of cleanup integration. Scheduled policy may
select `auto`, `privileged_helper`, or `global_lsof`. The backward-compatible
`auto` mode retains native enumeration and its existing fallback. Required
`privileged_helper` mode routes the initial plan, each routine-repository
snapshot, and each bounded pressure epoch through one helper request and never
falls back to ordinary-user evidence. If the helper is unavailable, rejects the
roots, exceeds a bound, or returns incomplete evidence, the routine repository
is skipped or the pressure epoch stops.

The client still revalidates containment, tracked content, source identity,
measurement, protection, mount boundaries, Cargo locks, quarantine, and source
parity. Aggregate metrics identify the helper protocol and executable hash,
requested roots, observations, duration, and completeness. Installation and
strict policy selection remain separate supervised gates.

Integration advances the ownership protocol to v2 because complete responses
now require the helper executable SHA-256. The client rejects a v1 helper rather
than accepting evidence whose binary identity cannot be recorded; the helper
and client are therefore installed as a verified release pair.

Execution requests only actionable worktree roots and divides any remaining
set above 2,048 roots into bounded helper requests. All batches must report the
same protocol and helper digest, and one incomplete batch rejects the whole
epoch. A genuinely missing worktree tombstone needs no ownership probe, but a
permission or filesystem error while inspecting a requested root is incomplete
evidence rather than absence.

## Implementation plan

The phases are ordered by expected effect. Tier 2 owner-free coarse cleanup is
the main near-term reclaim mechanism. Tier 1 granular pruning keeps active
trees from rebuilding the same long tail. Tier 3 whole-worktree deletion is
already conservative and is not the first place to spend implementation risk.

The current bet is measurement closure. This delivery makes capped and failed
inventory visibly partial at the root and retained-aggregate levels. The next
slice should segment oversized roots into resumable, non-overlapping census
units and reconcile their family totals. Classification and targeted adapters
then turn material managed regions into candidates without treating inventory
size as deletion authority. Active-target size budgets remain the next cleanup
capability after the census can explain where the long tail lives.

### Phase 1: separate policy domains

- Model source retention independently from generated-artifact retention.
- Add scoped protections while preserving legacy recursive leases.
- Report active ownership separately from source recency.
- Keep dirty-worktree protection for whole-worktree removal without granting
  automatic artifact retention.

### Phase 2: complete the generated-root controller

- Landed: bounded generated discovery, Git containment checks, APFS
  measurement, owner-free classification, rebuild-cost ordering, exact
  manifest execution, bounded ownership epochs, and privileged ownership
  evidence.
- Landed: project-local `node_modules/` follows higher rebuild-cost classes;
  execution retains exact source/inode identity, ownership, protection,
  quarantine, Cargo-lock, and realized-reclaim evidence.
- In delivery: distinguish traversal completion from private-measurement
  completion at the root and retained-aggregate levels.
- Next: segment and resume oversized inventory roots without double-counting,
  then classify their material generated descendants through existing exact
  execution contracts.

### Phase 3: strengthen active-target pruning

- Measure the residual composition of active Cargo targets.
- Apply incremental pruning and coherent profile reset routinely.
- Add a reviewed size-budget strategy for active targets.
- Reset inactive host and cross-target Cargo profiles at their lock-coordinated
  profile boundaries. Keep shared, custom-profile, and otherwise unclassified
  layouts fail-closed until their current working set can be identified safely.

### Phase 4: machine coverage closure and controller calibration

- The daily controller is running against its configured partial root set;
  preserve that operation while measuring whether its managed safe pool can
  plausibly close the 100–150 GiB target deficit.
- Run completion-aware report-only census across every configured root and
  record material domains as managed, report-only, excluded, or unclassified.
- Compare proposed actions and unexplained regions with manual disk-map
  judgments, including both large paths and high-count long tails.
- Segment capped roots and reconcile completed segments before treating a
  family total as a machine baseline.
- Keep Parallels excluded and untouched. Its running state is not a standing
  machine lock; unrelated inventory may proceed while concrete disk contention
  can serialize a broad scan.
- Treat repeated target-band recovery without manual large-directory cleanup
  as the remaining controller acceptance proof.

### Phase 5: owner-mediated domains

- Add pnpm store, Docker/OrbStack, IDE diagnostics, and similar collectors only
  through their owning interfaces.
- Keep durable databases, evidence, and VM storage report-only until their
  owners provide explicit retention/export contracts.

## Acceptance criteria

Full machine-wide controller acceptance holds when all of the following are
true:

- a dirty worktree is never automatically removed;
- an ignored generated root inside a dirty worktree can be independently
  classified and reclaimed when owner-free;
- a recently touched but owner-free worktree does not automatically retain its
  generated roots under pressure;
- a running build, dev server, package manager, or active lock prevents coarse
  deletion;
- active Cargo targets lose superseded state without losing their current
  locked working set;
- legacy broad protections remain broad, while scoped source protections no
  longer pin unrelated generated roots;
- execution refuses incomplete ownership, tracked content, symlink escapes,
  changed identities, or protected candidates;
- a capped inventory marks the root and every affected retained aggregate as
  an observed lower bound, a failed scan marks incomplete observations, and
  completed siblings remain exact;
- the coverage ledger explains each material storage family as managed,
  report-only, excluded, or unclassified, without counting worktree
  containers themselves as reclaim;
- pressure reporting distinguishes an exhausted safe pool from incomplete
  discovery and shows whether the managed pool can plausibly close the target
  deficit;
- pressure recovery stops from live `df` evidence at the configured target;
- repeated scheduled cycles keep free space inside the target band without
  recurring manual large-directory cleanup;
- Parallels and other durable owner-managed state remain outside generic
  generated cleanup.

## Drawbacks

Aggressive coarse cleanup spends developer time on occasional rebuilds. Large
dependency installs may need network access, and a deleted build cache may make
the next command noticeably slower. Scoped protections also introduce a more
explicit lease model than today's single recursive rule.

The controller is more complex than TTL cleanup because it distinguishes live
ownership, source safety, artifact recoverability, and rebuild cost. That
complexity reflects the real storage domains rather than hiding them in one
number.

## Alternatives

### Keep three- or seven-day artifact TTLs

This is simple and predictable, but the observed long tail inside the window
is large enough to cause recurring pressure. It also allows active targets to
accrete indefinitely.

### Delete whole worktrees sooner

This reclaims generated state but spends source-state risk to solve an artifact
problem. It is especially inappropriate for dirty or context-rich worktrees.

### Continue manual disk-map cleanup

Manual review supplies strong semantic judgment but is reactive, inconsistent,
and difficult to audit. It also does not prevent active target accretion.

### Delete every idle cache immediately

This maximizes space but can create rebuild thrash. Bounded routine cleanup,
rebuild-cost ordering, and an optional short cooldown preserve most of the
benefit without treating cache possibility as durability.

## Unresolved questions

1. What short routine cooldown best avoids rebuild thrash: elapsed hours, one
   completed workday, or an adaptive value learned from rebuild observations?
2. Which evidence should classify a task as actively benefiting from warm
   artifacts when no process currently has them open?
3. Should project-local `node_modules/` require a lockfile and locally available
   package-manager store before entering the higher-cost class, or is the
   package manifest alone sufficient?
4. What active `target/` size budget preserves a useful working set across the
   common debug, release, and test profiles?
5. How should existing broad leases be migrated into source and artifact
   scopes without surprising current workflows?
6. Should the steady-state controller aim directly for 150 GiB whenever it
   enters below 100 GiB, or use a smaller routine reserve and keep 150 GiB as
   the pressure-recovery target?
