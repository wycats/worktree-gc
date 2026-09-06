# Archived-child migration: Rust PER

## Purpose and current bet

Keep developer storage bounded while preserving durable work and recoverable
history. This bet packages first-party migration of archived legacy leaf tasks
into bounded batches, with verified physical-external originals and usable
recovery. Production implementation and tests belong in Rust.

PR #39 at `c3f06455646b0b3162109843e098ab445bd73249` is the port baseline.
The Python pilot remains historical evidence; the shipped Python operator,
Python fixture tests, and Python CI setup will be replaced.

Organic proof is an ordinary bounded batch that reduces retained task storage
and restores a chosen original as a readable, unarchivable isolated task.
Implementation tests alone do not establish unattended activation or
population-wide savings. Installation, live migration, and scheduling retain
their separate approval boundaries.

## Prepare findings

The September 5 pilot proved one compressed original's migration and later
history restoration. Its restoration reused an initialized index. Its initial
baseline startup, however, copied a rollout into a new home and then observed
native indexing. The current export-only recovery command does not itself
establish that indexing step.

Available Codex source at `cd769ed29c0e2942d59eb2e12c4fd176b64a31d2`
provides the expected route: app-server startup initializes the state runtime,
waits for metadata backfill, and imports both live and archived rollouts,
including compressed files. Native startup should register an original placed
in an absent isolated home. Installed-version qualification remains necessary.

The installed qualification target is Codex 0.153.4, SHA-256
`4ca47945439f9251fe35f4cbe071369192cd9a6c5a3a17b75c7a11ad548a9c7f`.

Physical topology requires more than filesystem device numbers. Data currently
uses an APFS volume in virtual container disk3 backed by physical disk0; the
ExFAT external SSD is on disk4. These names are observations, not policy
constants. Runtime verification must resolve physical stores afresh and require
known, externally attached backup storage disjoint from source storage.

## First Execute boundary: native registration qualification

Use only disposable tiny synthetic fixtures, first plain and then compressed:

1. Create native-valid archived-child metadata and sentinel history in a fresh
   isolated home with no SQLite index, credentials, or copied configuration.
2. Start the pinned native app-server in a network-denied, write-contained
   sandbox with isolated HOME/CODEX_HOME/XDG/temp paths. Disable background
   compression and migration for this invocation.
3. Initialize, read the exact task with history, unarchive it, and read it again.
   Never start a model turn.
4. Verify native index creation, exact sentinel history before/after unarchive,
   isolated file paths, unchanged synthetic original, and complete process-group
   teardown. Bound runtime and captured output.

A precondition miss or empty history does not qualify recovery. Resolve that
specific mechanism before depending on it in the full port. No live corpus,
external originals, helper, scheduler, or VM state is in this boundary.

## Full Rust port boundary after qualification

Keep the existing command names and policy defaults. Implement typed policy,
planning, journal, migration, and recovery modules in Rust, using the pinned
native binary as the sole live rollout/index writer. Prefer existing crates
and infrastructure; introduce explicit SQLite/plist/signal dependencies only
where the required guarantees need them. The configured zstd executable can
remain a bounded tool dependency without retaining Python.

All six current review findings are acceptance requirements:

- Recovery invokes native registration and proves usable read/unarchive rather
  than returning success after a byte export alone.
- External-backup checks require known disjoint physical disks, not merely
  different mounts, volume UUIDs, or `st_dev` values.
- Revalidate the exact original's identity and hash after native apply, just
  before publishing a verified journal.
- Hold protection authority over the complete native mutation surface,
  including index, sidecars, locks, and rollout temporaries; cover journal and
  backup mutations as applicable.
- Revalidate active lease paths canonically and reject symlink/metadata drift.
- Reject hardlinked index and existing writable sidecars before observation and
  again before native mutation.

Preserve leaf/parent reconciliation, archive grace and activity checks, strict
policy parsing, ordered continuation and session-metadata parity, raw expansion
budgets, count/byte/time/capacity limits, durable uncertain-outcome journals,
original retention, and separate stored-byte/filesystem-free-space accounting.

Two reuse hazards need explicit tests: the existing protection helper has a
`cfg(test)` bypass, so migration fixtures need a real registry-path seam; the
general bounded command helper only reaps the direct child, so migration needs
owned process-group teardown with TERM/HUP cancellation and journal unwinding.

## Review and rollout

### Native registration qualification result

On 2026-09-06 at 02:02 UTC, the ignored Rust integration qualification passed
against the pinned shipped binary for both plain and compressed synthetic
archived children. Each fresh store began without SQLite, acquired its archived
row through native startup, returned nonempty sentinel history, and preserved
that history and original file hashes through native unarchive and reread.
Compilation took 5.71 seconds and the test took 9.90 seconds. The fixture/native
process tree was absent after teardown; live stores were untouched.

This verifies the registration substrate. Production signal-safe cancellation,
complete protection coverage, and the other operator guards remain part of the
Rust port. The supervised harness's RAII teardown does not itself establish
TERM/HUP handling for the production operator.

Independent Review compares the implementation and qualification evidence to
these predictions, with special attention to recovery usability and authority
coverage. Port the existing fixtures plus new review regressions to Rust.
Validate check, focused tests, supplemental workspace suite, strict Clippy,
formatting, and teardown in a coordinated bounded lane.

Retain the historical unskipped 391/393 result separately from supplemental
runs excluding the two known live-ownership tests. Do not describe those runs
as an unqualified full-suite success.

After local review and exact-head publication/CI/Codex review, request separate
merge consent. A reviewed Rust implementation qualifies the path toward organic
proof; live activation and the first real batch remain pending until their
explicit boundary is approved.

## PER outcome: Rust implementation qualification

The Rust port replaces the embedded Python operator and Python fixture suite.
Independent review identified two additional boundaries, now covered by Rust:
native commands pin `sqlite_home` and `log_dir` to protected locations, and
SQLite observation uses `readonly_shm=1` while preserving WAL visibility.

The first WAL fixture exposed SQLite's process-local shared-memory-node reuse:
a reader in the same process as a writer can inherit its writable mapping.
The corrected fixture runs its writer in a bounded Rust child, matching Codex's
separate-process ownership. It preserves the strict database/WAL/SHM identity
and SHA-256 oracle and confirms the latest WAL row remains visible.

Local evidence on 2026-09-06:

- Locked all-target/all-feature check and strict Clippy passed.
- The focused migration suite passed 61 tests, including real TERM/HUP teardown.
- The supplemental workspace run passed 452 library and 32 CLI tests. The two
  historical ownership exclusions remain explicit; native acceptance tests
  were ignored in that ordinary suite.
- The production `register_history` qualification passed separately for plain
  and compressed synthetic originals against pinned Codex 0.153.4. Both cases
  verified native indexing, nonempty read/unarchive/read history parity, exact
  original bytes, and isolated unarchived paths. Runtime was 9.54 seconds.
- Final fixture/process/target-handle teardown was clear. No live corpus,
  external backup, configuration, scheduler, or installation was changed.

Implementation validation and synthetic production-registration proof are
complete. Publication, fresh exact-head review, merge consent, and a separately
approved live batch remain the next boundaries. Population-wide savings and
live-batch organic proof remain pending.
