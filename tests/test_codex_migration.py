"""Pure/fixture operator tests; no live Codex home, model request or migration."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location(
    "migration", Path(__file__).resolve().parents[1] / "src/codex_migration.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


@contextlib.contextmanager
def database(path):
    with contextlib.closing(sqlite3.connect(path)) as c, c:
        yield c


def record(kind, payload):
    return {"type": kind, "payload": payload}


def rollout(tid, padding=""):
    return b"".join(m.encoded(r) + b"\n" for r in [
        record("session_meta", {"id": tid, "history_mode": "legacy"}),
        record("response_item", {"type": "message", "text": padding}),
        record("compacted", {"replacement_history": [{"type": "message", "text": "checkpoint"}]}),
        record("response_item", {"type": "reasoning"}),
        record("turn_context", {"cwd": "/repo"}),
    ])


def row(tid=None, parent=None):
    tid = tid or str(uuid.uuid4())
    return {"id": tid, "source": json.dumps({"subagent": {"thread_spawn": {
        "parent_thread_id": parent}}}) if parent else 'cli',
        "history_mode": "legacy", "archived": 1, "archived_at": 100,
        "updated_at": 100, "is_pinned": 0, "rollout_path": "/unused"}


class FakeRuntime:
    calls = []
    corrupt = False
    fail_native = False

    def __init__(self, p):
        self.p = p

    def guard(self):
        pass

    def volume(self):
        pass

    def quiet(self, path=None):
        pass

    def verify_binary(self):
        pass

    def context(self, path, tid):
        return m.continuation([path.read_bytes()], tid, self.p["max_raw_bytes_per_task"])

    def native(self, tid, apply):
        self.calls.append((tid, apply))
        if self.fail_native and apply:
            raise m.Refusal("native failure")
        if apply:
            rows, _ = m.index_snapshot(self.p["codex_home"])
            r = next(r for r in rows if r["id"] == tid)
            path = Path(r["rollout_path"])
            lines = path.read_bytes().splitlines()
            # Simulate native removal of obsolete inherited history, retaining
            # the latest checkpoint and all subsequent continuation records.
            lines.pop(1)
            if self.corrupt:
                lines.append(m.encoded(record("response_item", {"type": "message", "text": "drift"})))
            path.write_bytes(b"\n".join(lines) + b"\n")
            with database(self.p["codex_home"] / "state_5.sqlite") as c:
                c.execute("update threads set history_mode='paginated' where id=?", (tid,))
        return {"outcomes": [{"thread_id": tid, "status": "migrated" if apply else "eligible"}]}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.home, self.backup, self.journals = (self.root / x for x in ("home", "backup", "journals"))
        for p in (self.home, self.backup, self.journals, self.home / "archived_sessions"):
            p.mkdir()
        self.parent = row()
        self.child = row(parent=self.parent["id"])
        self.source = self.home / "archived_sessions" / ("rollout-" + self.child["id"] + ".jsonl")
        self.child["rollout_path"] = str(self.source)
        self.source.write_bytes(rollout(self.child["id"], "old inherited " * 100))
        os.utime(self.source, (100, 100))
        with database(self.home / "state_5.sqlite") as c:
            c.execute("create table threads (id text primary key,rollout_path text,source text,"
                      "history_mode text,archived integer,archived_at integer,updated_at integer,is_pinned integer)")
            c.execute("create table thread_spawn_edges(parent_thread_id text,child_thread_id text)")
            for r in (self.parent, self.child):
                c.execute("insert into threads values (?,?,?,?,?,?,?,?)", tuple(r[k] for k in (
                    "id", "rollout_path", "source", "history_mode", "archived", "archived_at", "updated_at", "is_pinned")))
        self.policy = {"codex_home": self.home, "backup_root": self.backup, "journal_root": self.journals,
                       "enabled": True, "grace_hours": 24, "max_tasks": 4,
                       "max_source_bytes": m.GIB, "max_raw_bytes_per_task": m.GIB,
                       "max_seconds": 1800, "min_free_bytes": m.GIB, "exclude_threads": [],
                       "backup_volume_uuid": "fixture", "codex_sha256": "0" * 64,
                       "policy_sha256": "1" * 64}
        self.free = patch.object(m, "free_bytes", return_value=100 * m.GIB)
        self.free.start()
        self.protections = patch.object(m, "protection_guard", lambda: contextlib.nullcontext([]))
        self.protections.start()
        FakeRuntime.calls = []
        FakeRuntime.corrupt = False
        FakeRuntime.fail_native = False

    def tearDown(self):
        self.protections.stop()
        self.free.stop()
        self.tmp.cleanup()

    def candidate(self):
        rows, edges = m.index_snapshot(self.home)
        return m.plan(self.home, rows, edges, self.policy, time.time())["selected"][0]

    def test_dry_run_has_no_write_or_native_surface(self):
        before = self.source.read_bytes()
        result = m.batch(self.policy, runtime_factory=FakeRuntime)
        self.assertEqual(len(result["plan"]["selected"]), 1)
        self.assertEqual(list(self.journals.iterdir()), [])
        self.assertEqual(list(self.backup.iterdir()), [])
        self.assertEqual(FakeRuntime.calls, [])
        self.assertEqual(before, self.source.read_bytes())

    def test_scalar_root_sources_preserve_structured_child_lineage(self):
        for source in ("cli", "vscode", "exec", "mcp", "unknown", '"cli"'):
            with self.subTest(source=source):
                with database(self.home / "state_5.sqlite") as c:
                    c.execute("update threads set source=? where id=?", (source, self.parent["id"]))
                candidate = self.candidate()
                self.assertEqual(candidate["parent_id"], self.parent["id"])
                self.assertEqual(candidate["row"]["id"], self.child["id"])

    def test_malformed_structured_lineage_still_refuses(self):
        with database(self.home / "state_5.sqlite") as c:
            c.execute("update threads set source=? where id=?", ('{"subagent":', self.parent["id"]))
        with self.assertRaises(json.JSONDecodeError):
            self.candidate()

    def test_batch_native_backup_continuation_and_parent_parity(self):
        before = self.source.read_bytes()
        result = m.batch(self.policy, True, FakeRuntime)
        j = json.loads(Path(result["results"][0]["journal"]).read_bytes())
        self.assertEqual(j["phase"], "verified")
        self.assertEqual(Path(j["backup"]).read_bytes(), before)
        self.assertEqual(j["before_context"], j["after_context"])
        self.assertGreater(j["file_bytes_reduced"], 0)
        rows, _ = m.index_snapshot(self.home)
        self.assertEqual(next(r for r in rows if r["id"] == self.parent["id"]), self.parent)
        self.assertEqual(FakeRuntime.calls, [(self.child["id"], False), (self.child["id"], True)])
        self.assertEqual(m.batch(self.policy, True, FakeRuntime)["results"], [])

    def test_disabled_policy_does_not_create_journal_or_native_call(self):
        self.policy["enabled"] = False
        with self.assertRaisesRegex(m.Refusal, "disabled"):
            m.batch(self.policy, True, FakeRuntime)
        self.assertEqual(list(self.journals.iterdir()), [])
        self.assertEqual(FakeRuntime.calls, [])

    def test_native_failure_preserves_backup_and_blocks_next_batch(self):
        FakeRuntime.fail_native = True
        with self.assertRaisesRegex(m.Refusal, "native failure"):
            m.batch(self.policy, True, FakeRuntime)
        j = json.loads(next(self.journals.glob("*.json")).read_bytes())
        self.assertEqual(j["phase"], "recovery_required")
        self.assertTrue(Path(j["backup"]).is_file())
        with self.assertRaisesRegex(m.Refusal, "recovery pending"):
            m.batch(self.policy, True, FakeRuntime)
        self.assertEqual(len(FakeRuntime.calls), 2)

    def test_continuation_mismatch_is_durable_and_never_auto_restores(self):
        FakeRuntime.corrupt = True
        with self.assertRaisesRegex(m.Refusal, "continuation mismatch"):
            m.batch(self.policy, True, FakeRuntime)
        j = json.loads(next(self.journals.glob("*.json")).read_bytes())
        self.assertEqual(j["phase"], "recovery_required")
        self.assertIn(b"drift", self.source.read_bytes())
        self.assertNotIn(b"drift", Path(j["backup"]).read_bytes())

    def test_removed_edge_only_parent_requires_recovery(self):
        with database(self.home / "state_5.sqlite") as c:
            c.execute("update threads set source='cli' where id=?", (self.child["id"],))
            c.execute("insert into thread_spawn_edges values (?,?)", (self.parent["id"], self.child["id"]))
        class ChangedRuntime(FakeRuntime):
            def native(inner, tid, apply):
                result = super().native(tid, apply)
                if apply:
                    with database(inner.p["codex_home"] / "state_5.sqlite") as c:
                        c.execute("delete from thread_spawn_edges where child_thread_id=?", (tid,))
                return result
        with self.assertRaisesRegex(m.Refusal, "parent lineage drift"):
            m.batch(self.policy, True, ChangedRuntime)
        j = json.loads(next(self.journals.glob("*.json")).read_bytes())
        self.assertEqual(j["phase"], "recovery_required")
        self.assertTrue(Path(j["backup"]).is_file())

    def test_conflicting_parent_edge_requires_recovery(self):
        class ChangedRuntime(FakeRuntime):
            def native(inner, tid, apply):
                result = super().native(tid, apply)
                if apply:
                    with database(inner.p["codex_home"] / "state_5.sqlite") as c:
                        c.execute("insert into thread_spawn_edges values (?,?)", (str(uuid.uuid4()), tid))
                return result
        with self.assertRaisesRegex(m.Refusal, "parent lineage drift"):
            m.batch(self.policy, True, ChangedRuntime)
        j = json.loads(next(self.journals.glob("*.json")).read_bytes())
        self.assertEqual(j["phase"], "recovery_required")

    def test_session_metadata_drift_is_durable(self):
        class ChangedRuntime(FakeRuntime):
            def native(inner, tid, apply):
                result = super().native(tid, apply)
                if apply:
                    rows, _ = m.index_snapshot(inner.p["codex_home"])
                    path = Path(next(r["rollout_path"] for r in rows if r["id"] == tid))
                    records = [json.loads(line) for line in path.read_bytes().splitlines()]
                    records[0]["payload"]["base_instructions"] = {"text": "unexpected replacement"}
                    path.write_bytes(b"".join(m.encoded(r) + b"\n" for r in records))
                return result
        with self.assertRaisesRegex(m.Refusal, "continuation mismatch"):
            m.batch(self.policy, True, ChangedRuntime)
        j = json.loads(next(self.journals.glob("*.json")).read_bytes())
        self.assertEqual(j["phase"], "recovery_required")
        self.assertNotEqual(j["before_context"]["session_meta"], j["after_context"]["session_meta"])

    def test_quiet_store_refusal_precedes_backup(self):
        with patch.object(FakeRuntime, "quiet", side_effect=m.Refusal("store active")):
            with self.assertRaisesRegex(m.Refusal, "store active"):
                m.batch(self.policy, True, FakeRuntime)
        self.assertEqual(list(self.backup.iterdir()), [])
        self.assertEqual(FakeRuntime.calls, [])

    def test_external_volume_refusal_precedes_backup(self):
        with patch.object(FakeRuntime, "volume", side_effect=m.Refusal("volume mismatch")):
            with self.assertRaisesRegex(m.Refusal, "volume mismatch"):
                m.batch(self.policy, True, FakeRuntime)
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_unarchive_between_plan_and_apply_refuses(self):
        candidate = self.candidate()
        with database(self.home / "state_5.sqlite") as c:
            c.execute("update threads set archived=0 where id=?", (self.child["id"],))
        with self.assertRaisesRegex(m.Refusal, "index state changed"):
            m.migrate_one(candidate, self.policy, FakeRuntime(self.policy))
        self.assertEqual(FakeRuntime.calls, [])

    def test_source_identity_drift_refuses(self):
        candidate = self.candidate()
        self.source.write_bytes(rollout(self.child["id"], "changed"))
        with self.assertRaisesRegex(m.Refusal, "identity changed"):
            m.refresh(candidate, self.policy)

    def test_rollout_traversal_outside_archive_refuses_before_native(self):
        outside = self.home / self.source.name
        outside.write_bytes(self.source.read_bytes())
        with database(self.home / "state_5.sqlite") as c:
            c.execute("update threads set rollout_path=? where id=?",
                      (str(self.home / "archived_sessions" / ".." / outside.name), self.child["id"]))
        report = m.batch(self.policy, True, FakeRuntime)
        self.assertEqual(report["plan"]["refusals"]["rollout outside archive root"], 1)
        self.assertEqual(report["plan"]["selected"], [])
        self.assertEqual(report["results"], [])
        self.assertEqual(FakeRuntime.calls, [])
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_rollout_archive_symlink_escape_refuses(self):
        outside = self.home / "outside"
        outside.mkdir()
        (outside / self.source.name).write_bytes(self.source.read_bytes())
        alias = self.home / "archived_sessions" / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        changed = dict(self.child, rollout_path=str(alias / self.source.name))
        with self.assertRaisesRegex(m.Refusal, "path alias or symlink"):
            m.rollout_path(self.home, changed)

    def test_parent_state_drift_refuses(self):
        candidate = self.candidate()
        with database(self.home / "state_5.sqlite") as c:
            c.execute("update threads set updated_at=101 where id=?", (self.parent["id"],))
        with self.assertRaisesRegex(m.Refusal, "parent index state changed"):
            m.refresh(candidate, self.policy)

    def test_new_child_in_source_or_edge_prevents_migration(self):
        candidate = self.candidate()
        with database(self.home / "state_5.sqlite") as c:
            c.execute("insert into thread_spawn_edges values (?,?)", (self.child["id"], str(uuid.uuid4())))
        with self.assertRaisesRegex(m.Refusal, "has_children"):
            m.refresh(candidate, self.policy)

    def test_recursive_protection_prevents_native_call(self):
        with patch.object(m, "protection_guard", lambda: contextlib.nullcontext([self.home])):
            with self.assertRaisesRegex(m.Refusal, "recursive protection"):
                m.batch(self.policy, True, FakeRuntime)
        self.assertEqual(FakeRuntime.calls, [])

    def test_pending_partial_journal_blocks_batch(self):
        (self.journals / "broken.pending").write_bytes(b"partial")
        with self.assertRaisesRegex(m.Refusal, "pending or unknown"):
            m.batch(self.policy, True, FakeRuntime)

    def test_native_scratch_budget_uses_raw_bytes(self):
        with patch.object(FakeRuntime, "context", return_value=({}, 60 * m.GIB)):
            with self.assertRaisesRegex(m.Refusal, "headroom"):
                m.migrate_one(self.candidate(), self.policy, FakeRuntime(self.policy))
        self.assertEqual(list(self.backup.iterdir()), [])

    def test_no_eligible_tasks_does_not_count_parent_as_child(self):
        self.policy["exclude_threads"] = [self.child["id"]]
        report = m.batch(self.policy)
        self.assertEqual(report["plan"]["selected"], [])

    def test_ambiguous_compressed_spelling_symlink_and_hardlink_refuse(self):
        compressed = Path(str(self.source) + ".zst")
        compressed.write_bytes(b"fake")
        with self.assertRaisesRegex(m.Refusal, "ambiguous"):
            m.rollout_path(self.home, self.child)
        compressed.unlink()
        link = self.root / "link"
        os.link(self.source, link)
        with self.assertRaisesRegex(m.Refusal, "hardlinked"):
            m.identity(self.source)
        link.unlink()
        self.source.rename(link)
        self.source.symlink_to(link)
        with self.assertRaisesRegex(m.Refusal, "symlink"):
            m.rollout_path(self.home, self.child)

    def test_grace_uses_archive_updated_and_file_times(self):
        now = time.time()
        parents, children = m.lineage([self.parent, self.child], [])
        ids = {self.parent["id"], self.child["id"]}
        for field in ("archived_at", "updated_at"):
            r = self.child | {field: int(now)}
            self.assertEqual(m.eligibility(r, parents, children, ids, now, 86400, []),
                             "archive_or_activity_grace")
        os.utime(self.source, None)
        self.assertEqual(m.batch(self.policy)["plan"]["selected"], [])

    def test_active_parent_does_not_hold_archived_leaf(self):
        with database(self.home / "state_5.sqlite") as c:
            c.execute("update threads set archived=0 where id=?", (self.parent["id"],))
        self.assertEqual(len(m.batch(self.policy)["plan"]["selected"]), 1)

    def test_parent_conflict_retains_candidate(self):
        with database(self.home / "state_5.sqlite") as c:
            c.execute("insert into thread_spawn_edges values (?,?)", (str(uuid.uuid4()), self.child["id"]))
        self.assertEqual(m.batch(self.policy)["plan"]["selected"], [])

    def test_byte_and_task_bounds(self):
        self.policy["max_source_bytes"] = 1
        self.assertEqual(m.batch(self.policy)["plan"]["selected"], [])
        self.assertEqual(m.batch(self.policy)["plan"]["eligible_count"], 1)

    def test_selection_obeys_count_with_many_candidates(self):
        with database(self.home / "state_5.sqlite") as c:
            for _ in range(9):
                r = row(parent=self.parent["id"])
                path = self.source.with_name("rollout-" + r["id"] + ".jsonl")
                path.write_bytes(rollout(r["id"]))
                os.utime(path, (100, 100))
                r["rollout_path"] = str(path)
                c.execute("insert into threads values (?,?,?,?,?,?,?,?)", tuple(r[k] for k in (
                    "id", "rollout_path", "source", "history_mode", "archived", "archived_at", "updated_at", "is_pinned")))
        planned = m.batch(self.policy)["plan"]
        self.assertEqual(planned["eligible_count"], 10)
        self.assertEqual(len(planned["selected"]), 4)
        self.assertEqual(planned["selected"][0]["row"]["id"], self.child["id"])

    def test_index_cap_is_explicit(self):
        with patch.object(m, "INDEX_LIMIT", 1):
            with self.assertRaisesRegex(m.Refusal, "cap exceeded"):
                m.index_snapshot(self.home)

    def test_native_process_probe_allows_only_exact_owned_pid(self):
        rt = m.Runtime(self.policy)
        evidence = b"123 /Applications/ChatGPT.app/Contents/Resources/codex\n456 /usr/bin/other\n"
        with patch.object(m, "capture", return_value=evidence):
            with self.assertRaisesRegex(m.Refusal, "store is active"):
                rt.quiet()
            rt.quiet(allowed_pids=[123])
        with patch.object(m, "capture", return_value=evidence + b"789 /Applications/ChatGPT.app/Contents/Resources/codex\n"):
            with self.assertRaisesRegex(m.Refusal, "PID 789"):
                rt.quiet(allowed_pids=[123])

    def test_missing_backup_cannot_be_recovered(self):
        result = m.batch(self.policy, True, FakeRuntime)
        journal = Path(result["results"][0]["journal"])
        j = json.loads(journal.read_bytes())
        Path(j["backup"]).unlink()
        with self.assertRaises(FileNotFoundError):
            m.recover(journal, self.root / "recovered")
        self.assertFalse((self.root / "recovered").exists())

    def test_recovery_exports_original_and_preserves_live_newer_data(self):
        original = self.source.read_bytes()
        result = m.batch(self.policy, True, FakeRuntime)
        journal = Path(result["results"][0]["journal"])
        live_after = self.source.read_bytes()
        destination = self.root / "recovered"
        import plistlib
        with patch.object(m, "capture", return_value=plistlib.dumps({"VolumeUUID": "fixture"})):
            recovered = m.recover(journal, destination)
            self.assertEqual(Path(recovered["restored"]).read_bytes(), original)
            self.assertEqual(self.source.read_bytes(), live_after)
            with self.assertRaisesRegex(m.Refusal, "already exists"):
                m.recover(journal, destination)
            with self.assertRaisesRegex(m.Refusal, "outside live"):
                m.recover(journal, self.home / "danger")

    def test_partial_recovery_is_removed_and_same_destination_can_retry(self):
        result = m.batch(self.policy, True, FakeRuntime)
        journal = Path(result["results"][0]["journal"])
        j = json.loads(journal.read_bytes())
        original = Path(j["backup"]).read_bytes()
        live_after = self.source.read_bytes()
        destination = self.root / "recovered"
        failure = m.Refusal("recovery free-space floor")
        def partial_copy(source, target, guard):
            target.write_bytes(b"partial original history")
            raise failure
        with patch.object(m, "capture", return_value=m.plistlib.dumps({"VolumeUUID": "fixture"})):
            with patch.object(m, "verified_copy", side_effect=partial_copy):
                with self.assertRaises(m.Refusal) as caught:
                    m.recover(journal, destination)
                self.assertIs(caught.exception, failure)
            self.assertFalse(destination.exists())
            restored = m.recover(journal, destination)
        self.assertEqual(Path(restored["restored"]).read_bytes(), original)
        self.assertEqual(Path(j["backup"]).read_bytes(), original)
        self.assertEqual(self.source.read_bytes(), live_after)

    def test_recovery_rejects_backup_drift(self):
        result = m.batch(self.policy, True, FakeRuntime)
        journal = Path(result["results"][0]["journal"])
        j = json.loads(journal.read_bytes())
        Path(j["backup"]).write_bytes(b"corrupt")
        import plistlib
        with patch.object(m, "capture", return_value=plistlib.dumps({"VolumeUUID": "fixture"})):
            with self.assertRaisesRegex(m.Refusal, "identity mismatch"):
                m.recover(journal, self.root / "recovered")
        self.assertFalse((self.root / "recovered").exists())


class ProtectionGuardTests(unittest.TestCase):
    def test_malformed_protection_paths_fail_closed_before_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            root = state / "worktree-gc"
            root.mkdir()
            for path in ("/home/user/.", "/home/user/../archive", "/home/user/./archive",
                         "/home/user/\narchive", "/home/user/\x7farchive", 3):
                with self.subTest(path=path):
                    registry = m.encoded({"version": 1, "leases": [
                        {"path": path, "expires_at_unix": int(time.time()) + 3600}]})
                    (root / "protections.json").write_bytes(registry)
                    with patch.dict(os.environ, {"XDG_STATE_HOME": str(state)}):
                        with self.assertRaisesRegex(m.Refusal, "invalid protection path"):
                            with m.protection_guard():
                                self.fail("malformed protection accepted")
                    self.assertEqual((root / "protections.json").read_bytes(), registry)

    def test_first_use_creates_and_locks_missing_state_directory(self):
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve() / "new-state"
            with patch.dict(os.environ, {"XDG_STATE_HOME": str(state)}):
                with m.protection_guard() as paths:
                    self.assertEqual(paths, [])
                    with (state / "worktree-gc/protections.lock").open("rb") as other:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertFalse((state / "worktree-gc/protections.json").exists())

    def test_existing_registry_retains_active_protections(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve()
            root = state / "worktree-gc"
            root.mkdir()
            registry = m.encoded({"version": 1, "leases": [
                {"path": str(state), "expires_at_unix": int(time.time()) + 3600}]})
            (root / "protections.json").write_bytes(registry)
            with patch.dict(os.environ, {"XDG_STATE_HOME": str(state)}):
                with m.protection_guard() as paths:
                    self.assertEqual(paths, [state])
            self.assertEqual((root / "protections.json").read_bytes(), registry)

    def test_symlinked_state_is_rejected_before_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            real, alias = root / "real", root / "alias"
            real.mkdir()
            alias.symlink_to(real, target_is_directory=True)
            for state in (alias, root):
                with self.subTest(state=state):
                    if state == root:
                        (root / "worktree-gc").symlink_to(real, target_is_directory=True)
                    with patch.dict(os.environ, {"XDG_STATE_HOME": str(state)}):
                        with self.assertRaisesRegex(m.Refusal, "path alias or symlink"):
                            with m.protection_guard():
                                self.fail("aliased protection state accepted")
            self.assertEqual(list(real.iterdir()), [])

    def test_state_creation_error_remains_a_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp).resolve() / "state"
            with patch.dict(os.environ, {"XDG_STATE_HOME": str(state)}):
                with patch.object(Path, "mkdir", side_effect=PermissionError("denied")):
                    with self.assertRaises(PermissionError):
                        with m.protection_guard():
                            self.fail("incomplete protection evidence accepted")


class ContinuationTests(unittest.TestCase):
    def test_session_metadata_normalizes_only_native_representation_fields(self):
        tid = str(uuid.uuid4())
        records = [json.loads(line) for line in rollout(tid).splitlines()]
        def proof():
            return m.continuation([b"".join(m.encoded(r) + b"\n" for r in records)], tid, m.GIB)[0]
        before = proof()
        records[0]["payload"].update(history_mode="paginated", subagent_history_start_ordinal=5)
        self.assertEqual(before, proof())
        for field, value in (("cwd", "/changed"), ("model_provider", "different"),
                             ("base_instructions", {"text": "changed"}),
                             ("git", {"commit_hash": "different"}), ("future_field", None)):
            with self.subTest(field=field):
                records[0]["payload"][field] = value
                self.assertNotEqual(before["session_meta"], proof()["session_meta"])
                del records[0]["payload"][field]

    def test_state_and_response_interleaving_is_preserved(self):
        tid = str(uuid.uuid4())
        data = rollout(tid)
        parts = data.splitlines(keepends=True)
        parts[-1], parts[-2] = parts[-2], parts[-1]
        before = m.continuation([data], tid, m.GIB)[0]
        after = m.continuation([b"".join(parts)], tid, m.GIB)[0]
        self.assertEqual(before["state"], after["state"])
        self.assertEqual(before["responses"], after["responses"])
        self.assertNotEqual(before["ordered_continuation"], after["ordered_continuation"])

    def test_normal_shutdown_raises_through_the_journal_boundary(self):
        import signal
        with self.assertRaisesRegex(m.Refusal, "interrupted by signal"):
            m.interrupted(signal.SIGTERM, None)

    def test_streaming_and_exact_optional_null_normalization(self):
        tid = str(uuid.uuid4())
        data = rollout(tid)
        expected, _ = m.continuation([data], tid, m.GIB)
        items = [json.loads(x) for x in data.splitlines()]
        items[2]["payload"].update(compaction_response_id=None, latest_token_usage_record=None)
        items[3]["payload"]["content"] = None
        changed = b"".join(m.encoded(x) + b"\n" for x in items)
        actual, _ = m.continuation((changed[i:i + 7] for i in range(0, len(changed), 7)), tid, m.GIB)
        self.assertEqual(actual, expected)
        items[2]["payload"]["unknown"] = None
        different = b"".join(m.encoded(x) + b"\n" for x in items)
        self.assertNotEqual(m.continuation([different], tid, m.GIB)[0], expected)

    def test_identity_truncation_and_decompression_caps(self):
        tid = str(uuid.uuid4())
        data = rollout(tid)
        for source, identity, cap in ((data, str(uuid.uuid4()), m.GIB), (data[:-1], tid, m.GIB), (data, tid, 10)):
            with self.assertRaises(m.Refusal):
                m.continuation([source], identity, cap)

    def test_latest_checkpoint_replaces_prior_suffix(self):
        tid = str(uuid.uuid4())
        base = rollout(tid)
        suffix = b"".join(base.splitlines(keepends=True)[2:])
        self.assertEqual(m.continuation([base], tid, m.GIB)[0],
                         m.continuation([base + suffix], tid, m.GIB)[0])

    def test_backup_readback_and_exclusive_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, dst = Path(tmp).resolve() / "source", Path(tmp).resolve() / "backup"
            src.write_bytes(b"durable history")
            self.assertEqual(m.verified_copy(src.resolve(), dst), hashlib.sha256(src.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                m.verified_copy(src.resolve(), dst)

    def test_child_output_limit_and_timeout_teardown(self):
        import sys
        with patch.object(m, "OUTPUT_LIMIT", 10):
            with self.assertRaisesRegex(m.Refusal, "stdout limit"):
                m.capture([sys.executable, "-c", "print('x'*100)"], lambda: None)
        start = time.monotonic()
        def guard():
            m.require(time.monotonic() - start < .2, "deadline")
        with self.assertRaisesRegex(m.Refusal, "deadline"):
            m.capture([sys.executable, "-c", "import time; time.sleep(30)"], guard)


if __name__ == "__main__":
    unittest.main()
