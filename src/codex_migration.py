"""Opt-in archived-child migration. Embedded by the Rust CLI; Python 3.11+.

Only Codex writes the live rollout/index. Recovery exports an original to an
isolated home. This module never deletes sessions or overwrites live history.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import plistlib
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import tomllib
import uuid

GIB = 1024**3
LINE_LIMIT = 64 * 1024**2
OUTPUT_LIMIT = 4 * 1024**2
INDEX_LIMIT = 20_000
TERMINAL = {"verified", "refused_before_apply"}
STATE_TYPES = {"world_state", "turn_context", "token_usage_record",
               "inter_agent_communication_metadata"}


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical(path, directory=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute canonical path required")
    require(path.resolve(strict=True) == path, f"path alias or symlink: {path}")
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode),
            f"unexpected file type: {path}")
    return path


def identity(path):
    s = canonical(path).stat()
    require(s.st_nlink == 1, "hardlinked rollout or artifact")
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def free_bytes(path):
    s = os.statvfs(path)
    return s.f_bavail * s.f_frsize


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest_file(path, guard=lambda: None):
    before = identity(path)
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024**2):
            guard()
            h.update(block)
    require(identity(path) == before, "file changed while hashing")
    return h.hexdigest()


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_journal(path, value):
    # A crash leaves either the prior journal or a recognizable pending file.
    tmp = path.with_suffix(".pending")
    with tmp.open("xb") as f:
        f.write(encoded(value) + b"\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    sync_dir(path.parent)


def verified_copy(source, destination, guard=lambda: None):
    before = identity(source)
    h = hashlib.sha256()
    with source.open("rb") as src, destination.open("xb") as dst:
        while block := src.read(1024**2):
            guard()
            dst.write(block)
            h.update(block)
        dst.flush()
        os.fsync(dst.fileno())
    require(identity(source) == before, "source changed during backup")
    require(digest_file(destination, guard) == h.hexdigest(), "backup readback mismatch")
    sync_dir(destination.parent)
    return h.hexdigest()


def load_policy(path):
    path = canonical(path)
    require(path.stat().st_uid == os.getuid() and not path.stat().st_mode & 0o077,
            "migration policy must be user-owned mode 0600")
    require(path.stat().st_size <= 65536, "policy exceeds 64 KiB")
    with path.open("rb") as f:
        p = tomllib.load(f)
    required = {"codex_home", "codex_binary", "codex_sha256", "zstd_binary",
                "backup_root", "backup_volume_uuid", "journal_root"}
    defaults = {"enabled": False, "grace_hours": 24, "max_tasks": 4,
                "max_source_bytes": 4 * GIB, "max_raw_bytes_per_task": 30 * GIB,
                "max_seconds": 1800, "min_free_bytes": 30 * GIB,
                "exclude_threads": []}
    require(required <= p.keys(), "missing migration policy field")
    require(not p.keys() - required - defaults.keys(), "unknown migration policy field")
    p = defaults | p
    require(type(p["enabled"]) is bool, "enabled must be boolean")
    for key in ("grace_hours", "max_tasks", "max_source_bytes", "max_raw_bytes_per_task",
                "max_seconds", "min_free_bytes"):
        require(type(p[key]) is int and p[key] > 0, f"invalid limit: {key}")
    require(24 <= p["grace_hours"] <= 8760 and p["max_tasks"] <= 25,
            "grace must be 24..8760 hours; batch at most 25 tasks")
    require(p["max_seconds"] <= 3600 and p["min_free_bytes"] >= GIB,
            "batch at most one hour; free-space floor at least 1 GiB")
    require(p["max_source_bytes"] <= 100 * GIB and p["max_raw_bytes_per_task"] <= 100 * GIB,
            "byte limit exceeds 100 GiB")
    require(isinstance(p["exclude_threads"], list), "exclude_threads must be a list")
    for tid in p["exclude_threads"]:
        require(str(uuid.UUID(tid)) == tid, "invalid excluded task ID")
    for key in required:
        require(isinstance(p[key], str) and p[key], f"invalid {key}")
    require(len(p["codex_sha256"]) == 64 and
            all(c in "0123456789abcdef" for c in p["codex_sha256"]), "invalid binary digest")
    for key in ("codex_home", "backup_root", "journal_root"):
        p[key] = canonical(p[key], directory=True)
    for key in ("codex_binary", "zstd_binary"):
        p[key] = canonical(p[key])
    home, backup, journal = (p[k] for k in ("codex_home", "backup_root", "journal_root"))
    require(not backup.is_relative_to(home) and not home.is_relative_to(backup),
            "backup must be outside the Codex store")
    require(not journal.is_relative_to(home) and not home.is_relative_to(journal),
            "journal must be outside the Codex store")
    require(not journal.is_relative_to(backup) and not backup.is_relative_to(journal),
            "journal and external backup roots must be separate")
    require(home.stat().st_dev != backup.stat().st_dev, "backup requires a separate volume")
    require(journal.stat().st_uid == os.getuid() and not journal.stat().st_mode & 0o077,
            "journal root must be user-owned mode 0700")
    p["policy_sha256"] = digest_file(path)
    return p


def index_snapshot(home):
    db = canonical(home / "state_5.sqlite")
    uri = db.as_uri() + "?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as c:
        c.row_factory = sqlite3.Row
        c.execute("pragma query_only=on")
        c.execute("begin")
        rows = [dict(r) for r in c.execute(
            "select id,rollout_path,source,history_mode,archived,archived_at,updated_at,"
            "is_pinned from threads limit ?", (INDEX_LIMIT + 1,))]
        edges = [tuple(r) for r in c.execute(
            "select parent_thread_id,child_thread_id from thread_spawn_edges limit ?",
            (INDEX_LIMIT + 1,))]
    require(len(rows) <= INDEX_LIMIT and len(edges) <= INDEX_LIMIT, "task index cap exceeded")
    return rows, edges


def lineage(rows, edges):
    parents = {}
    for parent, child in edges:
        parents.setdefault(child, set()).add(parent)
    for r in rows:
        require(str(uuid.UUID(r["id"])) == r["id"], "invalid task ID in index")
        source = r["source"]
        require(isinstance(source, str) and source.strip(), "invalid task source")
        # Ordinary sources are stored as bare scalars as well as JSON strings.
        # Structured lineage must still parse successfully; corruption must not
        # hide an existing child from the leaf-only migration policy.
        if source.lstrip().startswith(("{", "[", '"')):
            source = json.loads(source)
        if isinstance(source, dict) and isinstance(source.get("subagent"), dict):
            spawn = source["subagent"].get("thread_spawn")
            if isinstance(spawn, dict):
                parent = spawn.get("parent_thread_id")
                require(isinstance(parent, str) and parent, "incomplete spawn lineage")
                parents.setdefault(r["id"], set()).add(parent)
    children = {p for values in parents.values() for p in values}
    return parents, children


def eligibility(row, parents, children, ids, now, grace, excluded):
    tid = row["id"]
    if row["history_mode"] != "legacy":
        return "already_paginated"
    if row["archived"] != 1:
        return "not_archived"
    if row["is_pinned"] != 0 or tid in excluded:
        return "protected_task"
    ps = parents.get(tid, set())
    if len(ps) != 1 or tid in ps or not ps <= ids:
        return "incomplete_or_conflicting_parent"
    # Both the persisted edge and source JSON contribute to the child set.
    if tid in children:
        return "has_children"
    for key in ("archived_at", "updated_at"):
        t = row[key]
        if type(t) is not int or t <= 0 or now - t < grace:
            return "archive_or_activity_grace"
    return None


def rollout_path(home, row):
    root = canonical(home / "archived_sessions", directory=True)
    logical = Path(row["rollout_path"])
    require(logical.is_absolute() and ".." not in logical.parts and
            logical.is_relative_to(root), "rollout outside archive root")
    name = logical.name
    require(name.endswith((".jsonl", ".jsonl.zst")) and
            name.removesuffix(".zst").endswith(row["id"] + ".jsonl"), "unexpected rollout name")
    plain = Path(str(logical).removesuffix(".zst"))
    compressed = Path(str(plain) + ".zst")
    found = []
    for path in (plain, compressed):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        selected = canonical(path)
        require(selected.is_relative_to(root), "canonical rollout outside archive root")
        found.append(selected)
    require(len(found) == 1, "missing or ambiguous rollout spelling")
    require(found[0].stat().st_dev == home.stat().st_dev, "nested rollout mount")
    return found[0]


def plan(home, rows, edges, p, now):
    parents, children = lineage(rows, edges)
    ids = {r["id"] for r in rows}
    by_id = {r["id"]: r for r in rows}
    candidates, refused = [], {}
    for row in rows:
        reason = eligibility(row, parents, children, ids, now, p["grace_hours"] * 3600,
                             p["exclude_threads"])
        if not reason:
            try:
                path = rollout_path(home, row)
                ident = identity(path)
                require(now - ident[3] / 1e9 >= p["grace_hours"] * 3600, "recent_file_activity")
                parent = next(iter(parents[row["id"]]))
                candidates.append({"row": row, "path": str(path), "identity": ident,
                                   "parent_id": parent, "parent_row": by_id[parent]})
            except (OSError, Refusal) as error:
                reason = str(error)
        if reason:
            refused[reason] = refused.get(reason, 0) + 1
    candidates.sort(key=lambda c: (-c["identity"][2], c["row"]["id"]))
    selected, used = [], 0
    for candidate in candidates:
        size = candidate["identity"][2]
        if len(selected) < p["max_tasks"] and used + size <= p["max_source_bytes"]:
            selected.append(candidate)
            used += size
    return {"selected": selected, "eligible_count": len(candidates),
            "eligible_file_bytes": sum(c["identity"][2] for c in candidates),
            "selected_file_bytes": used, "refusals": refused,
            "byte_currency": "stored_file_bytes_not_apfs_private_reclaim"}


def stop_process(p):
    # The direct child can exit while a descendant still holds a pipe. Always
    # tear down the run-owned process group, then reap the direct child.
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if p.poll() is None:
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def stream(args, guard, env=None, on_start=lambda pid: None):
    """Bound every child by the batch deadline; drain both pipes without deadlock."""
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         stdin=subprocess.DEVNULL, env=env, start_new_session=True)
    errors = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ, "out")
    sel.register(p.stderr, selectors.EVENT_READ, "err")
    try:
        on_start(p.pid)
        while sel.get_map():
            guard()
            for key, _ in sel.select(.1):
                b = os.read(key.fileobj.fileno(), 65536)
                if not b:
                    sel.unregister(key.fileobj)
                elif key.data == "err":
                    errors.extend(b)
                    require(len(errors) <= OUTPUT_LIMIT, "child stderr limit")
                else:
                    yield b
        require(p.wait(timeout=2) == 0, f"child exited {p.returncode}; stderr sha256 "
                + hashlib.sha256(errors).hexdigest())
    finally:
        stop_process(p)
        sel.close()
        p.stdout.close()
        p.stderr.close()


def capture(args, guard, env=None, on_start=lambda pid: None):
    result = bytearray()
    with contextlib.closing(stream(args, guard, env, on_start)) as blocks:
        for block in blocks:
            result.extend(block)
            require(len(result) <= OUTPUT_LIMIT, "child stdout limit")
    return bytes(result)


def continuation(blocks, tid, max_raw):
    """Streaming semantic digest; retain at most one JSON record, never a history."""
    pending = bytearray()
    raw = 0
    checkpoint = None
    responses = hashlib.sha256()
    state = hashlib.sha256()
    ordered = hashlib.sha256()
    count = 0
    head = None
    for block in blocks:
        raw += len(block)
        require(raw <= max_raw, "decompressed byte budget exceeded")
        pending.extend(block)
        while b"\n" in pending:
            line, _, pending = pending.partition(b"\n")
            require(len(line) < LINE_LIMIT, "rollout record bound")
            x = json.loads(line)
            if head is None:
                require(x.get("type") == "session_meta" and x["payload"]["id"] == tid,
                        "rollout task identity mismatch")
                head = x["payload"]
            kind, value = x.get("type"), x.get("payload")
            if kind == "compacted":
                require(isinstance(value, dict) and value.get("replacement_history") is not None,
                        "unsupported continuation checkpoint")
                value = dict(value)
                for key in ("compaction_response_id", "latest_token_usage_record"):
                    if value.get(key) is None:
                        value.pop(key, None)
                checkpoint = hashlib.sha256(encoded(value)).hexdigest()
                responses, state, count = hashlib.sha256(), hashlib.sha256(), 0
                ordered = hashlib.sha256()
            elif checkpoint is not None and kind == "response_item":
                value = dict(value)
                if value.get("type") == "reasoning" and value.get("content") is None:
                    value.pop("content", None)
                responses.update(encoded(value) + b"\n")
                ordered.update(encoded({"type": kind, "payload": value}) + b"\n")
                count += 1
            elif checkpoint is not None and kind in STATE_TYPES:
                state.update(encoded({"type": kind, "payload": value}) + b"\n")
                ordered.update(encoded({"type": kind, "payload": value}) + b"\n")
        require(len(pending) < LINE_LIMIT, "rollout record bound")
    require(not pending, "unterminated rollout record")
    require(checkpoint is not None, "no supported bounded continuation checkpoint")
    return {"checkpoint": checkpoint, "responses": responses.hexdigest(),
            "state": state.hexdigest(), "ordered_continuation": ordered.hexdigest(),
            "responses_count": count}, raw


class Runtime:
    def __init__(self, p):
        self.p = p
        self.deadline = time.monotonic() + p["max_seconds"]

    def guard(self):
        require(time.monotonic() < self.deadline, "batch time limit")
        require(free_bytes(self.p["codex_home"]) >= self.p["min_free_bytes"], "Data free-space floor")

    def volume(self):
        info = plistlib.loads(capture(["/usr/sbin/diskutil", "info", "-plist",
                                     str(self.p["backup_root"])], self.guard))
        require(info.get("VolumeUUID") == self.p["backup_volume_uuid"], "backup volume identity changed")
        mount = canonical(info["MountPoint"], directory=True)
        require(mount != Path("/") and self.p["backup_root"].is_relative_to(mount),
                "backup mount missing")
        require(self.p["backup_root"].stat().st_dev != self.p["codex_home"].stat().st_dev,
                "backup volume is the source device")

    def quiet(self, path=None, allowed_pids=()):
        self.guard()
        # Quiet-store v1: app-server, CLI sessions and migration workers defer a
        # batch. An explicit native invocation is the only allowed Codex writer.
        ps = capture(["/bin/ps", "-axo", "pid=,comm="], self.guard).decode()
        require(ps.strip(), "empty process evidence")
        for line in ps.splitlines():
            parts = line.strip().split(None, 1)
            require(len(parts) == 2 and parts[0].isdigit(), "malformed process evidence")
            name = Path(parts[1]).name.lower()
            require(int(parts[0]) in allowed_pids or name not in {"codex", "chatgpt", "codex-app-server"},
                    f"Codex store is active (PID {parts[0]})")
        if path is not None:
            # lsof exit 1 + empty streams is the exact-file no-owner result.
            result = subprocess.run(["/usr/sbin/lsof", "-nP", "-t", "--", str(path)],
                                    capture_output=True, timeout=10)
            require(result.returncode == 1 and not result.stdout and not result.stderr,
                    "rollout owner or incomplete exact-file evidence")

    def verify_binary(self):
        require(digest_file(self.p["codex_binary"], self.guard) == self.p["codex_sha256"],
                "native Codex binary identity changed")
        capture(["/usr/bin/codesign", "--verify", "--strict", str(self.p["codex_binary"])], self.guard)
        version = capture([str(self.p["codex_binary"]), "--version"], self.guard).decode().strip()
        require(version == "codex-cli 0.153.4", "native version needs a new compatibility proof")

    def context(self, path, tid):
        before = identity(path)
        if path.name.endswith(".zst"):
            blocks = stream([str(self.p["zstd_binary"]), "-dc", "--", str(path)], self.guard)
        else:
            def plain():
                with path.open("rb") as f:
                    while b := f.read(65536):
                        self.guard()
                        yield b
            blocks = plain()
        try:
            result = continuation(blocks, tid, self.p["max_raw_bytes_per_task"])
        finally:
            blocks.close()
        require(identity(path) == before, "rollout changed during continuation proof")
        return result

    def native(self, tid, apply):
        self.verify_binary()
        self.quiet()
        args = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)",
                str(self.p["codex_binary"]), "migrate-rollouts", "--thread", tid, "--json",
                "--max-mib-per-second", "100", "-c", "analytics.enabled=false",
                "--disable", "local_thread_store_compression",
                "--disable", "background_paginated_rollout_migration"]
        if apply:
            args.append("--apply")
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()),
               "CODEX_HOME": str(self.p["codex_home"]), "LANG": "en_US.UTF-8", "RUST_LOG": "error"}
        owned = []
        last_probe = 0.0
        def native_guard():
            nonlocal last_probe
            self.guard()
            if time.monotonic() - last_probe >= .5:
                self.quiet(allowed_pids=owned)
                last_probe = time.monotonic()
        report = json.loads(capture(args, native_guard, env, owned.append))
        outcomes = report.get("outcomes", [])
        require(len(outcomes) == 1 and outcomes[0].get("thread_id") == tid and
                outcomes[0].get("status") == ("migrated" if apply else "eligible"),
                "native migration refused or changed scope")
        return report


def refresh(candidate, p):
    rows, edges = index_snapshot(p["codex_home"])
    parents, children = lineage(rows, edges)
    row = next((r for r in rows if r["id"] == candidate["row"]["id"]), None)
    require(row == candidate["row"], "task index state changed")
    reason = eligibility(row, parents, children, {r["id"] for r in rows}, time.time(),
                         p["grace_hours"] * 3600, p["exclude_threads"])
    require(reason is None, f"task no longer eligible: {reason}")
    require(rollout_path(p["codex_home"], row) == Path(candidate["path"]) and
            identity(Path(candidate["path"])) == candidate["identity"], "rollout identity changed")
    require(parents[row["id"]] == {candidate["parent_id"]}, "parent lineage changed")
    require(next((r for r in rows if r["id"] == candidate["parent_id"]), None) ==
            candidate["parent_row"], "parent index state changed")


@contextlib.contextmanager
def protection_guard():
    """Same shared flock used by the Rust protection registry; no lease edits."""
    import fcntl
    state = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    root = state / "worktree-gc"
    require(root.is_absolute() and ".." not in root.parts and
            root.resolve(strict=False) == root, f"path alias or symlink: {root}")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = canonical(root, directory=True)
    fd = os.open(root / "protections.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        registry = root / "protections.json"
        try:
            registry.lstat()
        except FileNotFoundError:
            yield []
            return
        canonical(registry)
        require(registry.stat().st_size <= OUTPUT_LIMIT, "protection registry size limit")
        value = json.loads(registry.read_bytes())
        require(value.get("version") == 1 and isinstance(value.get("leases"), list),
                "invalid protection registry")
        paths = []
        for lease in value["leases"]:
            require(type(lease["expires_at_unix"]) is int, "invalid protection expiry")
            path = Path(lease["path"])
            require(path.is_absolute(), "non-absolute protection")
            if lease["expires_at_unix"] > time.time():
                paths.append(path)
        yield paths


def migrate_one(candidate, p, rt):
    tid, source = candidate["row"]["id"], Path(candidate["path"])
    rt.volume()
    rt.quiet(source)
    refresh(candidate, p)
    before_context, raw = rt.context(source, tid)
    # Native compressed migration materializes the full uncompressed rollout.
    require(free_bytes(p["codex_home"]) >= p["min_free_bytes"] + 2 * raw,
            "insufficient native decompression/rewrite headroom")
    require(free_bytes(p["backup_root"]) >= candidate["identity"][2] + GIB,
            "external backup capacity")
    run_id = str(uuid.uuid4())
    journal_path = p["journal_root"] / (run_id + ".json")
    backup_dir = p["backup_root"] / run_id
    backup_dir.mkdir(mode=0o700)
    sync_dir(backup_dir.parent)
    backup = backup_dir / source.name
    j = {"version": 1, "run_id": run_id, "phase": "backing_up", "candidate": candidate,
         "backup": str(backup), "backup_volume_uuid": p["backup_volume_uuid"],
         "codex_home": str(p["codex_home"]), "codex_sha256": p["codex_sha256"],
         "policy_sha256": p["policy_sha256"], "started_at": time.time(),
         "before_context": before_context, "raw_bytes": raw}
    write_journal(journal_path, j)
    applying = False
    try:
        j["backup_sha256"] = verified_copy(source, backup, rt.guard)
        j["phase"] = "backed_up"
        write_journal(journal_path, j)
        rt.native(tid, False)
        rt.volume()
        rt.quiet(source)
        refresh(candidate, p)
        require(digest_file(source, rt.guard) == j["backup_sha256"] and
                digest_file(backup, rt.guard) == j["backup_sha256"], "pre-apply backup/source drift")
        j["phase"] = "applying"
        j["free_before"] = free_bytes(p["codex_home"])
        write_journal(journal_path, j)
        applying = True
        j["native_report"] = rt.native(tid, True)
        after_context, _ = rt.context(source, tid)
        j["after_context"] = after_context
        j["after_sha256"] = digest_file(source, rt.guard)
        require(after_context == before_context, "continuation mismatch; recovery required")
        rows, edges = index_snapshot(p["codex_home"])
        row = next(r for r in rows if r["id"] == tid)
        require(row == candidate["row"] | {"history_mode": "paginated"}, "post-migration index drift")
        require(next((r for r in rows if r["id"] == candidate["parent_id"]), None) ==
                candidate["parent_row"], "post-migration parent drift")
        _, children = lineage(rows, edges)
        require(tid not in children, "post-migration child appeared")
        rt.quiet(source)
        rt.volume()
        j.update(phase="verified", after_bytes=source.stat().st_size,
                 file_bytes_reduced=candidate["identity"][2] - source.stat().st_size,
                 free_after=free_bytes(p["codex_home"]), finished_at=time.time())
        write_journal(journal_path, j)
    except BaseException as error:
        j.update(phase="recovery_required" if applying else "refused_before_apply",
                 error=str(error), finished_at=time.time())
        write_journal(journal_path, j)
        raise
    return {"journal": str(journal_path), "thread_id": tid, "phase": j["phase"],
            "file_bytes_reduced": j["file_bytes_reduced"],
            "filesystem_available_delta": j["free_after"] - j["free_before"]}


def pending_journals(root):
    count = 0
    for path in root.iterdir():
        count += 1
        require(count <= INDEX_LIMIT, "journal enumeration bound")
        if path.name == "runner.lock":
            continue
        require(path.suffix == ".json", f"pending or unknown migration evidence: {path.name}")
        require(canonical(path).stat().st_size <= OUTPUT_LIMIT, "journal size bound")
        value = json.loads(path.read_bytes())
        require(value.get("version") == 1 and value.get("phase") in TERMINAL,
                f"migration recovery pending: {path.name}")


def batch(p, apply=False, runtime_factory=Runtime):
    rt = runtime_factory(p)
    rows, edges = index_snapshot(p["codex_home"])
    report = {"version": 1, "mode": "apply" if apply else "dry_run", "observed_at": time.time(),
              "plan": plan(p["codex_home"], rows, edges, p, time.time()), "results": []}
    if not apply:
        return report
    require(p["enabled"], "migration policy is disabled")
    import fcntl
    lock_path = p["journal_root"] / "runner.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock, protection_guard() as protections:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending_journals(p["journal_root"])
        rt.quiet()
        rt.volume()
        rt.verify_binary()
        for candidate in report["plan"]["selected"]:
            rt.guard()
            source = Path(candidate["path"])
            require(not any(source.is_relative_to(path) or path.is_relative_to(source)
                            for path in protections), "recursive protection applies")
            report["results"].append(migrate_one(candidate, p, rt))
    return report


def recover(journal_path, destination):
    """Restore original bytes into an absent isolated home, never the live store."""
    path = canonical(journal_path)
    require(path.stat().st_size <= OUTPUT_LIMIT, "journal size bound")
    j = json.loads(path.read_bytes())
    require(j.get("version") == 1 and "backup_sha256" in j, "no verified backup in journal")
    target = Path(destination)
    canonical(target.parent, directory=True)
    require(target.is_absolute() and target.parent / target.name == target and
            target.name not in (".", "..") and not target.is_relative_to(Path(j["codex_home"])),
            "recovery requires a new isolated home outside live Codex")
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    else:
        raise Refusal("recovery destination already exists")
    backup = canonical(j["backup"])
    start = time.monotonic()
    def guard():
        require(time.monotonic() - start < 1800, "recovery deadline")
        require(free_bytes(target.parent) >= GIB, "recovery free-space floor")
    info = plistlib.loads(capture(["/usr/sbin/diskutil", "info", "-plist", str(backup)], guard))
    require(info.get("VolumeUUID") == j["backup_volume_uuid"], "backup volume mismatch")
    require(digest_file(backup, guard) == j["backup_sha256"], "backup identity mismatch")
    require(free_bytes(target.parent) >= backup.stat().st_size + GIB, "recovery capacity")
    target.mkdir(mode=0o700)  # exclusive: an existing home is always a refusal
    created = target.stat()
    archive = target / "archived_sessions"
    restored = archive / backup.name
    archive_identity = None
    try:
        archive.mkdir(mode=0o700)
        archive_identity = archive.stat()
        require(verified_copy(backup, restored, guard) == j["backup_sha256"], "restoration mismatch")
    except BaseException as error:
        try:
            current = canonical(target, directory=True).stat()
            require((current.st_dev, current.st_ino) == (created.st_dev, created.st_ino),
                    "recovery target changed during failure cleanup")
            if archive_identity is not None:
                current = canonical(archive, directory=True).stat()
                require((current.st_dev, current.st_ino) ==
                        (archive_identity.st_dev, archive_identity.st_ino),
                        "recovery archive changed during failure cleanup")
                restored.unlink(missing_ok=True)
                archive.rmdir()
            target.rmdir()
        except (OSError, Refusal) as cleanup_error:
            error.add_note(f"partial recovery retained at {target}: {cleanup_error}")
        raise
    return {"isolated_codex_home": str(target), "restored": str(restored),
            "sha256": j["backup_sha256"], "live_store_unchanged": True}


def interrupted(signum, frame):
    raise Refusal(f"interrupted by signal {signum}")


def main():
    require(sys.platform == "darwin", "native archived-child migration currently supports macOS")
    os.umask(0o077)
    # Give the generator/process/journal finally blocks a chance to run when
    # launchd or an operator requests a normal shutdown.
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--config", required=True)
    run.add_argument("--apply", action="store_true")
    recovery = sub.add_parser("recover")
    recovery.add_argument("--journal", required=True)
    recovery.add_argument("--destination", required=True)
    args = parser.parse_args()
    result = batch(load_policy(args.config), args.apply) if args.command == "run" else recover(
        args.journal, args.destination)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (Refusal, OSError, ValueError, KeyError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "refused", "error": str(error)}), file=sys.stderr)
        sys.exit(1)
