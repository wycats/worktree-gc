//! Explicit, offline qualification of the pinned native recovery-registration seam.
//! This test never reads the live Codex home and never sends a model request.
#![cfg(target_os = "macos")]

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const CODEX: &str = "/Applications/ChatGPT.app/Contents/Resources/codex";
const CODEX_SHA: &str = "4ca47945439f9251fe35f4cbe071369192cd9a6c5a3a17b75c7a11ad548a9c7f";
const CHILD: &str = "019fe295-7969-7502-bf8f-0b1eb4b0127b";
const PARENT: &str = "019fdec0-2f64-7e41-8b05-b91253ce2f06";
const SENTINEL: &str = "ISOLATED_RECOVERY_SENTINEL_20260905";
const OUTPUT_CAP: usize = 4 * 1024 * 1024;

fn hash(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

struct Process {
    child: Child,
    pending: Vec<u8>,
    observed: usize,
    stderr: PathBuf,
    deadline: Instant,
}

impl Process {
    fn spawn(root: &Path, home: &Path, args: &[&str], label: &str) -> Result<Self> {
        // Reads are allowed for native libraries; live application stores are denied.
        // Writes (including SQLite, logs, and native caches) stay within this fixture.
        let profile = format!(
            "(version 1)(allow default)(deny network*)(deny file-write* (require-not (subpath {})))(allow file-write* (literal \"/dev/null\"))(deny file-read* (subpath \"/Users/wycats/.codex\"))",
            serde_json::to_string(root.to_str().context("UTF-8 fixture path")?)?
        );
        let stderr = root.join(format!("{label}.stderr"));
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", &profile]).args(args).current_dir(home);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", home.join("user"))
            .env("CODEX_HOME", home.join("codex"))
            .env("TMPDIR", home.join("tmp"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("XDG_STATE_HOME", home.join("state"))
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("LANG", "en_US.UTF-8")
            .env("RUST_LOG", "error")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&stderr)?,
            )
            .process_group(0);
        let child = command.spawn().context("spawn isolated native command")?;
        let process = Self {
            child,
            pending: Vec::new(),
            observed: 0,
            stderr,
            deadline: Instant::now() + Duration::from_secs(90),
        };
        let fd = process.child.stdout.as_ref().context("stdout")?.as_raw_fd();
        // SAFETY: fd belongs to the live child's stdout pipe.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
            "nonblocking stdout setup"
        );
        Ok(process)
    }

    fn poll(&mut self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "native command deadline exceeded"
        );
        ensure!(
            fs::metadata(&self.stderr)?.len() <= OUTPUT_CAP as u64,
            "stderr output cap"
        );
        let mut buffer = [0; 8192];
        match self
            .child
            .stdout
            .as_mut()
            .context("stdout")?
            .read(&mut buffer)
        {
            Ok(count) => {
                self.observed += count;
                ensure!(self.observed <= OUTPUT_CAP, "stdout output cap");
                self.pending.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn send(&mut self, value: Value) -> Result<()> {
        let input = self.child.stdin.as_mut().context("stdin")?;
        writeln!(input, "{value}")?;
        input.flush()?;
        Ok(())
    }

    fn rpc(&mut self, id: u64, method: &str, params: Value) -> Result<Value> {
        self.send(json!({"id": id, "method": method, "params": params}))?;
        loop {
            self.poll()?;
            while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=end).collect();
                let value: Value = serde_json::from_slice(&line)?;
                if value.get("id") == Some(&json!(id)) {
                    ensure!(value.get("error").is_none(), "{method}: {value}");
                    return value.get("result").cloned().context("RPC result absent");
                }
            }
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "{method}: app-server exited {status}; {}",
                    fs::read_to_string(&self.stderr)?
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        self.child.stdin.take();
        loop {
            self.poll()?;
            if let Some(status) = self.child.try_wait()? {
                // Drain the final pipe bytes after process exit.
                loop {
                    let before = self.observed;
                    self.poll()?;
                    if before == self.observed {
                        break;
                    }
                }
                ensure!(
                    status.success(),
                    "command failed {status}: {}",
                    fs::read_to_string(&self.stderr)?
                );
                return Ok(std::mem::take(&mut self.pending));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let group = -(self.child.id() as i32);
        // The only signaled group was created by this harness via process_group(0).
        unsafe {
            libc::kill(group, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}

fn command(root: &Path, home: &Path, args: &[&str], label: &str) -> Result<Vec<u8>> {
    Process::spawn(root, home, args, label)?.finish()
}

fn fixture(home: &Path) -> Result<Vec<u8>> {
    // Same mandatory SessionMeta and user-event fields as Codex's native
    // app-server/tests/common/rollout.rs create_fake_rollout_with_text_elements.
    let timestamp = "2026-08-08T11:14:34Z";
    let records = [
        json!({"timestamp": timestamp, "type": "session_meta", "payload": {
            "id": CHILD, "timestamp": timestamp, "cwd": home, "originator": "codex",
            "cli_version": "0.153.4", "model_provider": "openai", "base_instructions": null,
            "parent_thread_id": PARENT, "history_mode": "legacy",
            "source": {"subagent": {"thread_spawn": {"parent_thread_id": PARENT, "depth": 1}}}
        }}),
        json!({"timestamp": timestamp, "type": "response_item", "payload": {
            "type": "message", "role": "user", "content": [{"type":"input_text", "text": SENTINEL}]
        }}),
        json!({"timestamp": timestamp, "type": "event_msg", "payload": {
            "type": "user_message", "message": SENTINEL, "text_elements": [], "local_images": []
        }}),
    ];
    Ok(records
        .iter()
        .map(|record| format!("{record}\n"))
        .collect::<String>()
        .into_bytes())
}

#[test]
#[ignore = "requires explicit native runtime slot: pinned Codex 0.153.4, sandbox-exec, sqlite3 and zstd"]
fn native_fresh_store_registers_plain_and_compressed_archived_children() -> Result<()> {
    ensure!(
        hash(Path::new(CODEX))? == CODEX_SHA,
        "pinned native artifact changed"
    );
    let temporary = tempfile::Builder::new()
        .prefix("gc-native-recovery-")
        .tempdir()?;
    let root = temporary.path().canonicalize()?;
    for compressed in [false, true] {
        let home = root.join(if compressed { "compressed" } else { "plain" });
        for directory in [
            "codex/archived_sessions",
            "user",
            "tmp",
            "cache",
            "state",
            "config",
        ] {
            fs::create_dir_all(home.join(directory))?;
        }
        let label = if compressed { "zst" } else { "plain" };
        let version = command(
            &root,
            &home,
            &[CODEX, "--version"],
            &format!("{label}-version"),
        )?;
        ensure!(
            String::from_utf8(version)?.trim() == "codex-cli 0.153.4",
            "native version changed"
        );
        command(
            &root,
            &home,
            &["/usr/bin/codesign", "--verify", "--strict", CODEX],
            &format!("{label}-signature"),
        )?;
        let original = home.join("original.jsonl");
        fs::write(&original, fixture(&home)?)?;
        let original_hash = hash(&original)?;
        let name = format!(
            "rollout-2026-08-08T11-14-34-{CHILD}.jsonl{}",
            if compressed { ".zst" } else { "" }
        );
        let archived = home.join("codex/archived_sessions").join(name);
        if compressed {
            command(
                &root,
                &home,
                &[
                    "/opt/homebrew/bin/zstd",
                    "-q",
                    original.to_str().context("source")?,
                    "-o",
                    archived.to_str().context("archive")?,
                ],
                &format!("{label}-compress"),
            )?;
        } else {
            fs::copy(&original, &archived)?;
        }
        let stored_hash = hash(&archived)?;
        let database = home.join("codex/state_5.sqlite");
        ensure!(!database.exists(), "fresh store unexpectedly indexed");
        let mut server = Process::spawn(
            &root,
            &home,
            &[
                CODEX,
                "app-server",
                "--stdio",
                "-c",
                "analytics.enabled=false",
                "--disable",
                "local_thread_store_compression",
                "--disable",
                "background_paginated_rollout_migration",
            ],
            &format!("{label}-server"),
        )?;
        server.rpc(1, "initialize", json!({"clientInfo":{"name":"gc-recovery-qualification", "version":"1"}, "capabilities":{"experimentalApi":true}}))?;
        server.send(json!({"method":"initialized"}))?;
        let registration_deadline = Instant::now() + Duration::from_secs(30);
        let mut attempt = 0;
        loop {
            ensure!(
                Instant::now() < registration_deadline,
                "startup did not register archived child"
            );
            server.poll()?;
            if database.exists() {
                let sql = format!("SELECT archived,rollout_path FROM threads WHERE id='{CHILD}';");
                let row = command(
                    &root,
                    &home,
                    &[
                        "/usr/bin/sqlite3",
                        "-readonly",
                        database.to_str().context("database")?,
                        &sql,
                    ],
                    &format!("{label}-index-{attempt}"),
                )?;
                if !row.is_empty() {
                    ensure!(
                        String::from_utf8(row)?.trim() == format!("1|{}", archived.display()),
                        "unexpected recovered index row"
                    );
                    break;
                }
            }
            attempt += 1;
            std::thread::sleep(Duration::from_millis(100));
        }
        let before = server.rpc(
            2,
            "thread/read",
            json!({"threadId":CHILD,"includeTurns":true}),
        )?;
        let turns = before.pointer("/thread/turns").context("history turns")?;
        ensure!(
            turns.as_array().is_some_and(|items| !items.is_empty())
                && turns.to_string().contains(SENTINEL),
            "sentinel history not reconstructed"
        );
        server.rpc(3, "thread/unarchive", json!({"threadId":CHILD}))?;
        let after = server.rpc(
            4,
            "thread/read",
            json!({"threadId":CHILD,"includeTurns":true}),
        )?;
        ensure!(
            after.pointer("/thread/turns") == Some(turns),
            "history changed after native unarchive"
        );
        let sql = format!("SELECT archived,rollout_path FROM threads WHERE id='{CHILD}';");
        let row = String::from_utf8(command(
            &root,
            &home,
            &[
                "/usr/bin/sqlite3",
                "-readonly",
                database.to_str().context("database")?,
                &sql,
            ],
            &format!("{label}-final-index"),
        )?)?;
        let (state, path) = row.trim().split_once('|').context("final index row")?;
        ensure!(state == "0", "unarchive did not update native index");
        let recovered = Path::new(path).canonicalize()?;
        ensure!(
            recovered.starts_with(home.join("codex/sessions")) && hash(&recovered)? == stored_hash,
            "unarchived source path/bytes changed"
        );
        ensure!(
            hash(&original)? == original_hash,
            "external-original fixture changed"
        );
        drop(server);
        eprintln!("qualified {label}: fresh native index, sentinel read/unarchive/read parity, original SHA {original_hash}");
    }
    Ok(())
}
