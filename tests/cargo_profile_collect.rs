use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct Fixture {
    _temp: TempDir,
    repo: PathBuf,
    profile: PathBuf,
    generated_manifest: PathBuf,
    state_home: PathBuf,
}

fn fixture() -> Result<Fixture> {
    let temp = TempDir::new()?;
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join("src"))?;
    fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"collector-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
    fs::write(repo.join(".gitignore"), "/target\n")?;
    git(&repo, &["init", "-q"])?;
    git(
        &repo,
        &["config", "user.email", "collector@example.invalid"],
    )?;
    git(&repo, &["config", "user.name", "Collector Test"])?;
    git(&repo, &["add", "Cargo.toml", "src/lib.rs", ".gitignore"])?;
    git(&repo, &["commit", "-qm", "fixture"])?;

    let profile = repo.join("target/debug");
    fs::create_dir_all(profile.join("deps"))?;
    fs::write(profile.join(".cargo-lock"), "")?;
    fs::write(profile.join("deps/libfixture.rlib"), "rebuildable")?;

    let generated_manifest = temp.path().join("generated.json");
    fs::write(
        &generated_manifest,
        serde_json::to_vec_pretty(&json!({
            "manifest_version": 2,
            "collector": "generated",
            "generated_at_unix": 1,
            "plan": {"artifacts": [{
                "name": "target",
                "path": repo.join("target"),
                "worktree_path": repo,
                "rebuildable_opportunity": true,
                "measurement": {
                    "complete": true,
                    "metrics": {"private_reclaimable_complete": true}
                },
                "in_use": false,
                "protection": null,
                "has_tracked_files": false,
                "ignored": true,
                "open_handle_evidence": "complete"
            }]}
        }))?,
    )?;

    Ok(Fixture {
        state_home: temp.path().join("state"),
        _temp: temp,
        repo,
        profile,
        generated_manifest,
    })
}

fn git(repo: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git").args(args).current_dir(repo).output()?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn collect(fixture: &Fixture, execute_digest: Option<&str>) -> Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_worktree-gc"));
    command
        .args(["collect", "cargo-profiles", "--generated-manifest"])
        .arg(&fixture.generated_manifest)
        .args(["--max-entries", "10000"])
        .env("XDG_STATE_HOME", &fixture.state_home)
        .env("HOME", fixture._temp.path());
    if let Some(digest) = execute_digest {
        command.args(["--execute", "--approved-digest", digest]);
    }
    command.output().context("run Cargo profile collector")
}

fn manifests(fixture: &Fixture) -> Result<Vec<(PathBuf, Value)>> {
    let directory = fixture.state_home.join("worktree-gc/collectors");
    let mut manifests = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.contains("cargo-profile-opportunities-") && name.ends_with(".json")
                })
        })
        .map(|path| {
            let value = serde_json::from_slice(&fs::read(&path)?)?;
            Ok((path, value))
        })
        .collect::<Result<Vec<_>>>()?;
    manifests.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(manifests)
}

#[test]
fn exact_approved_plan_resets_only_the_cargo_profile_and_records_success() -> Result<()> {
    let fixture = fixture()?;
    let dry_run = collect(&fixture, None)?;
    anyhow::ensure!(
        dry_run.status.success(),
        "dry-run failed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    let dry_manifest = manifests(&fixture)?
        .pop()
        .context("missing dry-run manifest")?
        .1;
    let digest = dry_manifest["plan"]["eligibility_digest"]
        .as_str()
        .context("missing eligibility digest")?;
    assert_eq!(
        dry_manifest["plan"]["candidates"].as_array().unwrap().len(),
        1,
        "dry-run stdout: {}\nmanifest: {}",
        String::from_utf8_lossy(&dry_run.stdout),
        serde_json::to_string_pretty(&dry_manifest)?
    );

    let execution = collect(&fixture, Some(digest))?;
    anyhow::ensure!(
        execution.status.success(),
        "execution failed: {}",
        String::from_utf8_lossy(&execution.stderr)
    );
    assert!(!fixture.profile.exists());
    assert!(fixture.repo.join("Cargo.toml").is_file());
    assert!(fixture.repo.join("src/lib.rs").is_file());
    assert!(!fixture.repo.join("target/.worktree-gc-trash").exists());

    let execute_manifest = manifests(&fixture)?
        .into_iter()
        .map(|(_, value)| value)
        .find(|value| value["mode"] == "execute")
        .context("missing execute manifest")?;
    assert_eq!(execute_manifest["outcome"]["profiles_reset"], 1);
    assert_eq!(execute_manifest["outcome"]["verification_complete"], true);
    assert_eq!(execute_manifest["outcome"]["error"], Value::Null);
    assert!(execute_manifest["outcome"]["remaining_paths"]
        .as_array()
        .unwrap()
        .is_empty());
    Ok(())
}

#[test]
fn execution_stops_if_the_target_is_no_longer_ignored() -> Result<()> {
    let fixture = fixture()?;
    let dry_run = collect(&fixture, None)?;
    anyhow::ensure!(dry_run.status.success(), "initial dry-run failed");
    let dry_manifest = manifests(&fixture)?
        .pop()
        .context("missing dry-run manifest")?
        .1;
    let digest = dry_manifest["plan"]["eligibility_digest"]
        .as_str()
        .context("missing eligibility digest")?;

    fs::write(fixture.repo.join(".gitignore"), "")?;
    git(&fixture.repo, &["add", ".gitignore"])?;
    git(&fixture.repo, &["commit", "-qm", "track ignore change"])?;
    let execution = collect(&fixture, Some(digest))?;
    assert!(!execution.status.success());
    assert!(fixture.profile.is_dir());
    assert!(
        String::from_utf8_lossy(&execution.stderr).contains("does not match current plan"),
        "unexpected execution stderr: {}",
        String::from_utf8_lossy(&execution.stderr)
    );
    Ok(())
}
