//! Advisory checks: no registry locks, journals, or native store writes.
use super::*;

fn record(checks: &mut Vec<Value>, name: &str, result: Result<Value>) {
    checks.push(match result {
        Ok(evidence) => json!({"check":name,"status":"passed","evidence":evidence}),
        Err(error) => json!({"check":name,"status":"failed","error":format!("{error:#}")}),
    });
}

pub(super) fn capacity_evidence(policy: &Policy, internal: u64, external: u64) -> Result<Value> {
    // Preflight deliberately does not read/decompress rollouts. Reserve apply's
    // largest permitted per-task scratch requirement; tasks run sequentially.
    let required = policy.native_headroom(policy.max_raw_bytes_per_task)?;
    ensure!(
        internal >= required,
        "Data below conservative migration scratch requirement: available {internal}, required {required}"
    );
    ensure!(
        external >= policy.max_source_bytes.saturating_add(GIB),
        "backup below batch capacity: {external}"
    );
    Ok(
        json!({"internal_available_bytes":internal,"external_available_bytes":external,"required_internal_available_bytes":required,"scratch_reserve_bytes":required-policy.min_free_bytes,"scratch_basis":"configured maximum raw bytes per task; apply rechecks measured raw bytes"}),
    )
}

pub fn preflight(config: &Path) -> Result<Value> {
    ensure!(
        cfg!(target_os = "macos"),
        "migration preflight requires macOS"
    );
    let mut checks = Vec::new();
    let policy = match Policy::parse(config) {
        Ok(policy) => policy,
        Err(error) => {
            record(&mut checks, "policy", Err(error));
            for name in [
                "paths_and_bounds",
                "capacity",
                "native_binary",
                "zstd_binary",
                "sandbox",
                "external_volume",
                "protections",
                "journals",
                "candidates",
                "quiet_store",
            ] {
                checks.push(json!({"check":name,"status":"blocked","reason":"policy unavailable"}));
            }
            return Ok(report(checks, None));
        }
    };
    record(
        &mut checks,
        "policy",
        Ok(json!({"sha256":policy.policy_sha256,"enabled":policy.enabled})),
    );
    record(&mut checks, "paths_and_bounds", policy.validate().map(|()| json!({"codex_home":policy.codex_home,"backup_root":policy.backup_root,"journal_root":policy.journal_root})));
    let cancel = io::Cancellation::install()?;
    // Bound even a malformed policy; preflight probes do not share apply's
    // capacity guard, so low capacity cannot mask independent diagnostics.
    let runtime = native::NativeRuntime::for_preflight(&policy, &cancel);
    record(
        &mut checks,
        "capacity",
        (|| {
            let internal = io::free(&policy.codex_home)?;
            let external = io::free(&policy.backup_root)?;
            capacity_evidence(&policy, internal, external)
        })(),
    );
    record(
        &mut checks,
        "native_binary",
        runtime
            .verify_binary()
            .map(|()| json!({"sha256":policy.codex_sha256,"version":NATIVE_VERSION})),
    );
    record(&mut checks, "zstd_binary", runtime.verify_zstd());
    record(
        &mut checks,
        "sandbox",
        runtime
            .sandbox_probe()
            .map(|()| json!({"network_denied":true,"writes_denied":true})),
    );
    record(
        &mut checks,
        "external_volume",
        runtime
            .volume()
            .map(|()| json!({"uuid":policy.backup_volume_uuid,"physically_external":true})),
    );
    record(
        &mut checks,
        "protections",
        crate::protection::protection_registry_path()
            .and_then(|path| {
                MigrationProtectionGuard::observe(&path, &policy.surfaces(), SystemTime::now())
            })
            .map(|()| json!({"advisory":true})),
    );
    record(
        &mut checks,
        "journals",
        pending_journals(&policy.journal_root).map(|()| json!({"pending":false})),
    );
    record(
        &mut checks,
        "candidates",
        index_snapshot(&policy.codex_home)
            .and_then(|(rows, edges)| plan(&rows, &edges, &policy, now()))
            .and_then(|plan| Ok(serde_json::to_value(plan)?)),
    );
    match runtime.active_codex_pids() {
        Ok(pids) if !pids.is_empty() => {
            checks.push(json!({"check":"quiet_store","status":"awaiting_shutdown","pids":pids}))
        }
        result => record(
            &mut checks,
            "quiet_store",
            result.map(|pids| json!({"pids":pids})),
        ),
    }
    Ok(report(checks, Some(&policy.policy_sha256)))
}

fn report(checks: Vec<Value>, digest: Option<&str>) -> Value {
    let ready = checks
        .iter()
        .all(|c| c["status"] == "passed" || c["status"] == "awaiting_shutdown");
    json!({"version":1,"mode":"preflight","observed_at":now(),"policy_sha256":digest,"ready":ready,"checks":checks,"advisory_only":true})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preflight_readiness_requires_every_available_check() {
        for status in ["failed", "blocked"] {
            assert_eq!(
                report(
                    vec![
                        json!({"status":"awaiting_shutdown"}),
                        json!({"status":status})
                    ],
                    None
                )["ready"],
                false
            );
        }
        assert_eq!(
            report(
                vec![
                    json!({"status":"passed"}),
                    json!({"status":"awaiting_shutdown"})
                ],
                None
            )["ready"],
            true
        );
    }
}
