use crate::WorktreeInfo;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const PULL_REQUESTS_PER_BRANCH_LIMIT: usize = 20;
const BRANCHES_PER_QUERY: usize = 25;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PullRequestPolicy {
    pub merged_grace_days: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestLifecycle {
    NotApplicable,
    None,
    Open,
    Merged,
    Closed,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PullRequestState {
    Open,
    Merged,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PullRequestRecord {
    pub repository: String,
    pub number: u64,
    pub url: String,
    pub state: PullRequestState,
    pub head_ref_name: String,
    pub head_oid: String,
    pub merged_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PullRequestEvidence {
    pub provider: String,
    pub observed_at_unix: u64,
    pub complete: bool,
    pub lifecycle: PullRequestLifecycle,
    pub repositories: Vec<String>,
    pub pull_requests: Vec<PullRequestRecord>,
    pub error: Option<String>,
}

impl PullRequestEvidence {
    fn not_applicable(observed_at_unix: u64) -> Self {
        Self {
            provider: "github".to_string(),
            observed_at_unix,
            complete: true,
            lifecycle: PullRequestLifecycle::NotApplicable,
            repositories: Vec::new(),
            pull_requests: Vec::new(),
            error: None,
        }
    }
}

#[derive(Default)]
struct EvidenceAccumulator {
    complete: bool,
    pull_requests: Vec<PullRequestRecord>,
    errors: Vec<String>,
}

pub(crate) fn observe_pull_requests(
    repo: &Path,
    worktrees: &[WorktreeInfo],
    now: SystemTime,
) -> BTreeMap<(String, String), PullRequestEvidence> {
    let observed_at_unix = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let branch_heads = worktrees
        .iter()
        .filter(|worktree| {
            worktree.exists
                && worktree.prunable.is_none()
                && !worktree.detached
                && worktree.branch.is_some()
        })
        .filter_map(|worktree| Some((worktree.branch.clone()?, worktree.head.clone()?)))
        .collect::<BTreeSet<_>>();
    if branch_heads.is_empty() {
        return BTreeMap::new();
    }
    let repositories = match github_repositories(repo) {
        Ok(repositories) => repositories,
        Err(error) => {
            return branch_heads
                .into_iter()
                .map(|branch_head| {
                    (
                        branch_head,
                        incomplete_evidence(
                            observed_at_unix,
                            Vec::new(),
                            format!("failed to inspect GitHub remotes: {error:#}"),
                        ),
                    )
                })
                .collect();
        }
    };
    if repositories.is_empty() {
        return branch_heads
            .into_iter()
            .map(|branch_head| {
                (
                    branch_head,
                    PullRequestEvidence::not_applicable(observed_at_unix),
                )
            })
            .collect();
    }

    let mut accumulators = branch_heads
        .iter()
        .cloned()
        .map(|branch_head| {
            (
                branch_head,
                EvidenceAccumulator {
                    complete: true,
                    ..EvidenceAccumulator::default()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let branch_heads = branch_heads.into_iter().collect::<Vec<_>>();
    for repository in &repositories {
        for batch in branch_heads.chunks(BRANCHES_PER_QUERY) {
            match query_pull_requests_for_branches(repository, batch) {
                Ok(observations) => {
                    for (branch_head, observation) in observations {
                        let accumulator = accumulators
                            .get_mut(&branch_head)
                            .expect("queried branch head must have an accumulator");
                        accumulator.complete &= observation.complete;
                        accumulator.pull_requests.extend(observation.pull_requests);
                        accumulator.errors.extend(observation.errors);
                    }
                }
                Err(error) => {
                    for branch_head in batch {
                        let accumulator = accumulators
                            .get_mut(branch_head)
                            .expect("queried branch head must have an accumulator");
                        accumulator.complete = false;
                        accumulator.errors.push(format!(
                            "failed to query {repository} for {} at {}: {error:#}",
                            branch_head.0, branch_head.1
                        ));
                    }
                }
            }
        }
    }

    accumulators
        .into_iter()
        .map(|(branch_head, mut accumulator)| {
            accumulator.pull_requests.sort_by(|left, right| {
                (&left.repository, left.number, left.state as u8).cmp(&(
                    &right.repository,
                    right.number,
                    right.state as u8,
                ))
            });
            accumulator.pull_requests.dedup();
            accumulator.errors.sort();
            accumulator.errors.dedup();
            let lifecycle = classify_lifecycle(accumulator.complete, &accumulator.pull_requests);
            (
                branch_head,
                PullRequestEvidence {
                    provider: "github".to_string(),
                    observed_at_unix,
                    complete: accumulator.complete,
                    lifecycle,
                    repositories: repositories.clone(),
                    pull_requests: accumulator.pull_requests,
                    error: (!accumulator.errors.is_empty()).then(|| accumulator.errors.join("; ")),
                },
            )
        })
        .collect()
}

fn classify_lifecycle(complete: bool, records: &[PullRequestRecord]) -> PullRequestLifecycle {
    if !complete {
        PullRequestLifecycle::Incomplete
    } else if records
        .iter()
        .any(|record| record.state == PullRequestState::Open)
    {
        PullRequestLifecycle::Open
    } else if records
        .iter()
        .any(|record| record.state == PullRequestState::Merged)
    {
        PullRequestLifecycle::Merged
    } else if records
        .iter()
        .any(|record| record.state == PullRequestState::Closed)
    {
        PullRequestLifecycle::Closed
    } else {
        PullRequestLifecycle::None
    }
}

fn incomplete_evidence(
    observed_at_unix: u64,
    repositories: Vec<String>,
    error: String,
) -> PullRequestEvidence {
    PullRequestEvidence {
        provider: "github".to_string(),
        observed_at_unix,
        complete: false,
        lifecycle: PullRequestLifecycle::Incomplete,
        repositories,
        pull_requests: Vec::new(),
        error: Some(error),
    }
}

fn github_repositories(repo: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .args(["remote", "-v"])
        .current_dir(repo)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to inspect Git remotes in {}", repo.display()))?;
    if !output.status.success() {
        bail!(
            "git remote -v failed in {}: {}",
            repo.display(),
            bounded_error(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(parse_github_repository)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn parse_github_repository(remote: &str) -> Option<String> {
    let path = remote
        .strip_prefix("https://github.com/")
        .or_else(|| remote.strip_prefix("http://github.com/"))
        .or_else(|| remote.strip_prefix("git://github.com/"))
        .or_else(|| remote.strip_prefix("ssh://git@github.com/"))
        .or_else(|| remote.strip_prefix("git@github.com:"))?;
    let path = path
        .trim_end_matches('/')
        .strip_suffix(".git")
        .unwrap_or(path);
    let mut components = path.split('/');
    let owner = components.next()?;
    let name = components.next()?;
    if owner.is_empty() || name.is_empty() || components.next().is_some() {
        return None;
    }
    Some(format!("{owner}/{name}"))
}

struct QueryObservation {
    complete: bool,
    pull_requests: Vec<PullRequestRecord>,
    errors: Vec<String>,
}

fn query_pull_requests_for_branches(
    repository: &str,
    branch_heads: &[(String, String)],
) -> Result<BTreeMap<(String, String), QueryObservation>> {
    let query = build_query(repository, branch_heads)?;
    let output = Command::new("gh")
        .args(["api", "graphql", "-f"])
        .arg(format!("query={query}"))
        .env("GH_HTTP_TIMEOUT", "10")
        .stdin(Stdio::null())
        .output()
        .context("failed to launch gh api graphql")?;
    if !output.status.success() {
        bail!("gh api graphql failed: {}", bounded_error(&output.stderr));
    }
    parse_query_response(repository, branch_heads, &output.stdout)
}

fn build_query(repository: &str, branch_heads: &[(String, String)]) -> Result<String> {
    let (owner, name) = repository
        .split_once('/')
        .context("GitHub repository must be owner/name")?;
    let mut query = format!(
        "query {{ repository(owner: {}, name: {}) {{",
        serde_json::to_string(owner)?,
        serde_json::to_string(name)?
    );
    for (index, (branch, head)) in branch_heads.iter().enumerate() {
        if !matches!(head.len(), 40 | 64) || !head.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid Git object id {head:?}");
        }
        query.push_str(&format!(
            " c{index}: pullRequests(first: {PULL_REQUESTS_PER_BRANCH_LIMIT}, headRefName: {}, states: [OPEN, MERGED, CLOSED], orderBy: {{ field: UPDATED_AT, direction: DESC }}) {{ pageInfo {{ hasNextPage }} nodes {{ number url state mergedAt headRefName headRefOid }} }}",
            serde_json::to_string(branch)?
        ));
    }
    query.push_str(" } }");
    Ok(query)
}

fn parse_query_response(
    repository: &str,
    branch_heads: &[(String, String)],
    output: &[u8],
) -> Result<BTreeMap<(String, String), QueryObservation>> {
    let value: Value =
        serde_json::from_slice(output).context("failed to parse gh GraphQL output")?;
    if let Some(errors) = value.get("errors") {
        bail!("GitHub GraphQL returned errors: {errors}");
    }
    let repository_value = value
        .pointer("/data/repository")
        .context("GitHub GraphQL response omitted data.repository")?;
    if repository_value.is_null() {
        bail!("GitHub repository {repository} was not found");
    }

    branch_heads
        .iter()
        .enumerate()
        .map(|(index, (branch, head))| {
            let connection = repository_value
                .get(format!("c{index}"))
                .context("GitHub GraphQL response omitted branch alias")?;
            let has_next_page = connection
                .pointer("/pageInfo/hasNextPage")
                .and_then(Value::as_bool)
                .context("GitHub PR connection omitted pageInfo.hasNextPage")?;
            let nodes = connection
                .get("nodes")
                .and_then(Value::as_array)
                .context("GitHub PR connection omitted nodes")?;
            let mut records = Vec::new();
            let mut errors = Vec::new();
            for node in nodes {
                let Some(node_branch) = node.get("headRefName").and_then(Value::as_str) else {
                    errors.push("pull request omitted headRefName".to_string());
                    continue;
                };
                if node_branch != branch {
                    errors.push(format!(
                        "branch-filtered query for {branch:?} returned {node_branch:?}"
                    ));
                    continue;
                }
                let Some(node_head) = node.get("headRefOid").and_then(Value::as_str) else {
                    errors.push("pull request omitted headRefOid".to_string());
                    continue;
                };
                if !node_head.eq_ignore_ascii_case(head) {
                    continue;
                }
                match parse_record(repository, node) {
                    Ok(record) => records.push(record),
                    Err(error) => errors.push(error.to_string()),
                }
            }
            Ok((
                (branch.clone(), head.clone()),
                QueryObservation {
                    complete: !has_next_page && errors.is_empty(),
                    pull_requests: records,
                    errors,
                },
            ))
        })
        .collect()
}

fn parse_record(repository: &str, value: &Value) -> Result<PullRequestRecord> {
    let state = match value
        .get("state")
        .and_then(Value::as_str)
        .context("associated PR omitted state")?
    {
        "OPEN" => PullRequestState::Open,
        "MERGED" => PullRequestState::Merged,
        "CLOSED" => PullRequestState::Closed,
        state => bail!("associated PR reported unknown state {state:?}"),
    };
    let merged_at_unix = value
        .get("mergedAt")
        .and_then(Value::as_str)
        .map(|merged_at| {
            OffsetDateTime::parse(merged_at, &Rfc3339)
                .map(|time| time.unix_timestamp())
                .with_context(|| format!("invalid mergedAt {merged_at:?}"))
        })
        .transpose()?;
    if state == PullRequestState::Merged && merged_at_unix.is_none() {
        bail!("merged PR omitted mergedAt");
    }
    Ok(PullRequestRecord {
        repository: repository.to_string(),
        number: value
            .get("number")
            .and_then(Value::as_u64)
            .context("associated PR omitted number")?,
        url: value
            .get("url")
            .and_then(Value::as_str)
            .context("associated PR omitted URL")?
            .to_string(),
        state,
        head_ref_name: value
            .get("headRefName")
            .and_then(Value::as_str)
            .context("associated PR omitted headRefName")?
            .to_string(),
        head_oid: value
            .get("headRefOid")
            .and_then(Value::as_str)
            .context("associated PR omitted headRefOid")?
            .to_string(),
        merged_at_unix,
    })
}

fn bounded_error(output: &[u8]) -> String {
    String::from_utf8_lossy(output)
        .trim()
        .chars()
        .take(1_000)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_supported_github_remote_spellings() {
        for remote in [
            "https://github.com/vercel/v0.git",
            "git@github.com:vercel/v0.git",
            "ssh://git@github.com/vercel/v0.git",
            "git://github.com/vercel/v0",
        ] {
            assert_eq!(
                parse_github_repository(remote).as_deref(),
                Some("vercel/v0")
            );
        }
        assert_eq!(
            parse_github_repository("https://example.com/vercel/v0.git"),
            None
        );
    }

    #[test]
    fn query_parser_keeps_only_exact_head_pull_requests() -> Result<()> {
        let branch = "wycats/feature".to_string();
        let head = "a".repeat(40);
        let other = "b".repeat(40);
        let fixture = json!({
            "data": {
                "repository": {
                    "c0": {
                        "pageInfo": { "hasNextPage": false },
                        "nodes": [
                            {
                                "number": 12,
                                "url": "https://github.com/acme/repo/pull/12",
                                "state": "MERGED",
                                "mergedAt": "2026-07-20T12:00:00Z",
                                "headRefName": branch,
                                "headRefOid": head,
                            },
                            {
                                "number": 11,
                                "url": "https://github.com/acme/repo/pull/11",
                                "state": "MERGED",
                                "mergedAt": "2026-07-19T12:00:00Z",
                                "headRefName": branch,
                                "headRefOid": other,
                            }
                        ]
                    }
                }
            }
        });
        let key = (branch.clone(), head.clone());
        let parsed = parse_query_response(
            "acme/repo",
            std::slice::from_ref(&key),
            &serde_json::to_vec(&fixture)?,
        )?;
        let observation = &parsed[&key];
        assert!(observation.complete);
        assert_eq!(observation.pull_requests.len(), 1);
        assert_eq!(observation.pull_requests[0].number, 12);
        Ok(())
    }

    #[test]
    fn query_parser_fails_closed_on_pagination() -> Result<()> {
        let branch = "wycats/feature".to_string();
        let head = "a".repeat(40);
        let fixture = json!({
            "data": {
                "repository": {
                    "c0": {
                        "pageInfo": { "hasNextPage": true },
                        "nodes": []
                    }
                }
            }
        });
        let key = (branch.clone(), head.clone());
        let parsed = parse_query_response(
            "acme/repo",
            std::slice::from_ref(&key),
            &serde_json::to_vec(&fixture)?,
        )?;
        assert!(!parsed[&key].complete);
        Ok(())
    }

    #[test]
    fn query_uses_retained_pr_head_metadata_instead_of_commit_association() -> Result<()> {
        let query = build_query(
            "acme/repo",
            &[("wycats/feature".to_string(), "a".repeat(40))],
        )?;
        assert!(query.contains("pullRequests(first: 20"));
        assert!(query.contains("headRefName: \"wycats/feature\""));
        assert!(query.contains("headRefOid"));
        assert!(!query.contains("associatedPullRequests"));
        assert!(!query.contains("object(oid:"));
        Ok(())
    }

    #[test]
    fn open_pull_request_takes_precedence_over_merged() {
        let records = vec![
            PullRequestRecord {
                repository: "acme/repo".to_string(),
                number: 1,
                url: "https://github.com/acme/repo/pull/1".to_string(),
                state: PullRequestState::Merged,
                head_ref_name: "wycats/feature".to_string(),
                head_oid: "a".repeat(40),
                merged_at_unix: Some(1),
            },
            PullRequestRecord {
                repository: "acme/repo".to_string(),
                number: 2,
                url: "https://github.com/acme/repo/pull/2".to_string(),
                state: PullRequestState::Open,
                head_ref_name: "wycats/feature".to_string(),
                head_oid: "a".repeat(40),
                merged_at_unix: None,
            },
        ];
        assert_eq!(
            classify_lifecycle(true, &records),
            PullRequestLifecycle::Open
        );
    }
}
