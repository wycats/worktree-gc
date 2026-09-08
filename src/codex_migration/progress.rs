//! Bounded, content-free progress on stderr; stdout remains the final JSON report.
use std::cell::RefCell;
use std::io::Write;
use std::time::{Duration, Instant};

pub(super) struct Progress {
    state: RefCell<State>,
    enabled: bool,
}
struct State {
    started: Instant,
    stage_started: Instant,
    last: Instant,
    task: String,
    stage: &'static str,
    bytes: Option<u64>,
}
impl Progress {
    pub fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            state: RefCell::new(State {
                started: now,
                stage_started: now,
                last: now,
                task: "batch".into(),
                stage: "starting",
                bytes: None,
            }),
        }
    }
    pub fn task(&self, index: usize, total: usize, id: &str) {
        self.state.borrow_mut().task = format!("task {index}/{total} {id:?}");
        self.stage("checking candidate");
    }
    pub fn stage(&self, stage: &'static str) {
        let mut state = self.state.borrow_mut();
        state.stage = stage;
        state.stage_started = Instant::now();
        state.bytes = None;
        drop(state);
        self.emit(true);
    }
    pub fn bytes(&self, count: u64) {
        let mut state = self.state.borrow_mut();
        state.bytes = Some(state.bytes.unwrap_or(0).saturating_add(count));
        drop(state);
        self.emit(false);
    }
    pub fn tick(&self) {
        self.emit(false);
    }
    fn emit(&self, force: bool) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.borrow_mut();
        if !force && state.last.elapsed() < Duration::from_secs(1) {
            return;
        }
        let line = render(
            &state,
            state.started.elapsed(),
            state.stage_started.elapsed(),
        );
        // Telemetry failure must not abort an already-applying native operation.
        // Safety/results remain in durable journals, independent of terminal I/O.
        let _ = writeln!(std::io::stderr().lock(), "{line}");
        state.last = Instant::now();
    }
}
fn render(state: &State, elapsed: Duration, stage_elapsed: Duration) -> String {
    let bytes = state
        .bytes
        .map(|n| {
            format!(
                " | {n} decompressed bytes | {:.1} MiB/s",
                n as f64 / 1048576.0 / stage_elapsed.as_secs_f64().max(0.001)
            )
        })
        .unwrap_or_default();
    format!(
        "[migration {}] {} | elapsed {:.1}s | stage {:.1}s{bytes}",
        state.task,
        state.stage,
        elapsed.as_secs_f64(),
        stage_elapsed.as_secs_f64()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_reports_stage_bytes_rate_and_escaped_task_identity() {
        let p = Progress::new(false);
        p.task(2, 4, "id\n\x1b");
        p.stage("verifying original continuation");
        p.bytes(10485760);
        let text = render(
            &p.state.borrow(),
            Duration::from_secs(8),
            Duration::from_secs(2),
        );
        assert!(
            text.contains("task 2/4")
                && text.contains("10485760 decompressed bytes")
                && text.contains("5.0 MiB/s")
        );
        assert!(!text.chars().any(char::is_control));
        p.stage("native migration");
        assert_eq!(p.state.borrow().bytes, None);
    }
}
