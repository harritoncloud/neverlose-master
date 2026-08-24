use anyhow::{Context, Result};
use std::path::Path;

use super::types::StateData;

pub(crate) async fn persist_state(path: &Path, state: &StateData) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(state).context("failed to serialize state")?;
    tokio::fs::write(&tmp, &json)
        .await
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!(
            "failed to rename {} -> {}",
            tmp.display(),
            path.display()
        ))
}

pub fn now_iso() -> String {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    chrono_now(dur)
}

fn chrono_now(dur: std::time::Duration) -> String {
    let secs = dur.as_secs();
    let days_since_epoch = secs / 86400;
    let secs_of_day = secs % 86400;
    let (y, m, d) = days_to_date((days_since_epoch as i64) + 719468);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn days_to_date(days: i64) -> (i64, i64, i64) {
    let era = if days >= 0 {
        days
    } else {
        days - 146096
    } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

pub(crate) fn unix_timestamp() -> i32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i32
}
