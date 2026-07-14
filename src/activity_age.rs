use jiff::civil::{Date, Weekday};
use jiff::tz::TimeZone;
use jiff::Timestamp;
use serde::Serialize;
use std::time::SystemTime;

pub const WEEKDAY_CALENDAR_ID: &str = "weekday-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActivityAgeEvidence {
    pub elapsed_days: u64,
    pub workdays: u64,
    pub timezone: String,
    pub calendar: &'static str,
    pub activity_local_date: String,
    pub observation_local_date: String,
    pub activity_utc_offset_seconds: i32,
    pub observation_utc_offset_seconds: i32,
}

pub(crate) fn system_local_activity_age(
    now: SystemTime,
    activity_unix: i64,
) -> Option<ActivityAgeEvidence> {
    let timezone = TimeZone::try_system().ok()?;
    let timezone_name = timezone.iana_name().unwrap_or("system-local").to_string();
    let observation = Timestamp::try_from(now).ok()?;
    let activity = Timestamp::from_second(activity_unix).ok()?;
    activity_age_in_timezone(observation, activity, &timezone, timezone_name)
}

pub(crate) fn elapsed_age_days(now: SystemTime, activity_unix: i64) -> Option<u64> {
    let observation = Timestamp::try_from(now).ok()?;
    let activity = Timestamp::from_second(activity_unix).ok()?;
    if activity > observation {
        return None;
    }
    u64::try_from(observation.duration_since(activity).as_secs() / 86_400).ok()
}

fn activity_age_in_timezone(
    observation: Timestamp,
    activity: Timestamp,
    timezone: &TimeZone,
    timezone_name: String,
) -> Option<ActivityAgeEvidence> {
    if activity > observation {
        return None;
    }
    let activity_zoned = activity.to_zoned(timezone.clone());
    let observation_zoned = observation.to_zoned(timezone.clone());
    let activity_date = activity_zoned.date();
    let observation_date = observation_zoned.date();
    Some(ActivityAgeEvidence {
        elapsed_days: u64::try_from(observation.duration_since(activity).as_secs() / 86_400)
            .ok()?,
        workdays: workdays_between(activity_date, observation_date)?,
        timezone: timezone_name,
        calendar: WEEKDAY_CALENDAR_ID,
        activity_local_date: activity_date.to_string(),
        observation_local_date: observation_date.to_string(),
        activity_utc_offset_seconds: activity_zoned.offset().seconds(),
        observation_utc_offset_seconds: observation_zoned.offset().seconds(),
    })
}

fn workdays_between(activity: Date, observation: Date) -> Option<u64> {
    if activity > observation {
        return None;
    }
    let total_days = observation.duration_since(activity).as_hours() / 24;
    let total_days = u64::try_from(total_days).ok()?;
    let full_weeks = total_days / 7;
    let remaining_days = total_days % 7;
    let activity_weekday = u64::try_from(activity.weekday().to_monday_zero_offset()).ok()?;
    let saturday = u64::try_from(Weekday::Saturday.to_monday_zero_offset()).ok()?;
    let mut workdays = full_weeks.saturating_mul(5);
    for offset in 1..=remaining_days {
        let weekday = (activity_weekday + offset) % 7;
        if weekday < saturday {
            workdays = workdays.saturating_add(1);
        }
    }
    Some(workdays)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;
    use std::str::FromStr;

    #[test]
    fn workday_age_skips_weekends() {
        let friday = date(2026, 7, 10);
        assert_eq!(workdays_between(friday, friday), Some(0));
        assert_eq!(workdays_between(friday, date(2026, 7, 13)), Some(1));
        assert_eq!(workdays_between(friday, date(2026, 7, 14)), Some(2));
        assert_eq!(workdays_between(friday, date(2026, 7, 15)), Some(3));
    }

    #[test]
    fn workday_age_counts_complete_weeks_and_remainders() {
        assert_eq!(
            workdays_between(date(2026, 7, 6), date(2026, 7, 13)),
            Some(5)
        );
        assert_eq!(
            workdays_between(date(2026, 7, 11), date(2026, 7, 20)),
            Some(6)
        );
    }

    #[test]
    fn evidence_records_the_calendar_and_local_boundary() {
        let friday = Timestamp::from_str("2026-07-10T23:00:00Z").unwrap();
        let monday = Timestamp::from_str("2026-07-13T01:00:00Z").unwrap();
        let evidence =
            activity_age_in_timezone(monday, friday, &TimeZone::UTC, "UTC".to_string()).unwrap();

        assert_eq!(evidence.elapsed_days, 2);
        assert_eq!(evidence.workdays, 1);
        assert_eq!(evidence.timezone, "UTC");
        assert_eq!(evidence.calendar, WEEKDAY_CALENDAR_ID);
        assert_eq!(evidence.activity_local_date, "2026-07-10");
        assert_eq!(evidence.observation_local_date, "2026-07-13");
        assert_eq!(evidence.activity_utc_offset_seconds, 0);
        assert_eq!(evidence.observation_utc_offset_seconds, 0);
    }

    #[test]
    fn future_activity_is_not_age_evidence() {
        assert_eq!(workdays_between(date(2026, 7, 15), date(2026, 7, 14)), None);
    }
}
