//! Time-range selection for the CloudWatch Search screen.
//!
//! - `TimeRangePreset` cycles through 1h / 3h / 6h / 24h.
//! - `TimeRange` owns the user's current choice (preset or a custom UTC window).
//! - Resolvers convert the choice to the concrete (start, end) windows expected
//!   by `FilterLogEventsRequest` (millis) and `StartInsightsQueryRequest`
//!   (seconds), sampling `Utc::now()` once per call to avoid skew.

use chrono::{NaiveDateTime, TimeZone, Utc};

/// Maximum allowed custom-range span: 30 days, inclusive.
pub const MAX_CUSTOM_RANGE_SECS: i64 = 30 * 86_400;

/// Format accepted by the custom-range modal (UTC).
pub const CUSTOM_DATETIME_FMT: &str = "%Y-%m-%d %H:%M";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRangePreset {
    OneHour,
    ThreeHours,
    SixHours,
    TwentyFourHours,
}

impl TimeRangePreset {
    pub fn duration_secs(self) -> i64 {
        match self {
            Self::OneHour => 3_600,
            Self::ThreeHours => 3 * 3_600,
            Self::SixHours => 6 * 3_600,
            Self::TwentyFourHours => 24 * 3_600,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::ThreeHours => "3h",
            Self::SixHours => "6h",
            Self::TwentyFourHours => "24h",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::OneHour => Self::ThreeHours,
            Self::ThreeHours => Self::SixHours,
            Self::SixHours => Self::TwentyFourHours,
            Self::TwentyFourHours => Self::OneHour,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeRange {
    Preset(TimeRangePreset),
    /// Custom window stored as UTC Unix-epoch seconds.
    Custom { start_secs: i64, end_secs: i64 },
}

impl Default for TimeRange {
    fn default() -> Self {
        Self::Preset(TimeRangePreset::OneHour)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeRangeError {
    /// `end` not strictly greater than `start`.
    EndBeforeStart,
    /// `end - start` exceeds `MAX_CUSTOM_RANGE_SECS`.
    RangeTooLong,
    /// Failed to parse a datetime string.
    ParseError(String),
}

impl std::fmt::Display for TimeRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EndBeforeStart => write!(f, "End must be after start"),
            Self::RangeTooLong => write!(f, "Range must not exceed 30 days"),
            Self::ParseError(field) => write!(
                f,
                "Invalid date in {}; use YYYY-MM-DD HH:MM (UTC)",
                field
            ),
        }
    }
}

impl TimeRange {
    /// Cycle to the next preset. If currently a custom range, reset to 1h.
    pub fn cycle_preset(&mut self) {
        *self = match self {
            Self::Preset(p) => Self::Preset(p.next()),
            Self::Custom { .. } => Self::Preset(TimeRangePreset::OneHour),
        };
    }

    /// Set a custom UTC window. Validates `end > start` and span ≤ 30 days.
    pub fn set_custom(&mut self, start_secs: i64, end_secs: i64) -> Result<(), TimeRangeError> {
        if end_secs <= start_secs {
            return Err(TimeRangeError::EndBeforeStart);
        }
        if end_secs - start_secs > MAX_CUSTOM_RANGE_SECS {
            return Err(TimeRangeError::RangeTooLong);
        }
        *self = Self::Custom {
            start_secs,
            end_secs,
        };
        Ok(())
    }

    /// Resolve to (start_ms, end_ms) for FilterLogEvents.
    pub fn resolve_filter_log_events_window(&self) -> (i64, i64) {
        let (s, e) = self.resolve_secs();
        (s * 1000, e * 1000)
    }

    /// Resolve to (start_secs, end_secs) for Logs Insights StartQuery.
    pub fn resolve_insights_window(&self) -> (i64, i64) {
        self.resolve_secs()
    }

    fn resolve_secs(&self) -> (i64, i64) {
        match self {
            Self::Preset(p) => {
                let now = Utc::now().timestamp();
                (now - p.duration_secs(), now)
            }
            Self::Custom {
                start_secs,
                end_secs,
            } => (*start_secs, *end_secs),
        }
    }

    /// Short label for the footer/status bar.
    pub fn footer_label(&self) -> String {
        match self {
            Self::Preset(p) => p.label().to_string(),
            Self::Custom {
                start_secs,
                end_secs,
            } => {
                let start = Utc
                    .timestamp_opt(*start_secs, 0)
                    .single()
                    .map(|dt| dt.format(CUSTOM_DATETIME_FMT).to_string())
                    .unwrap_or_else(|| start_secs.to_string());
                let end = Utc
                    .timestamp_opt(*end_secs, 0)
                    .single()
                    .map(|dt| dt.format(CUSTOM_DATETIME_FMT).to_string())
                    .unwrap_or_else(|| end_secs.to_string());
                format!("custom {}→{} UTC", start, end)
            }
        }
    }
}

/// Parse a `"YYYY-MM-DD HH:MM"` string as a UTC Unix-epoch second count.
///
/// `field_label` is used in the returned error so the modal can highlight which
/// field failed to parse.
pub fn parse_utc_datetime(s: &str, field_label: &str) -> Result<i64, TimeRangeError> {
    let trimmed = s.trim();
    NaiveDateTime::parse_from_str(trimmed, CUSTOM_DATETIME_FMT)
        .map_err(|_| TimeRangeError::ParseError(field_label.to_string()))
        .map(|ndt| ndt.and_utc().timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_cycle_wraps_one_hour_to_one_hour() {
        let mut r = TimeRange::default();
        for _ in 0..4 {
            r.cycle_preset();
        }
        assert_eq!(r, TimeRange::Preset(TimeRangePreset::OneHour));
    }

    #[test]
    fn cycle_visits_3h_6h_24h() {
        let mut r = TimeRange::default();
        r.cycle_preset();
        assert_eq!(r, TimeRange::Preset(TimeRangePreset::ThreeHours));
        r.cycle_preset();
        assert_eq!(r, TimeRange::Preset(TimeRangePreset::SixHours));
        r.cycle_preset();
        assert_eq!(r, TimeRange::Preset(TimeRangePreset::TwentyFourHours));
    }

    #[test]
    fn cycle_from_custom_resets_to_one_hour() {
        let mut r = TimeRange::Custom {
            start_secs: 1_000_000,
            end_secs: 1_000_000 + 7 * 86_400,
        };
        r.cycle_preset();
        assert_eq!(r, TimeRange::Preset(TimeRangePreset::OneHour));
    }

    #[test]
    fn parse_valid_iso_minute_precision() {
        // 2026-05-01 14:00 UTC → known Unix timestamp
        let ts = parse_utc_datetime("2026-05-01 14:00", "start").unwrap();
        // sanity: roundtrip back to the same string
        let dt = Utc.timestamp_opt(ts, 0).single().unwrap();
        assert_eq!(dt.format(CUSTOM_DATETIME_FMT).to_string(), "2026-05-01 14:00");
    }

    #[test]
    fn parse_invalid_returns_err() {
        assert!(matches!(
            parse_utc_datetime("not a date", "start"),
            Err(TimeRangeError::ParseError(_))
        ));
        assert!(matches!(
            parse_utc_datetime("2026-13-40 99:99", "end"),
            Err(TimeRangeError::ParseError(_))
        ));
        assert!(matches!(
            parse_utc_datetime("", "start"),
            Err(TimeRangeError::ParseError(_))
        ));
    }

    #[test]
    fn parse_error_carries_field_label() {
        let err = parse_utc_datetime("garbage", "end").unwrap_err();
        match err {
            TimeRangeError::ParseError(label) => assert_eq!(label, "end"),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn validation_30_days_inclusive_accepted() {
        let mut r = TimeRange::default();
        let start = 1_700_000_000_i64;
        let end = start + MAX_CUSTOM_RANGE_SECS; // exactly 30 days
        r.set_custom(start, end).expect("30 days inclusive should be ok");
        assert_eq!(
            r,
            TimeRange::Custom {
                start_secs: start,
                end_secs: end
            }
        );
    }

    #[test]
    fn validation_30_days_plus_one_sec_rejected() {
        let mut r = TimeRange::default();
        let start = 1_700_000_000_i64;
        let end = start + MAX_CUSTOM_RANGE_SECS + 1;
        assert_eq!(r.set_custom(start, end), Err(TimeRangeError::RangeTooLong));
        // state unchanged
        assert_eq!(r, TimeRange::Preset(TimeRangePreset::OneHour));
    }

    #[test]
    fn validation_end_equal_start_rejected() {
        let mut r = TimeRange::default();
        assert_eq!(
            r.set_custom(1_000_000, 1_000_000),
            Err(TimeRangeError::EndBeforeStart)
        );
    }

    #[test]
    fn validation_end_before_start_rejected() {
        let mut r = TimeRange::default();
        assert_eq!(
            r.set_custom(2_000_000, 1_000_000),
            Err(TimeRangeError::EndBeforeStart)
        );
    }

    #[test]
    fn resolve_filter_window_returns_millis_for_one_hour_preset() {
        let r = TimeRange::default();
        let (start, end) = r.resolve_filter_log_events_window();
        assert_eq!(end - start, 3_600_000);
        // end is within 2 seconds of "now" in millis
        let now_ms = Utc::now().timestamp_millis();
        assert!((now_ms - end).abs() < 2_000);
    }

    #[test]
    fn resolve_insights_window_returns_secs_for_one_hour_preset() {
        let r = TimeRange::default();
        let (start, end) = r.resolve_insights_window();
        assert_eq!(end - start, 3_600);
    }

    #[test]
    fn resolve_returns_24h_for_24h_preset() {
        let r = TimeRange::Preset(TimeRangePreset::TwentyFourHours);
        let (start, end) = r.resolve_insights_window();
        assert_eq!(end - start, 24 * 3_600);
    }

    #[test]
    fn custom_resolvers_consistency_secs_times_thousand_equals_millis() {
        let mut r = TimeRange::default();
        let start = 1_700_000_000_i64;
        let end = start + 12 * 3_600;
        r.set_custom(start, end).unwrap();

        let (start_secs, end_secs) = r.resolve_insights_window();
        let (start_ms, end_ms) = r.resolve_filter_log_events_window();
        assert_eq!(start_secs * 1000, start_ms);
        assert_eq!(end_secs * 1000, end_ms);
        assert_eq!(start_secs, start);
        assert_eq!(end_secs, end);
    }

    #[test]
    fn footer_label_preset() {
        assert_eq!(TimeRange::default().footer_label(), "1h");
        assert_eq!(
            TimeRange::Preset(TimeRangePreset::TwentyFourHours).footer_label(),
            "24h"
        );
    }

    #[test]
    fn footer_label_custom_includes_utc_marker() {
        let start = Utc.with_ymd_and_hms(2026, 5, 1, 14, 0, 0).unwrap().timestamp();
        let r = TimeRange::Custom {
            start_secs: start,
            end_secs: start + 86_400, // +1 day
        };
        let label = r.footer_label();
        assert!(label.contains("custom"));
        assert!(label.contains("UTC"));
        assert!(label.contains("→"));
        // Must include both formatted timestamps.
        assert!(label.contains("2026-05-01 14:00"));
        assert!(label.contains("2026-05-02 14:00"));
    }
}
