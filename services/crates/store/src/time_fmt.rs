use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

/// RFC 3339 in UTC with millisecond precision, e.g. `2026-09-30T09:15:02.123Z`. Fixed width, so
/// it sorts lexicographically.
pub fn ts_millis(t: OffsetDateTime) -> String {
    let f =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");
    t.to_offset(UtcOffset::UTC).format(&f).unwrap_or_default()
}

pub fn day(t: OffsetDateTime) -> String {
    let f = format_description!("[year]-[month]-[day]");
    t.to_offset(UtcOffset::UTC).format(&f).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn formats_fixed_width_utc() {
        let t = datetime!(2026-09-30 19:15:02.1234 +10:00);
        assert_eq!(ts_millis(t), "2026-09-30T09:15:02.123Z");
        assert_eq!(day(t), "2026-09-30");
    }
}
