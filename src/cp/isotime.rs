//! Minimal RFC3339-UTC arithmetic (no `chrono`/`time` dep, musl-friendly).
//! Only what the sync join needs: parse `YYYY-MM-DDTHH:MM:SS[.fff]Z` to epoch
//! millis and format back. Uses Howard Hinnant's civil-date algorithms.

/// Days since 1970-01-01 for a proleptic-Gregorian (y, m, d). Valid for y > 0.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Inverse of [`days_from_civil`]: days-since-epoch → (y, m, d).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Parse an ISO-8601 timestamp to epoch milliseconds. Handles both `Z`-suffixed
/// UTC timestamps and `±HH:MM` offset-bearing timestamps. Returns `None` on a
/// shape we don't recognise.
pub fn parse_epoch_millis(ts: &str) -> Option<i64> {
    let (date, time_part) = ts.split_once('T')?;

    // Strip and parse the timezone suffix: Z, +HH:MM, or -HH:MM
    let (time, offset_secs) = parse_time_and_offset(time_part)?;

    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;
    let (hms, frac) = match time.split_once('.') {
        Some((a, b)) => (a, b),
        None => (time, ""),
    };
    let mut tp = hms.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let s: i64 = tp.next().unwrap_or("0").parse().ok()?;
    // Milliseconds from up-to-3 fractional digits.
    let mut millis = 0i64;
    if !frac.is_empty() {
        let mut digits = frac.bytes().filter(|b| b.is_ascii_digit());
        let d0 = digits.next().map(|b| (b - b'0') as i64).unwrap_or(0);
        let d1 = digits.next().map(|b| (b - b'0') as i64).unwrap_or(0);
        let d2 = digits.next().map(|b| (b - b'0') as i64).unwrap_or(0);
        millis = d0 * 100 + d1 * 10 + d2;
    }
    let days = days_from_civil(y, mo, d);
    // Subtract offset to convert local wall-clock to UTC
    Some((days * 86400 + h * 3600 + mi * 60 + s - offset_secs) * 1000 + millis)
}

/// Parse the time portion after 'T', returning (time_without_offset, offset_seconds).
/// `Z` → offset 0, `+05:30` → +19800, `-04:00` → -14400.
fn parse_time_and_offset(time_part: &str) -> Option<(&str, i64)> {
    if let Some(t) = time_part.strip_suffix('Z') {
        return Some((t, 0));
    }
    // Look for +HH:MM or -HH:MM at the end (always 6 chars: ±HH:MM)
    if time_part.len() >= 6 {
        let (rest, offset_str) = time_part.split_at(time_part.len() - 6);
        let sign_byte = offset_str.as_bytes()[0];
        if sign_byte == b'+' || sign_byte == b'-' {
            let mut parts = offset_str[1..].split(':');
            let oh: i64 = parts.next()?.parse().ok()?;
            let om: i64 = parts.next()?.parse().ok()?;
            let sign: i64 = if sign_byte == b'+' { 1 } else { -1 };
            return Some((rest, sign * (oh * 3600 + om * 60)));
        }
    }
    // No recognised offset — treat as UTC (backward compat with bare timestamps)
    Some((time_part, 0))
}

/// Format epoch milliseconds back to `YYYY-MM-DDTHH:MM:SS.fffZ`.
pub fn format_epoch_millis(epoch_millis: i64) -> String {
    let total_secs = epoch_millis.div_euclid(1000);
    let millis = epoch_millis.rem_euclid(1000);
    let days = total_secs.div_euclid(86400);
    let sod = total_secs.rem_euclid(86400);
    let (y, mo, d) = civil_from_days(days);
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// `start + secs`, returned as an ISO-8601 UTC string. If `start` can't be
/// parsed, returns it unchanged.
pub fn add_seconds(start: &str, secs: f64) -> String {
    match parse_epoch_millis(start) {
        Some(ms) => format_epoch_millis(ms + (secs * 1000.0) as i64),
        None => start.to_string(),
    }
}

/// Normalize any ISO-8601 timestamp to canonical UTC `YYYY-MM-DDTHH:MM:SS.fffZ`.
/// If the input is already `Z`-suffixed, it is re-formatted for consistency.
/// If the input has a `±HH:MM` offset, it is converted to UTC.
/// Unparseable inputs are returned unchanged.
pub fn normalize_to_utc(ts: &str) -> String {
    match parse_epoch_millis(ts) {
        Some(ms) => format_epoch_millis(ms),
        None => ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let ts = "2026-06-09T20:00:00.000Z";
        let ms = parse_epoch_millis(ts).unwrap();
        assert_eq!(format_epoch_millis(ms), ts);
    }

    #[test]
    fn known_epoch() {
        assert_eq!(parse_epoch_millis("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_epoch_millis("2000-01-01T00:00:00Z"),
            Some(946_684_800_000)
        );
    }

    #[test]
    fn add_crosses_minute_and_day() {
        assert_eq!(
            add_seconds("2026-06-09T20:00:00.000Z", 251.4),
            "2026-06-09T20:04:11.400Z"
        );
        assert_eq!(
            add_seconds("2026-06-09T23:59:59.000Z", 2.0),
            "2026-06-10T00:00:01.000Z"
        );
    }

    #[test]
    fn normalize_utc_passthrough() {
        // Z-suffixed timestamps must pass through unchanged
        assert_eq!(
            normalize_to_utc("2026-07-26T23:51:39.450Z"),
            "2026-07-26T23:51:39.450Z"
        );
        assert_eq!(
            normalize_to_utc("2026-07-26T00:00:00Z"),
            "2026-07-26T00:00:00.000Z"
        );
    }

    #[test]
    fn normalize_edt_offset() {
        // -04:00 (EDT): 19:00 local = 23:00 UTC
        assert_eq!(
            normalize_to_utc("2026-07-26T19:00:00-04:00"),
            "2026-07-26T23:00:00.000Z"
        );
        // 20:00 EDT = 00:00 next day UTC
        assert_eq!(
            normalize_to_utc("2026-07-26T20:00:00-04:00"),
            "2026-07-27T00:00:00.000Z"
        );
    }

    #[test]
    fn normalize_positive_offset() {
        // +05:30 (IST): 05:30 local = 00:00 UTC same day
        assert_eq!(
            normalize_to_utc("2026-07-26T05:30:00+05:30"),
            "2026-07-26T00:00:00.000Z"
        );
    }

    #[test]
    fn normalize_zero_offset() {
        assert_eq!(
            normalize_to_utc("2026-07-26T12:00:00+00:00"),
            "2026-07-26T12:00:00.000Z"
        );
    }

    #[test]
    fn normalize_with_fractional_seconds() {
        assert_eq!(
            normalize_to_utc("2026-07-26T19:51:39.450-04:00"),
            "2026-07-26T23:51:39.450Z"
        );
    }

    #[test]
    fn normalize_unparseable_returns_unchanged() {
        assert_eq!(normalize_to_utc("not-a-timestamp"), "not-a-timestamp");
        assert_eq!(normalize_to_utc(""), "");
    }
}
