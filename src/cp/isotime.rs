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

/// Parse an ISO-8601 UTC timestamp to epoch milliseconds. Returns `None` on a
/// shape we don't recognise.
pub fn parse_epoch_millis(ts: &str) -> Option<i64> {
    let (date, time) = ts.split_once('T')?;
    let time = time.trim_end_matches('Z');
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
    Some((days * 86400 + h * 3600 + mi * 60 + s) * 1000 + millis)
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
}
