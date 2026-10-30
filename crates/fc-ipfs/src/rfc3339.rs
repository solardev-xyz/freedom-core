//! An IPNS record's EOL validity: RFC 3339 with an optional fraction, as Go's
//! `time.RFC3339Nano` writes it and freedom-ipfs reads it (`time`'s
//! `Rfc3339`). The core's clock comes in as a parameter.

fn digits(b: &[u8], at: usize, n: usize) -> Option<u32> {
    let s = b.get(at..at + n)?;
    s.iter().try_fold(0u32, |acc, &c| {
        c.is_ascii_digit().then(|| acc * 10 + u32::from(c - b'0'))
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

/// The instant `text` names: Unix seconds and nanoseconds. `None` unless it
/// is `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` with a valid date and time
/// (leap seconds aren't read).
pub fn parse(text: &str) -> Option<(i64, u32)> {
    let b = text.as_bytes();
    let year = digits(b, 0, 4)?;
    let month = digits(b, 5, 2)?;
    let day = digits(b, 8, 2)?;
    let hour = digits(b, 11, 2)?;
    let minute = digits(b, 14, 2)?;
    let second = digits(b, 17, 2)?;
    if b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || !matches!(b.get(10), Some(b'T' | b't'))
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return None;
    }
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(i64::from(year), month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut at = 19;
    let mut nanos = 0u32;
    if b.get(at) == Some(&b'.') {
        at += 1;
        let start = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        let frac = &b[start..at];
        if frac.is_empty() || frac.len() > 9 {
            return None;
        }
        nanos = frac
            .iter()
            .fold(0u32, |acc, &c| acc * 10 + u32::from(c - b'0'))
            * 10u32.pow(9 - frac.len() as u32);
    }
    let offset: i64 = match b.get(at) {
        Some(b'Z' | b'z') if b.len() == at + 1 => 0,
        Some(&sign @ (b'+' | b'-')) if b.len() == at + 6 && b[at + 3] == b':' => {
            let h = digits(b, at + 1, 2)?;
            let m = digits(b, at + 4, 2)?;
            if h > 23 || m > 59 {
                return None;
            }
            let o = i64::from(h * 3600 + m * 60);
            if sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    let days = days_from_civil(i64::from(year), month, day);
    let secs = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second) - offset;
    Some((secs, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants() {
        assert_eq!(parse("1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(
            parse("2099-01-01T00:00:00.000000000Z"),
            Some((4_070_908_800, 0))
        );
        assert_eq!(
            parse("2000-01-01T00:00:00.5Z"),
            Some((946_684_800, 500_000_000))
        );
        assert_eq!(parse("2000-01-01T01:00:00+01:00"), Some((946_684_800, 0)));
        assert_eq!(
            parse("2024-02-29T00:00:00Z").map(|x| x.0),
            Some(1_709_164_800)
        );
        for bad in [
            "2023-02-29T00:00:00Z",
            "2000-01-01T00:00:00",
            "2000-01-01 00:00:00Z",
            "2000-13-01T00:00:00Z",
            "2000-01-01T00:00:60Z",
            "2000-01-01T00:00:00.Z",
            "2000-01-01T00:00:00.1234567891Z",
            "2000-01-01T00:00:00Zx",
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }
}
