//! Minimal calendar date (`YYYY-MM-DD`) used for key expiry.

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    year: i32,
    month: u32,
    day: u32,
}

impl Date {
    pub fn new(year: i32, month: u32, day: u32) -> Result<Self> {
        if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
            bail!("invalid date {year:04}-{month:02}-{day:02}");
        }
        Ok(Self { year, month, day })
    }

    /// Today's date in UTC. `GK_TODAY=YYYY-MM-DD` overrides it, which keeps
    /// expiry checks reproducible in tests and CI.
    pub fn today() -> Self {
        if let Some(date) = std::env::var("GK_TODAY").ok().and_then(|s| s.parse().ok()) {
            return date;
        }
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::from_days((secs / 86_400) as i64)
    }

    /// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
    pub fn to_days(self) -> i64 {
        let y = i64::from(self.year) - i64::from(self.month <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = self.month as i64;
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + self.day as i64 - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    pub fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
        let year = (yoe + era * 400 + i64::from(month <= 2)) as i32;
        Self { year, month, day }
    }

    /// Signed number of days from `self` until `other`.
    pub fn days_until(self, other: Date) -> i64 {
        other.to_days() - self.to_days()
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

impl FromStr for Date {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.trim().split('-').collect();
        let [y, m, d] = parts.as_slice() else {
            bail!("expected YYYY-MM-DD, got {s:?}");
        };
        if y.len() != 4 || m.len() != 2 || d.len() != 2 {
            bail!("expected YYYY-MM-DD, got {s:?}");
        }
        let parse = |p: &str| -> Result<u32> {
            p.parse()
                .map_err(|_| anyhow::anyhow!("expected YYYY-MM-DD, got {s:?}"))
        };
        Date::new(parse(y)? as i32, parse(m)?, parse(d)?)
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_displays() {
        let d: Date = "2026-02-28".parse().unwrap();
        assert_eq!(d.to_string(), "2026-02-28");
    }

    #[test]
    fn rejects_invalid_dates() {
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "2026-00-10",
            "26-01-01",
            "2026/01/01",
            "x",
        ] {
            assert!(bad.parse::<Date>().is_err(), "{bad} should not parse");
        }
        assert!("2024-02-29".parse::<Date>().is_ok());
    }

    #[test]
    fn day_arithmetic_round_trips() {
        assert_eq!(Date::new(1970, 1, 1).unwrap().to_days(), 0);
        for days in [-1000, 0, 59, 365, 11_016, 20_000, 100_000] {
            assert_eq!(Date::from_days(days).to_days(), days);
        }
        let a: Date = "2026-12-30".parse().unwrap();
        let b: Date = "2027-01-02".parse().unwrap();
        assert_eq!(a.days_until(b), 3);
        assert_eq!(b.days_until(a), -3);
        assert!(a < b);
    }
}
