//! JavaScript's semantics where the reference's stores compare, subtract
//! or sort the values a grant file holds (design 0012, "The files"): a
//! file the core reads may hold any JSON, and the reference coerces
//! whatever it finds.
//!
//! - [`to_number`]: ECMAScript's `ToNumber` of a JSON value, as `now -
//!   lastUsed` and `expiresAt > now` apply it: `"70000"` is 70,000,
//!   `null` is 0, a missing field `NaN`, an array its joined text's number,
//!   and an object with its own `toString` key throws.
//! - [`sort`]: V8's `Array.prototype.sort` (its TimSort, `array-sort.tq`),
//!   step for step. A comparator that answers `NaN` (a missing or
//!   non-numeric `lastUsed`) isn't consistent, and where such entries end
//!   up depends on the order in which V8 compares; any other stable sort
//!   puts them elsewhere.

use fc_json::{JsValue, ToPrimitiveError};

/// `ToNumber(value)`, through `ToPrimitive(value, number)` for an array or
/// an object (its `toString`: no JSON value has a callable `valueOf`).
pub(crate) fn to_number(value: &JsValue) -> Result<f64, ToPrimitiveError> {
    Ok(match value {
        JsValue::Undefined => f64::NAN,
        JsValue::Null => 0.0,
        JsValue::Bool(flag) => f64::from(u8::from(*flag)),
        JsValue::Number(number) => *number,
        // A lone surrogate reads as U+FFFD, which no number holds either.
        JsValue::String(text) => string_to_number(text.as_str()),
        JsValue::Array(_) | JsValue::Object(_) => string_to_number(&value.js_string()?),
    })
}

/// ECMAScript's WhiteSpace and LineTerminator, which `StringToNumber`
/// trims (U+FEFF is one, U+0085 isn't).
fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `Number(text)`: ECMAScript's `StringToNumber`. Decimals are rounded to
/// the nearest double (ties to even), as `str::parse` rounds them; `0x`,
/// `0o` and `0b` integers too, as V8 rounds them.
pub(crate) fn string_to_number(text: &str) -> f64 {
    let text = text.trim_matches(is_js_space);
    if text.is_empty() {
        return 0.0;
    }
    for (prefix, bits) in [
        ("0x", 4),
        ("0X", 4),
        ("0o", 3),
        ("0O", 3),
        ("0b", 1),
        ("0B", 1),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            return radix_integer(digits, bits);
        }
    }
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let magnitude = if body == "Infinity" {
        f64::INFINITY
    } else if decimal_literal(body) {
        body.parse::<f64>().unwrap_or(f64::NAN)
    } else {
        return f64::NAN;
    };
    if negative { -magnitude } else { magnitude }
}

/// StrUnsignedDecimalLiteral, but `Infinity`: digits with an optional point
/// (a digit on at least one side of it) and an optional exponent.
fn decimal_literal(text: &str) -> bool {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty()) || !digits(whole) || !digits(fraction) {
        return false;
    }
    match exponent {
        None => true,
        Some(e) => {
            let e = e.strip_prefix(['+', '-']).unwrap_or(e);
            !e.is_empty() && digits(e)
        }
    }
}

/// A `0x`/`0o`/`0b` integer's digits (`bits` a digit) as the nearest
/// double, ties to even; `NaN` if there are none or one isn't a digit.
fn radix_integer(digits: &str, bits: u32) -> f64 {
    let radix = 1u32 << bits;
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return f64::NAN;
    }
    // The first 60 or more significant bits, exactly; past them, how many
    // bits were left off and whether any of them was set.
    let mut mantissa: u64 = 0;
    let mut dropped: i64 = 0;
    let mut sticky = false;
    for c in digits.chars() {
        let digit = u64::from(c.to_digit(radix).unwrap_or(0));
        if mantissa < 1 << 60 {
            mantissa = (mantissa << bits) | digit;
        } else {
            dropped += i64::from(bits);
            sticky |= digit != 0;
        }
    }
    if mantissa == 0 {
        return 0.0;
    }
    // Round to 53 bits.
    let length = 64 - i64::from(mantissa.leading_zeros());
    let mut shift = (length - 53).max(0);
    let mut kept = mantissa >> shift;
    if shift > 0 {
        let rest = mantissa & ((1u64 << shift) - 1);
        let half = 1u64 << (shift - 1);
        if rest > half || (rest == half && (sticky || kept & 1 == 1)) {
            kept += 1;
            if kept == 1 << 53 {
                kept >>= 1;
                shift += 1;
            }
        }
    }
    let exponent = shift + dropped;
    if exponent > 1023 {
        return f64::INFINITY;
    }
    // `kept` < 2^53 is exact, and so is a power of two up to 2^1023.
    let scale = f64::from_bits(((exponent + 1023) as u64) << 52);
    kept as f64 * scale
}

/// V8's `Array.prototype.sort(compare)` of `items`, in place: its TimSort,
/// as `third_party/v8/builtins/array-sort.tq` runs it, with each
/// comparison's `NaN` read as 0. `compare(a, b)` is the comparator's
/// number for `(a, b)`.
pub(crate) fn sort<T: Copy>(items: &mut [T], compare: impl FnMut(T, T) -> f64) {
    let mut state = Sort {
        compare,
        min_gallop: MIN_GALLOP,
        runs: Vec::new(),
    };
    state.run(items);
}

/// V8's `kMinGallopWins`, and each sort's first `minGallop`.
const MIN_GALLOP: usize = 7;

struct Sort<F> {
    compare: F,
    min_gallop: usize,
    /// Pending runs: base and length.
    runs: Vec<(usize, usize)>,
}

impl<F> Sort<F> {
    /// `Compare(x, y) < 0` (a `NaN` is 0, and so not below it).
    fn lt<T: Copy>(&mut self, x: T, y: T) -> bool
    where
        F: FnMut(T, T) -> f64,
    {
        (self.compare)(x, y) < 0.0
    }

    /// `ArrayTimSortImpl`.
    fn run<T: Copy>(&mut self, work: &mut [T])
    where
        F: FnMut(T, T) -> f64,
    {
        let length = work.len();
        if length < 2 {
            return;
        }
        let mut remaining = length;
        let mut low = 0;
        let min_run = min_run_length(length);
        while remaining != 0 {
            let mut current = self.count_and_make_run(work, low, low + remaining);
            if current < min_run {
                let forced = min_run.min(remaining);
                self.binary_insertion_sort(work, low, low + current, low + forced);
                current = forced;
            }
            self.runs.push((low, current));
            self.merge_collapse(work);
            low += current;
            remaining -= current;
        }
        self.merge_force_collapse(work);
    }

    /// `CountAndMakeRun`: the run at `low_arg`, reversed in place if it
    /// descends strictly.
    fn count_and_make_run<T: Copy>(&mut self, work: &mut [T], low_arg: usize, high: usize) -> usize
    where
        F: FnMut(T, T) -> f64,
    {
        let low = low_arg + 1;
        if low == high {
            return 1;
        }
        let mut run = 2;
        let descending = self.lt(work[low], work[low - 1]);
        let mut previous = work[low];
        for &current in &work[low + 1..high] {
            let below = self.lt(current, previous);
            if descending != below {
                break;
            }
            previous = current;
            run += 1;
        }
        if descending {
            work[low_arg..low_arg + run].reverse();
        }
        run
    }

    /// `BinaryInsertionSort`: `[low, high)` sorted, `[low, start)` already.
    fn binary_insertion_sort<T: Copy>(
        &mut self,
        work: &mut [T],
        low: usize,
        start: usize,
        high: usize,
    ) where
        F: FnMut(T, T) -> f64,
    {
        let mut start = if low == start { start + 1 } else { start };
        while start < high {
            let (mut left, mut right) = (low, start);
            let pivot = work[start];
            while left < right {
                let mid = left + ((right - left) >> 1);
                if self.lt(pivot, work[mid]) {
                    right = mid;
                } else {
                    left = mid + 1;
                }
            }
            work.copy_within(left..start, left + 1);
            work[left] = pivot;
            start += 1;
        }
    }

    /// `RunInvariantEstablished`.
    fn invariant(&self, n: usize) -> bool {
        n < 2 || self.runs[n - 2].1 > self.runs[n - 1].1 + self.runs[n].1
    }

    /// `MergeCollapse`.
    fn merge_collapse<T: Copy>(&mut self, work: &mut [T])
    where
        F: FnMut(T, T) -> f64,
    {
        while self.runs.len() > 1 {
            let mut n = self.runs.len() - 2;
            if !self.invariant(n + 1) || !self.invariant(n) {
                if self.runs[n - 1].1 < self.runs[n + 1].1 {
                    n -= 1;
                }
                self.merge_at(work, n);
            } else if self.runs[n].1 <= self.runs[n + 1].1 {
                self.merge_at(work, n);
            } else {
                break;
            }
        }
    }

    /// `MergeForceCollapse`.
    fn merge_force_collapse<T: Copy>(&mut self, work: &mut [T])
    where
        F: FnMut(T, T) -> f64,
    {
        while self.runs.len() > 1 {
            let mut n = self.runs.len() - 2;
            if n > 0 && self.runs[n - 1].1 < self.runs[n + 1].1 {
                n -= 1;
            }
            self.merge_at(work, n);
        }
    }

    /// `MergeAt`: runs `i` and `i + 1` merged.
    fn merge_at<T: Copy>(&mut self, work: &mut [T], i: usize)
    where
        F: FnMut(T, T) -> f64,
    {
        let size = self.runs.len();
        let (mut base_a, mut length_a) = self.runs[i];
        let (base_b, mut length_b) = self.runs[i + 1];
        self.runs[i].1 = length_a + length_b;
        if i + 3 == size {
            self.runs[i + 1] = self.runs[i + 2];
        }
        self.runs.truncate(size - 1);

        let k = self.gallop_right(work, work[base_b], base_a, length_a, 0);
        base_a += k;
        length_a -= k;
        if length_a == 0 {
            return;
        }
        length_b = self.gallop_left(
            work,
            work[base_a + length_a - 1],
            base_b,
            length_b,
            length_b - 1,
        );
        if length_b == 0 {
            return;
        }
        if length_a <= length_b {
            self.merge_low(work, base_a, length_a, base_b, length_b);
        } else {
            self.merge_high(work, base_a, length_a, base_b, length_b);
        }
    }

    /// `GallopLeft`: where `key` goes in `array[base..base + length]`, the
    /// leftmost place, searching from `hint`.
    fn gallop_left<T: Copy>(
        &mut self,
        array: &[T],
        key: T,
        base: usize,
        length: usize,
        hint: usize,
    ) -> usize
    where
        F: FnMut(T, T) -> f64,
    {
        let (base, length, hint) = (base as isize, length as isize, hint as isize);
        let at = |offset: isize| array[(base + offset) as usize];
        let mut last = 0isize;
        let mut offset = 1isize;
        if self.lt(at(hint), key) {
            let max = length - hint;
            while offset < max {
                if !self.lt(at(hint + offset), key) {
                    break;
                }
                last = offset;
                offset = (offset << 1) + 1;
            }
            offset = offset.min(max);
            last += hint;
            offset += hint;
        } else {
            let max = hint + 1;
            while offset < max {
                if self.lt(at(hint - offset), key) {
                    break;
                }
                last = offset;
                offset = (offset << 1) + 1;
            }
            offset = offset.min(max);
            let previous = last;
            last = hint - offset;
            offset = hint - previous;
        }
        last += 1;
        while last < offset {
            let m = last + ((offset - last) >> 1);
            if self.lt(at(m), key) {
                last = m + 1;
            } else {
                offset = m;
            }
        }
        offset as usize
    }

    /// `GallopRight`: where `key` goes in `array[base..base + length]`, the
    /// rightmost place, searching from `hint`.
    fn gallop_right<T: Copy>(
        &mut self,
        array: &[T],
        key: T,
        base: usize,
        length: usize,
        hint: usize,
    ) -> usize
    where
        F: FnMut(T, T) -> f64,
    {
        let (base, length, hint) = (base as isize, length as isize, hint as isize);
        let at = |offset: isize| array[(base + offset) as usize];
        let mut last = 0isize;
        let mut offset = 1isize;
        if self.lt(key, at(hint)) {
            let max = hint + 1;
            while offset < max {
                if !self.lt(key, at(hint - offset)) {
                    break;
                }
                last = offset;
                offset = (offset << 1) + 1;
            }
            offset = offset.min(max);
            let previous = last;
            last = hint - offset;
            offset = hint - previous;
        } else {
            let max = length - hint;
            while offset < max {
                if self.lt(key, at(hint + offset)) {
                    break;
                }
                last = offset;
                offset = (offset << 1) + 1;
            }
            offset = offset.min(max);
            last += hint;
            offset += hint;
        }
        last += 1;
        while last < offset {
            let m = last + ((offset - last) >> 1);
            if self.lt(key, at(m)) {
                offset = m;
            } else {
                last = m + 1;
            }
        }
        offset as usize
    }

    /// `MergeLow`: run A (the shorter) copied aside, merged from the left.
    fn merge_low<T: Copy>(
        &mut self,
        work: &mut [T],
        base_a: usize,
        length_a: usize,
        base_b: usize,
        length_b: usize,
    ) where
        F: FnMut(T, T) -> f64,
    {
        let (mut length_a, mut length_b) = (length_a, length_b);
        let temp: Vec<T> = work[base_a..base_a + length_a].to_vec();
        let mut dest = base_a;
        let mut cursor_temp = 0;
        let mut cursor_b = base_b;
        work[dest] = work[cursor_b];
        dest += 1;
        cursor_b += 1;

        enum End {
            Succeed,
            CopyB,
        }
        let end = 'merge: {
            length_b -= 1;
            if length_b == 0 {
                break 'merge End::Succeed;
            }
            if length_a == 1 {
                break 'merge End::CopyB;
            }
            let mut min_gallop = self.min_gallop;
            loop {
                let mut wins_a = 0;
                let mut wins_b = 0;
                loop {
                    if self.lt(work[cursor_b], temp[cursor_temp]) {
                        work[dest] = work[cursor_b];
                        dest += 1;
                        cursor_b += 1;
                        wins_b += 1;
                        length_b -= 1;
                        wins_a = 0;
                        if length_b == 0 {
                            break 'merge End::Succeed;
                        }
                        if wins_b >= min_gallop {
                            break;
                        }
                    } else {
                        work[dest] = temp[cursor_temp];
                        dest += 1;
                        cursor_temp += 1;
                        wins_a += 1;
                        length_a -= 1;
                        wins_b = 0;
                        if length_a == 1 {
                            break 'merge End::CopyB;
                        }
                        if wins_a >= min_gallop {
                            break;
                        }
                    }
                }
                min_gallop += 1;
                let mut first = true;
                while wins_a >= MIN_GALLOP || wins_b >= MIN_GALLOP || first {
                    first = false;
                    min_gallop = min_gallop.saturating_sub(1).max(1);
                    self.min_gallop = min_gallop;
                    wins_a = self.gallop_right(&temp, work[cursor_b], cursor_temp, length_a, 0);
                    if wins_a > 0 {
                        work[dest..dest + wins_a]
                            .copy_from_slice(&temp[cursor_temp..cursor_temp + wins_a]);
                        dest += wins_a;
                        cursor_temp += wins_a;
                        length_a -= wins_a;
                        if length_a == 1 {
                            break 'merge End::CopyB;
                        }
                        // Impossible for a consistent comparator, which
                        // this needn't be.
                        if length_a == 0 {
                            break 'merge End::Succeed;
                        }
                    }
                    work[dest] = work[cursor_b];
                    dest += 1;
                    cursor_b += 1;
                    length_b -= 1;
                    if length_b == 0 {
                        break 'merge End::Succeed;
                    }
                    wins_b = self.gallop_left(work, temp[cursor_temp], cursor_b, length_b, 0);
                    if wins_b > 0 {
                        work.copy_within(cursor_b..cursor_b + wins_b, dest);
                        dest += wins_b;
                        cursor_b += wins_b;
                        length_b -= wins_b;
                        if length_b == 0 {
                            break 'merge End::Succeed;
                        }
                    }
                    work[dest] = temp[cursor_temp];
                    dest += 1;
                    cursor_temp += 1;
                    length_a -= 1;
                    if length_a == 1 {
                        break 'merge End::CopyB;
                    }
                }
                min_gallop += 1;
                self.min_gallop = min_gallop;
            }
        };
        match end {
            End::Succeed => {
                if length_a > 0 {
                    work[dest..dest + length_a]
                        .copy_from_slice(&temp[cursor_temp..cursor_temp + length_a]);
                }
            }
            End::CopyB => {
                // The last of run A goes after the rest of run B.
                work.copy_within(cursor_b..cursor_b + length_b, dest);
                work[dest + length_b] = temp[cursor_temp];
            }
        }
    }

    /// `MergeHigh`: run B (the shorter) copied aside, merged from the right.
    fn merge_high<T: Copy>(
        &mut self,
        work: &mut [T],
        base_a: usize,
        length_a: usize,
        base_b: usize,
        length_b: usize,
    ) where
        F: FnMut(T, T) -> f64,
    {
        let (mut length_a, mut length_b) = (length_a, length_b);
        let temp: Vec<T> = work[base_b..base_b + length_b].to_vec();
        // Cursors run down to one before their run's start.
        let base_a = base_a as isize;
        let mut dest = (base_b + length_b) as isize - 1;
        let mut cursor_temp = length_b as isize - 1;
        let mut cursor_a = base_a + length_a as isize - 1;
        let u = |index: isize| index as usize;
        work[u(dest)] = work[u(cursor_a)];
        dest -= 1;
        cursor_a -= 1;

        enum End {
            Succeed,
            CopyA,
        }
        let end = 'merge: {
            length_a -= 1;
            if length_a == 0 {
                break 'merge End::Succeed;
            }
            if length_b == 1 {
                break 'merge End::CopyA;
            }
            let mut min_gallop = self.min_gallop;
            loop {
                let mut wins_a = 0;
                let mut wins_b = 0;
                loop {
                    if self.lt(temp[u(cursor_temp)], work[u(cursor_a)]) {
                        work[u(dest)] = work[u(cursor_a)];
                        dest -= 1;
                        cursor_a -= 1;
                        wins_a += 1;
                        length_a -= 1;
                        wins_b = 0;
                        if length_a == 0 {
                            break 'merge End::Succeed;
                        }
                        if wins_a >= min_gallop {
                            break;
                        }
                    } else {
                        work[u(dest)] = temp[u(cursor_temp)];
                        dest -= 1;
                        cursor_temp -= 1;
                        wins_b += 1;
                        length_b -= 1;
                        wins_a = 0;
                        if length_b == 1 {
                            break 'merge End::CopyA;
                        }
                        if wins_b >= min_gallop {
                            break;
                        }
                    }
                }
                min_gallop += 1;
                let mut first = true;
                while wins_a >= MIN_GALLOP || wins_b >= MIN_GALLOP || first {
                    first = false;
                    min_gallop = min_gallop.saturating_sub(1).max(1);
                    self.min_gallop = min_gallop;
                    let k = self.gallop_right(
                        work,
                        temp[u(cursor_temp)],
                        u(base_a),
                        length_a,
                        length_a - 1,
                    );
                    wins_a = length_a - k;
                    if wins_a > 0 {
                        dest -= wins_a as isize;
                        cursor_a -= wins_a as isize;
                        work.copy_within(u(cursor_a + 1)..u(cursor_a + 1) + wins_a, u(dest + 1));
                        length_a -= wins_a;
                        if length_a == 0 {
                            break 'merge End::Succeed;
                        }
                    }
                    work[u(dest)] = temp[u(cursor_temp)];
                    dest -= 1;
                    cursor_temp -= 1;
                    length_b -= 1;
                    if length_b == 1 {
                        break 'merge End::CopyA;
                    }
                    let k = self.gallop_left(&temp, work[u(cursor_a)], 0, length_b, length_b - 1);
                    wins_b = length_b - k;
                    if wins_b > 0 {
                        dest -= wins_b as isize;
                        cursor_temp -= wins_b as isize;
                        let from = u(cursor_temp + 1);
                        work[u(dest + 1)..u(dest + 1) + wins_b]
                            .copy_from_slice(&temp[from..from + wins_b]);
                        length_b -= wins_b;
                        if length_b == 1 {
                            break 'merge End::CopyA;
                        }
                        // Impossible for a consistent comparator, which
                        // this needn't be.
                        if length_b == 0 {
                            break 'merge End::Succeed;
                        }
                    }
                    work[u(dest)] = work[u(cursor_a)];
                    dest -= 1;
                    cursor_a -= 1;
                    length_a -= 1;
                    if length_a == 0 {
                        break 'merge End::Succeed;
                    }
                }
                min_gallop += 1;
                self.min_gallop = min_gallop;
            }
        };
        match end {
            End::Succeed => {
                if length_b > 0 {
                    let to = u(dest - (length_b as isize - 1));
                    work[to..to + length_b].copy_from_slice(&temp[..length_b]);
                }
            }
            End::CopyA => {
                // The first of run B goes before the rest of run A.
                dest -= length_a as isize;
                cursor_a -= length_a as isize;
                work.copy_within(u(cursor_a + 1)..u(cursor_a + 1) + length_a, u(dest + 1));
                work[u(dest)] = temp[u(cursor_temp)];
            }
        }
    }
}

/// `ComputeMinRunLength`.
fn min_run_length(mut n: usize) -> usize {
    let mut r = 0;
    while n >= 64 {
        r |= n & 1;
        n >>= 1;
    }
    n + r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_of_strings() {
        let cases: &[(&str, f64)] = &[
            ("", 0.0),
            (" \t\n\u{feff}\u{3000}", 0.0),
            ("70000", 70000.0),
            (" 42 ", 42.0),
            ("+5", 5.0),
            ("-5", -5.0),
            ("5.", 5.0),
            (".5", 0.5),
            ("1e3", 1000.0),
            ("1E+3", 1000.0),
            ("1e400", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
            ("0x10", 16.0),
            ("0o17", 15.0),
            ("0b101", 5.0),
            ("0x", f64::NAN),
            ("-0x10", f64::NAN),
            ("1_000", f64::NAN),
            ("inf", f64::NAN),
            ("NaN", f64::NAN),
            (".", f64::NAN),
            ("e5", f64::NAN),
            ("5e", f64::NAN),
            ("\u{85}5", f64::NAN),
            ("abc", f64::NAN),
            // 2^53 + 1: a tie, to even; 2^53 + 3 up, to even.
            ("0x20000000000001", 9007199254740992.0),
            ("0x20000000000003", 9007199254740996.0),
            // Just past the tie: up.
            (
                "0x200000000000010000000001",
                9007199254740994.0 * 1099511627776.0,
            ),
            // Exactly the tie, with zeros after it: to even.
            (
                "0x200000000000010000000000",
                9007199254740992.0 * 1099511627776.0,
            ),
            ("0x1fffffffffffff8", 144115188075855872.0),
        ];
        for (text, expected) in cases {
            let n = string_to_number(text);
            assert!(
                n == *expected || (n.is_nan() && expected.is_nan()),
                "{text:?}: {n}"
            );
        }
        assert!(string_to_number("-0").is_sign_negative());
        assert_eq!(
            string_to_number(&format!("0x{}", "f".repeat(300))),
            f64::INFINITY
        );
    }

    #[test]
    fn numbers_of_values() {
        let value = |text: &str| fc_json::parse(text).unwrap();
        assert_eq!(to_number(&value("null")), Ok(0.0));
        assert_eq!(to_number(&value("true")), Ok(1.0));
        assert_eq!(to_number(&value("[]")), Ok(0.0));
        assert_eq!(to_number(&value("[\"7\"]")), Ok(7.0));
        assert!(to_number(&value("[1,2]")).unwrap().is_nan());
        assert!(to_number(&value("{}")).unwrap().is_nan());
        assert!(to_number(&value("{\"valueOf\":1}")).unwrap().is_nan());
        assert!(to_number(&value("{\"toString\":1}")).is_err());
        assert!(to_number(&value("[{\"toString\":1}]")).is_err());
        assert!(to_number(&JsValue::Undefined).unwrap().is_nan());
    }

    #[test]
    fn a_consistent_sort_is_stable() {
        let mut items: Vec<(u32, usize)> =
            (0..500).map(|i| ((i * 7919) % 13, i as usize)).collect();
        let mut expected = items.clone();
        expected.sort_by_key(|(key, _)| *key);
        sort(&mut items, |a, b| f64::from(a.0) - f64::from(b.0));
        assert_eq!(items, expected);
    }
}
