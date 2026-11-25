//! V8's `Array.prototype.sort` (its TimSort, `array-sort.tq`), step for
//! step: the port `fc-approval` uses for its grant files, kept here as is.
//! A comparator that answers `NaN` (a missing or non-numeric `createdAt`)
//! isn't consistent, and where such entries end up depends on the order in
//! which V8 compares; any other stable sort puts them elsewhere.

/// V8's `Array.prototype.sort(compare)` of `items`, in place: its TimSort,
/// as `third_party/v8/builtins/array-sort.tq` runs it, with each
/// comparison's `NaN` read as 0. `compare(a, b)` is the comparator's
/// number for `(a, b)`.
pub fn sort<T: Copy>(items: &mut [T], compare: impl FnMut(T, T) -> f64) {
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
    fn a_consistent_sort_is_stable() {
        let mut items: Vec<(u32, usize)> =
            (0..500).map(|i| ((i * 7919) % 13, i as usize)).collect();
        let mut expected = items.clone();
        expected.sort_by_key(|(key, _)| *key);
        sort(&mut items, |a, b| f64::from(a.0) - f64::from(b.0));
        assert_eq!(items, expected);
    }

    #[test]
    fn nan_comparisons_land_where_v8_puts_them() {
        // Node 22: `[0, 1, 2, 3].sort((a, b) => keys[a] - keys[b])`.
        let keys = [3.0, f64::NAN, 1.0, 2.0];
        let mut items: Vec<usize> = (0..keys.len()).collect();
        sort(&mut items, |a, b| keys[a] - keys[b]);
        assert_eq!(items, [0, 1, 2, 3]);
        let keys = [5.0, 1.0, f64::NAN, 4.0, 2.0, 3.0];
        let mut items: Vec<usize> = (0..keys.len()).collect();
        sort(&mut items, |a, b| keys[a] - keys[b]);
        assert_eq!(items, [1, 4, 5, 3, 0, 2]);
    }
}
