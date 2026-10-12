//! A JSON text indexed in place: each value is a span of the text, so a
//! large document (an RPC answer) is kept once, as text, and read without
//! building values.
//!
//! - **Grammar and depth** are [`crate::parse`]'s: V8's `JSON.parse`, with
//!   nesting deeper than [`MAX_DEPTH`] refused.
//! - **Semantics** are JavaScript's when a value is read: a duplicate key's
//!   last value wins, at its first position; `__proto__` is an ordinary key;
//!   numbers are doubles; strings are UTF-16, lone surrogates included.
//! - **Writing** ([`Value::write`]) gives exactly what `JSON.stringify` gives
//!   for the value `JSON.parse` returns, with keys in JavaScript's property
//!   order or sorted by UTF-16 code units (the order the chain-data router's
//!   `stableValue` uses).
//!
//! # Memory
//!
//! An index holds one 8-byte node per value and per key. Every node but the
//! first starts with a byte of its own and is followed by a byte that is no
//! node's first byte (a separator, a bracket or whitespace), so a text of
//! `n` bytes has at most `(n + 1) / 2` nodes, allocated exactly: the index's
//! heap is at most [`HEAP_PER_TEXT_BYTE`] `× (n + 1)` bytes
//! ([`Index::heap_bytes`]). Building it also uses a stack of at most
//! [`MAX_DEPTH`] 4-byte entries.
//!
//! [`Value::write`] needs, while it runs, the members of the objects it is
//! inside: at most [`WRITE_SCRATCH_PER_TEXT_BYTE`] `× (n + 1)` bytes for
//! sorted keys and twice that for property order (each member is at least
//! four bytes of text, and the scratch grows by doubling), plus
//! [`WRITE_SCRATCH_FLOOR`] once (the smallest allocation a growing vector
//! makes), plus a stack of at most [`MAX_DEPTH`] frames. Every walk is
//! iterative.

use std::cmp::Ordering;

use crate::{MAX_DEPTH, number_to_string};

/// Why a text isn't indexed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    #[error("invalid JSON at byte {0}")]
    Syntax(usize),
    #[error("JSON nested deeper than {MAX_DEPTH} levels")]
    TooDeep,
    #[error("a JSON text of {0} bytes is too long to index")]
    TooLong(usize),
}

/// The longest text an index addresses: offsets are 32-bit.
pub const MAX_TEXT: usize = u32::MAX as usize - 1;

/// An index's heap is at most this many bytes per byte of text, plus this
/// many once ([`Index::heap_bytes`]).
pub const HEAP_PER_TEXT_BYTE: usize = 4;

/// [`Value::write`]'s scratch, with sorted keys, is at most this many bytes
/// per byte of text, plus this many once; property order needs twice as
/// much. Both add [`WRITE_SCRATCH_FLOOR`] once.
pub const WRITE_SCRATCH_PER_TEXT_BYTE: usize = 2;

/// The smallest scratch a write that sees an object allocates: a growing
/// vector's first allocation holds four members, of at most 8 bytes each.
/// A tiny text such as `{"":0}` needs it whole.
pub const WRITE_SCRATCH_FLOOR: usize = 32;

#[derive(Debug, Clone, Copy)]
struct Node {
    /// The value's first byte.
    start: u32,
    /// The node after this value's subtree: nodes are in document order.
    next: u32,
}

/// A validated JSON text and the spans of its values.
#[derive(Debug, Clone)]
pub struct Index<'t> {
    text: &'t str,
    nodes: Vec<Node>,
}

/// One value of an indexed text: an object's keys are values too.
#[derive(Debug, Clone, Copy)]
pub struct Value<'i, 't> {
    index: &'i Index<'t>,
    id: usize,
}

/// A value's type, from its first byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Null,
    False,
    True,
    Number,
    String,
    Array,
    Object,
}

/// The order [`Value::write`] puts an object's keys in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrder {
    /// JavaScript's property order, as `JSON.stringify` writes: array-index
    /// keys ascending, then the others where they first appeared.
    Property,
    /// Sorted by UTF-16 code units, as `Object.keys(o).sort()` gives.
    Sorted,
}

/// Where [`Value::write`] writes: a string, or a hasher.
pub trait Sink {
    fn push(&mut self, text: &str);
}

impl Sink for String {
    fn push(&mut self, text: &str) {
        self.push_str(text);
    }
}

impl<'t> Index<'t> {
    /// Validates `text` as `JSON.parse` would (refusing nesting deeper than
    /// [`MAX_DEPTH`]) and indexes it.
    pub fn new(text: &'t str) -> Result<Self, IndexError> {
        if text.len() > MAX_TEXT {
            return Err(IndexError::TooLong(text.len()));
        }
        // The first pass validates and counts, so the nodes are allocated
        // once, exactly, and nothing is allocated for a text that fails.
        let mut count = Count(0);
        scan(text, &mut count)?;
        let mut fill = Fill {
            nodes: Vec::with_capacity(count.0),
            open: Vec::new(),
        };
        scan(text, &mut fill)?;
        Ok(Self {
            text,
            nodes: fill.nodes,
        })
    }

    /// The indexed text.
    pub fn text(&self) -> &'t str {
        self.text
    }

    /// The document's value.
    pub fn root(&self) -> Value<'_, 't> {
        Value { index: self, id: 0 }
    }

    /// The bytes of heap the index holds: at most
    /// `HEAP_PER_TEXT_BYTE * (text.len() + 1)`.
    pub fn heap_bytes(&self) -> usize {
        self.nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<Node>())
    }

    fn start(&self, id: usize) -> usize {
        self.nodes
            .get(id)
            .map_or(self.text.len(), |n| n.start as usize)
    }

    fn next(&self, id: usize) -> usize {
        self.nodes
            .get(id)
            .map_or(self.nodes.len(), |n| n.next as usize)
    }

    fn byte(&self, id: usize) -> u8 {
        self.text
            .as_bytes()
            .get(self.start(id))
            .copied()
            .unwrap_or(b'n')
    }

    fn kind(&self, id: usize) -> Kind {
        match self.byte(id) {
            b'{' => Kind::Object,
            b'[' => Kind::Array,
            b'"' => Kind::String,
            b't' => Kind::True,
            b'f' => Kind::False,
            b'n' => Kind::Null,
            _ => Kind::Number,
        }
    }

    fn children(&self, id: usize) -> Children<'_, 't> {
        let container = matches!(self.kind(id), Kind::Array | Kind::Object);
        Children {
            index: self,
            next: id + 1,
            end: if container { self.next(id) } else { id + 1 },
        }
    }

    /// A string token's UTF-16 code units.
    fn units(&self, id: usize) -> Units<'t> {
        Units {
            text: self.text,
            i: self.start(id) + 1,
            low: None,
        }
    }

    fn cmp_keys(&self, a: usize, b: usize) -> Ordering {
        self.units(a).cmp(self.units(b))
    }

    /// The key as an array index (a canonical decimal below 2^32 - 1).
    fn array_index(&self, id: usize) -> Option<u32> {
        let mut value: u64 = 0;
        let mut digits = 0usize;
        for unit in self.units(id) {
            let digit = unit.checked_sub(u16::from(b'0')).filter(|d| *d < 10)?;
            if digits == 1 && value == 0 {
                return None; // a leading zero
            }
            value = value * 10 + u64::from(digit);
            digits += 1;
            if value >= u64::from(u32::MAX) {
                return None;
            }
        }
        if digits == 0 {
            return None;
        }
        u32::try_from(value).ok()
    }

    /// Appends an object's members to `arena`, each key once, in `order`.
    fn order_members(&self, object: usize, order: KeyOrder, arena: &mut Arena) {
        match arena {
            Arena::Sorted(keys) => {
                // The value of a key is the node after it.
                let base = keys.len();
                keys.extend(
                    self.children(object)
                        .step_by(2)
                        .filter_map(|key| u32::try_from(key.id).ok()),
                );
                let Some(members) = keys.get_mut(base..) else {
                    return;
                };
                members.sort_unstable_by(|a, b| {
                    self.cmp_keys(*a as usize, *b as usize).then(a.cmp(b))
                });
                // Of each run of equal keys, the last holds the value.
                let mut kept = 0;
                for i in 0..members.len() {
                    let last_of_run = members.get(i + 1).is_none_or(|next| {
                        self.cmp_keys(*next as usize, members[i] as usize) != Ordering::Equal
                    });
                    if last_of_run {
                        members[kept] = members[i];
                        kept += 1;
                    }
                }
                keys.truncate(base + kept);
            }
            Arena::Property(pairs) => {
                let base = pairs.len();
                pairs.extend(
                    self.children(object)
                        .step_by(2)
                        .filter_map(|key| u32::try_from(key.id).ok())
                        .map(|key| (key, key)),
                );
                let Some(members) = pairs.get_mut(base..) else {
                    return;
                };
                members.sort_unstable_by(|a, b| {
                    self.cmp_keys(a.0 as usize, b.0 as usize)
                        .then(a.0.cmp(&b.0))
                });
                // Each key once: its first position, its last value.
                let mut kept = 0;
                let mut i = 0;
                while i < members.len() {
                    let first = members[i].0;
                    let mut last = members[i].1;
                    i += 1;
                    while i < members.len()
                        && self.cmp_keys(members[i].0 as usize, first as usize) == Ordering::Equal
                    {
                        last = members[i].1;
                        i += 1;
                    }
                    members[kept] = (first, last);
                    kept += 1;
                }
                pairs.truncate(base + kept);
                if order == KeyOrder::Property
                    && let Some(members) = pairs.get_mut(base..)
                {
                    let rank = |key: u32| match self.array_index(key as usize) {
                        Some(n) => (0, u64::from(n)),
                        None => (1, u64::from(key)),
                    };
                    members.sort_unstable_by_key(|(first, _)| rank(*first));
                }
            }
        }
    }
}

impl<'i, 't> Value<'i, 't> {
    /// The value's type.
    pub fn kind(self) -> Kind {
        self.index.kind(self.id)
    }

    /// The offset of the value's first byte in the text.
    pub fn start(self) -> usize {
        self.index.start(self.id)
    }

    /// The offset just past the value's last byte.
    pub fn end(self) -> usize {
        let index = self.index;
        let s = index.text.as_bytes();
        // Down the last children to a scalar or an empty container, then
        // past each closing bracket on the way back up.
        let mut open = 0usize;
        let mut id = self.id;
        let mut pos = loop {
            let start = index.start(id);
            match index.kind(id) {
                Kind::Array | Kind::Object => {
                    open += 1;
                    match index.children(id).last() {
                        Some(last) => id = last.id,
                        None => break start + 1,
                    }
                }
                Kind::String => break string_end(s, start).unwrap_or(s.len()),
                Kind::Number => break number_end(s, start).unwrap_or(s.len()),
                Kind::True | Kind::Null => break start + 4,
                Kind::False => break start + 5,
            }
        };
        for _ in 0..open {
            pos = skip_ws(s, pos) + 1;
        }
        pos.min(s.len())
    }

    /// The value's own text.
    pub fn raw(self) -> &'t str {
        self.index
            .text
            .get(self.start()..self.end())
            .unwrap_or_default()
    }

    /// An array's elements, or an object's keys and values in turn, in the
    /// text's order (duplicates included). Empty for other values.
    pub fn children(self) -> impl Iterator<Item = Value<'i, 't>> {
        self.index.children(self.id)
    }

    /// An object's members in the text's order, duplicates included.
    pub fn members(self) -> impl Iterator<Item = (Value<'i, 't>, Value<'i, 't>)> {
        let mut children = self.index.children(self.id);
        std::iter::from_fn(move || Some((children.next()?, children.next()?)))
    }

    /// `object[key]` for an own key: its last value. `None` when absent or
    /// when this isn't an object.
    pub fn get(self, key: &str) -> Option<Value<'i, 't>> {
        if self.kind() != Kind::Object {
            return None;
        }
        self.members()
            .filter(|(k, _)| k.is_str(key))
            .last()
            .map(|(_, v)| v)
    }

    /// Whether this is a string whose value is `text`.
    pub fn is_str(self, text: &str) -> bool {
        if self.kind() != Kind::String {
            return false;
        }
        let token = self.raw();
        if token.contains('\\') {
            self.units().eq(text.encode_utf16())
        } else {
            token.strip_prefix('"').and_then(|t| t.strip_suffix('"')) == Some(text)
        }
    }

    /// A string's UTF-16 code units (lone surrogates included). Empty for
    /// other values.
    pub fn units(self) -> Units<'t> {
        if self.kind() == Kind::String {
            self.index.units(self.id)
        } else {
            Units {
                text: "",
                i: 0,
                low: None,
            }
        }
    }

    /// A number's value, as `JSON.parse` reads it (`1e400` is infinite).
    /// `NaN` for other values.
    pub fn number(self) -> f64 {
        if self.kind() != Kind::Number {
            return f64::NAN;
        }
        self.raw().parse().unwrap_or(f64::NAN)
    }

    /// JavaScript truthiness.
    pub fn truthy(self) -> bool {
        match self.kind() {
            Kind::Null | Kind::False => false,
            Kind::True | Kind::Array | Kind::Object => true,
            // No escape is empty, so only `""` is.
            Kind::String => self.raw() != "\"\"",
            Kind::Number => self.number() != 0.0,
        }
    }

    /// An object's own properties in JavaScript's property order, each key
    /// once: the key where it first appeared, the value it last had.
    pub fn properties(self) -> Vec<(Value<'i, 't>, Value<'i, 't>)> {
        if self.kind() != Kind::Object {
            return Vec::new();
        }
        let mut arena = Arena::Property(Vec::new());
        self.index
            .order_members(self.id, KeyOrder::Property, &mut arena);
        let Arena::Property(pairs) = arena else {
            return Vec::new();
        };
        pairs
            .into_iter()
            .map(|(key, last)| {
                (
                    Value {
                        index: self.index,
                        id: key as usize,
                    },
                    Value {
                        index: self.index,
                        id: last as usize + 1,
                    },
                )
            })
            .collect()
    }

    /// Writes `JSON.stringify(JSON.parse(raw))`, with object keys in
    /// `order`.
    pub fn write(self, order: KeyOrder, out: &mut impl Sink) {
        write_value(self, order, out);
    }

    /// [`Self::write`] into a new string.
    pub fn stringify(self, order: KeyOrder) -> String {
        let mut out = String::new();
        self.write(order, &mut out);
        out
    }
}

/// An array's elements, or an object's keys and values in turn.
struct Children<'i, 't> {
    index: &'i Index<'t>,
    next: usize,
    end: usize,
}

impl<'i, 't> Iterator for Children<'i, 't> {
    type Item = Value<'i, 't>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        let value = Value {
            index: self.index,
            id: self.next,
        };
        self.next = self.index.next(self.next).max(self.next + 1);
        Some(value)
    }
}

/// A string token's UTF-16 code units, decoded as they're read.
#[derive(Debug, Clone)]
pub struct Units<'t> {
    text: &'t str,
    /// The next byte of the token.
    i: usize,
    /// The second half of a surrogate pair.
    low: Option<u16>,
}

impl Iterator for Units<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        if let Some(low) = self.low.take() {
            return Some(low);
        }
        let s = self.text.as_bytes();
        match *s.get(self.i)? {
            b'"' => None,
            b'\\' => {
                let escape = *s.get(self.i + 1)?;
                self.i += 2;
                Some(match escape {
                    b'"' => 0x22,
                    b'\\' => 0x5c,
                    b'/' => 0x2f,
                    b'b' => 0x08,
                    b'f' => 0x0c,
                    b'n' => 0x0a,
                    b'r' => 0x0d,
                    b't' => 0x09,
                    b'u' => {
                        let digits = std::str::from_utf8(s.get(self.i..self.i + 4)?).ok()?;
                        self.i += 4;
                        u16::from_str_radix(digits, 16).ok()?
                    }
                    _ => return None,
                })
            }
            b if b < 0x80 => {
                self.i += 1;
                Some(u16::from(b))
            }
            _ => {
                let c = self.text.get(self.i..)?.chars().next()?;
                self.i += c.len_utf8();
                let mut pair = [0u16; 2];
                let units = c.encode_utf16(&mut pair);
                if let [high, low] = units {
                    self.low = Some(*low);
                    Some(*high)
                } else {
                    units.first().copied()
                }
            }
        }
    }
}

/// `JSON.stringify(string)` for a string of UTF-16 code units: lone
/// surrogates and control characters escaped, the rest as it is.
pub fn quote_units(units: impl IntoIterator<Item = u16>, out: &mut impl Sink) {
    use std::fmt::Write as _;
    // Written in pieces, so a long string needs no second copy.
    let mut buffer = String::with_capacity(64);
    buffer.push('"');
    for item in char::decode_utf16(units) {
        match item {
            Ok('"') => buffer.push_str("\\\""),
            Ok('\\') => buffer.push_str("\\\\"),
            Ok('\u{08}') => buffer.push_str("\\b"),
            Ok('\u{0c}') => buffer.push_str("\\f"),
            Ok('\n') => buffer.push_str("\\n"),
            Ok('\r') => buffer.push_str("\\r"),
            Ok('\t') => buffer.push_str("\\t"),
            Ok(c) if (c as u32) < 0x20 => {
                let _ = write!(buffer, "\\u{:04x}", c as u32);
            }
            Ok(c) => buffer.push(c),
            Err(lone) => {
                let _ = write!(buffer, "\\u{:04x}", lone.unpaired_surrogate());
            }
        }
        if buffer.len() >= 8192 {
            out.push(&buffer);
            buffer.clear();
        }
    }
    buffer.push('"');
    out.push(&buffer);
}

/// The scratch [`Value::write`] keeps the open objects' members in.
enum Arena {
    /// Key nodes; each value is the node after its key.
    Sorted(Vec<u32>),
    /// A key's first node and its last node.
    Property(Vec<(u32, u32)>),
}

impl Arena {
    fn len(&self) -> usize {
        match self {
            Arena::Sorted(keys) => keys.len(),
            Arena::Property(pairs) => pairs.len(),
        }
    }

    fn truncate(&mut self, len: usize) {
        match self {
            Arena::Sorted(keys) => keys.truncate(len),
            Arena::Property(pairs) => pairs.truncate(len),
        }
    }

    /// The key and value node of the member at `i`.
    fn member(&self, i: usize) -> Option<(usize, usize)> {
        match self {
            Arena::Sorted(keys) => keys.get(i).map(|k| (*k as usize, *k as usize + 1)),
            Arena::Property(pairs) => pairs
                .get(i)
                .map(|(k, last)| (*k as usize, *last as usize + 1)),
        }
    }

    #[cfg(test)]
    fn capacity_bytes(&self) -> usize {
        match self {
            Arena::Sorted(keys) => keys.capacity() * 4,
            Arena::Property(pairs) => pairs.capacity() * 8,
        }
    }
}

fn write_value(value: Value<'_, '_>, order: KeyOrder, out: &mut impl Sink) {
    let mut arena = match order {
        KeyOrder::Sorted => Arena::Sorted(Vec::new()),
        KeyOrder::Property => Arena::Property(Vec::new()),
    };
    write_with(value, order, out, &mut arena);
}

fn write_with(value: Value<'_, '_>, order: KeyOrder, out: &mut impl Sink, arena: &mut Arena) {
    enum Frame {
        Array {
            first: usize,
            next: usize,
            end: usize,
        },
        Object {
            base: usize,
            pos: usize,
        },
    }
    let index = value.index;
    let mut stack: Vec<Frame> = Vec::new();
    let mut current = Some(value.id);
    loop {
        if let Some(id) = current.take() {
            match index.kind(id) {
                Kind::Array => {
                    out.push("[");
                    stack.push(Frame::Array {
                        first: id + 1,
                        next: id + 1,
                        end: index.next(id),
                    });
                }
                Kind::Object => {
                    out.push("{");
                    let base = arena.len();
                    index.order_members(id, order, arena);
                    stack.push(Frame::Object { base, pos: base });
                }
                Kind::String => write_string(index, id, out),
                Kind::Number => {
                    let n = Value { index, id }.number();
                    if n.is_finite() {
                        out.push(&number_to_string(n));
                    } else {
                        out.push("null");
                    }
                }
                Kind::Null => out.push("null"),
                Kind::True => out.push("true"),
                Kind::False => out.push("false"),
            }
        }
        let Some(frame) = stack.last_mut() else {
            return;
        };
        match frame {
            Frame::Array { first, next, end } => {
                if *next < *end {
                    if *next != *first {
                        out.push(",");
                    }
                    current = Some(*next);
                    *next = index.next(*next).max(*next + 1);
                } else {
                    out.push("]");
                    stack.pop();
                }
            }
            Frame::Object { base, pos } => match arena.member(*pos) {
                Some((key, member)) => {
                    if *pos > *base {
                        out.push(",");
                    }
                    *pos += 1;
                    write_string(index, key, out);
                    out.push(":");
                    current = Some(member);
                }
                None => {
                    out.push("}");
                    arena.truncate(*base);
                    stack.pop();
                }
            },
        }
    }
}

/// A string as `JSON.stringify` writes it. Without escapes, the token is
/// already that: JSON forbids raw control characters, and UTF-8 text holds
/// no lone surrogates.
fn write_string(index: &Index<'_>, id: usize, out: &mut impl Sink) {
    let start = index.start(id);
    let end = string_end(index.text.as_bytes(), start).unwrap_or(start);
    match index.text.get(start..end) {
        Some(token) if !token.contains('\\') => out.push(token),
        _ => quote_units(index.units(id), out),
    }
}

// ---------------------------------------------------------------------------
// The scanner: V8's grammar, as `crate::parse` reads it.

/// What the scanner reports, in document order.
trait Events {
    /// A value or a key starts at `at`.
    fn value(&mut self, at: usize);
    /// The value reported last is a container, now open.
    fn open(&mut self);
    /// The innermost open container is closed.
    fn close(&mut self);
}

struct Count(usize);

impl Events for Count {
    fn value(&mut self, _: usize) {
        self.0 += 1;
    }
    fn open(&mut self) {}
    fn close(&mut self) {}
}

struct Fill {
    nodes: Vec<Node>,
    /// The open containers' nodes, innermost last.
    open: Vec<u32>,
}

impl Events for Fill {
    fn value(&mut self, at: usize) {
        // Both fit: the text is at most MAX_TEXT bytes, with fewer nodes.
        let id = self.nodes.len() as u32;
        self.nodes.push(Node {
            start: at as u32,
            next: id + 1,
        });
    }
    fn open(&mut self) {
        self.open.push(self.nodes.len().saturating_sub(1) as u32);
    }
    fn close(&mut self) {
        let next = self.nodes.len() as u32;
        if let Some(node) = self
            .open
            .pop()
            .and_then(|id| self.nodes.get_mut(id as usize))
        {
            node.next = next;
        }
    }
}

fn scan(text: &str, events: &mut impl Events) -> Result<(), IndexError> {
    let s = text.as_bytes();
    // The open containers, innermost last: true for an object.
    let mut objects = [false; MAX_DEPTH];
    let mut depth = 0usize;
    let mut i = skip_ws(s, 0);
    loop {
        // A value starts at `i`.
        match s.get(i) {
            Some(&open @ (b'{' | b'[')) => {
                // Every container is a level, an empty one included.
                let Some(slot) = objects.get_mut(depth) else {
                    return Err(IndexError::TooDeep);
                };
                *slot = open == b'{';
                depth += 1;
                events.value(i);
                events.open();
                i = skip_ws(s, i + 1);
                let close = if open == b'{' { b'}' } else { b']' };
                if s.get(i) == Some(&close) {
                    i += 1;
                    events.close();
                    depth -= 1;
                } else {
                    if open == b'{' {
                        i = key(s, i, events)?;
                    }
                    continue;
                }
            }
            Some(b'"') => {
                events.value(i);
                i = string_end(s, i)?;
            }
            Some(b't') => {
                events.value(i);
                i = literal(s, i, b"true")?;
            }
            Some(b'f') => {
                events.value(i);
                i = literal(s, i, b"false")?;
            }
            Some(b'n') => {
                events.value(i);
                i = literal(s, i, b"null")?;
            }
            Some(b'-' | b'0'..=b'9') => {
                events.value(i);
                i = number_end(s, i)?;
            }
            _ => return Err(IndexError::Syntax(i)),
        }
        // After a value: separators and closing brackets.
        loop {
            i = skip_ws(s, i);
            let Some(object) = depth.checked_sub(1).and_then(|top| objects.get(top)) else {
                return if i == s.len() {
                    Ok(())
                } else {
                    Err(IndexError::Syntax(i))
                };
            };
            match (s.get(i), object) {
                (Some(b','), _) => {
                    i = skip_ws(s, i + 1);
                    if *object {
                        i = key(s, i, events)?;
                    }
                    break;
                }
                (Some(b']'), false) | (Some(b'}'), true) => {
                    i += 1;
                    events.close();
                    depth -= 1;
                }
                _ => return Err(IndexError::Syntax(i)),
            }
        }
    }
}

/// A key and its colon: returns where its value starts.
fn key(s: &[u8], i: usize, events: &mut impl Events) -> Result<usize, IndexError> {
    if s.get(i) != Some(&b'"') {
        return Err(IndexError::Syntax(i));
    }
    events.value(i);
    let i = skip_ws(s, string_end(s, i)?);
    if s.get(i) != Some(&b':') {
        return Err(IndexError::Syntax(i));
    }
    Ok(skip_ws(s, i + 1))
}

/// JSON's whitespace only: tab, LF, CR and space.
fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while matches!(s.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

fn literal(s: &[u8], i: usize, word: &[u8]) -> Result<usize, IndexError> {
    if s.get(i..i + word.len()) == Some(word) {
        Ok(i + word.len())
    } else {
        Err(IndexError::Syntax(i))
    }
}

/// The end of the string token at `i` (its opening quote).
fn string_end(s: &[u8], mut i: usize) -> Result<usize, IndexError> {
    i += 1;
    loop {
        match s.get(i) {
            Some(b'"') => return Ok(i + 1),
            Some(b'\\') => match s.get(i + 1) {
                Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => i += 2,
                Some(b'u')
                    if s.get(i + 2..i + 6)
                        .is_some_and(|digits| digits.iter().all(u8::is_ascii_hexdigit)) =>
                {
                    i += 6;
                }
                _ => return Err(IndexError::Syntax(i + 1)),
            },
            // A raw control character, or the end of the text.
            Some(&b) if b >= 0x20 => i += 1,
            _ => return Err(IndexError::Syntax(i)),
        }
    }
}

fn digits(s: &[u8], mut i: usize) -> usize {
    while s.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    i
}

/// The end of the number token at `i`.
fn number_end(s: &[u8], mut i: usize) -> Result<usize, IndexError> {
    if s.get(i) == Some(&b'-') {
        i += 1;
    }
    match s.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => i = digits(s, i),
        _ => return Err(IndexError::Syntax(i)),
    }
    if s.get(i) == Some(&b'.') {
        let end = digits(s, i + 1);
        if end == i + 1 {
            return Err(IndexError::Syntax(end));
        }
        i = end;
    }
    if matches!(s.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(s.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let end = digits(s, i);
        if end == i {
            return Err(IndexError::Syntax(end));
        }
        i = end;
    }
    Ok(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JsValue, JsonError, parse};

    fn stringify(text: &str, order: KeyOrder) -> String {
        Index::new(text).unwrap().root().stringify(order)
    }

    /// The tree parser and the index accept and refuse the same texts.
    fn same_verdict(text: &str) {
        let tree = parse(text);
        let index = Index::new(text);
        match (&tree, &index) {
            (Ok(_), Ok(_)) | (Err(JsonError::TooDeep), Err(IndexError::TooDeep)) => {}
            (Err(JsonError::Syntax(_)), Err(IndexError::Syntax(_))) => {}
            _ => panic!("{text:?}: {tree:?} but {index:?}"),
        }
        // Where both accept, writing in property order is JSON.stringify of
        // the tree (strings without lone surrogates, which the tree can't
        // hold).
        if let (Ok(tree), Ok(index)) = (tree, index)
            && !text.contains("\\u")
        {
            assert_eq!(
                index.root().stringify(KeyOrder::Property),
                tree.stringify(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn accepts_and_refuses_what_parse_does() {
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        for text in [
            "0",
            "-0",
            "1.5e-7",
            "1E+2",
            "-1.0e400",
            "true",
            "false",
            "null",
            "\"\"",
            "\"a\\\"b\"",
            "[]",
            "{}",
            " [ 1 , 2 ] ",
            "{\"a\":1,\"a\":2}",
            "{\"b\":1,\"2\":0,\"a\":3,\"1\":4,\"01\":5}",
            "[{\"a\":[{}]},[[]],\"x\"]",
            "\t\n\r 7 \r\n\t",
            &nest(MAX_DEPTH),
            &nest(MAX_DEPTH + 1),
            &format!("{{\"a\":{}}}", nest(MAX_DEPTH - 1)),
            &format!("{{\"a\":{}}}", nest(MAX_DEPTH)),
            &format!("[{},x]", nest(MAX_DEPTH + 5)),
            "\u{FEFF}{}",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "-",
            "\"\u{1}\"",
            "nul",
            "[1] x",
            "\u{a0}1",
            "",
            " ",
            "[",
            "]",
            "{\"a\"}",
            "{\"a\" 1}",
            "{1:2}",
            "[1 2]",
            "\"\\x\"",
            "\"\\u12\"",
            "\"\\u+041\"",
            "\"\\u-041\"",
            "+1",
            ".5",
            "1.e3",
            "1e",
            "1e+",
            "--1",
            "[-]",
            "{\"a\":1}}",
            "[]]",
            "\"a",
            "tru",
            "falsey",
            "nulll",
            "[1,,2]",
            "{,}",
            "{\"a\":1,,}",
            "\"\t\"",
            "\"\u{7f}\u{2028}é😀\"",
        ] {
            same_verdict(text);
        }
    }

    #[test]
    fn spans_and_lookups() {
        let text =
            r#" { "result" : [ 1 , { "a" : "b" } ] , "id":7, "result" : {"x":[ ]} , "e":"" } "#;
        let index = Index::new(text).unwrap();
        let root = index.root();
        assert_eq!(root.kind(), Kind::Object);
        assert_eq!(root.raw(), text.trim());
        let result = root.get("result").unwrap();
        assert_eq!(result.raw(), r#"{"x":[ ]}"#);
        assert_eq!(result.get("x").unwrap().raw(), "[ ]");
        assert_eq!(root.get("id").unwrap().number(), 7.0);
        assert!(root.get("missing").is_none());
        assert!(result.get("x").unwrap().get("x").is_none());
        assert!(!root.get("e").unwrap().truthy());
        assert_eq!(root.members().count(), 4);
        let first = root.members().next().unwrap().1;
        assert_eq!(first.raw(), r#"[ 1 , { "a" : "b" } ]"#);
        assert_eq!(
            first.children().map(|v| v.raw()).collect::<Vec<_>>(),
            ["1", r#"{ "a" : "b" }"#]
        );
        // Escaped keys are the same keys.
        let escaped = Index::new(r#"{"\u0061":1,"a":2,"\ud800":3}"#).unwrap();
        assert_eq!(escaped.root().get("a").unwrap().raw(), "2");
        assert!(escaped.root().members().next().unwrap().0.is_str("a"));
        let lone: Vec<u16> = escaped.root().members().nth(2).unwrap().0.units().collect();
        assert_eq!(lone, [0xD800]);
        for (text, truthy) in [
            ("0", false),
            ("-0", false),
            ("0.0e5", false),
            ("1e-400", false),
            ("\"\"", false),
            ("null", false),
            ("false", false),
            ("\"0\"", true),
            ("\"\\u0000\"", true),
            ("1e400", true),
            ("[]", true),
            ("{}", true),
            ("true", true),
            ("-1", true),
        ] {
            assert_eq!(Index::new(text).unwrap().root().truthy(), truthy, "{text}");
        }
    }

    #[test]
    fn writes_like_json_stringify() {
        let text = r#"{"b":1,"2":0,"a":[1E2,-0,1e400,"\u0041\/\ud800\ud83d\ude00\u001f"],"1":{"y":null,"x":true},"01":5,"b":false}"#;
        assert_eq!(
            stringify(text, KeyOrder::Property),
            r#"{"1":{"y":null,"x":true},"2":0,"b":false,"a":[100,0,null,"A/\ud800😀\u001f"],"01":5}"#
        );
        assert_eq!(
            stringify(text, KeyOrder::Sorted),
            r#"{"01":5,"1":{"x":true,"y":null},"2":0,"a":[100,0,null,"A/\ud800😀\u001f"],"b":false}"#
        );
        // UTF-16 order: a supplementary character (D83D DE00) sorts before
        // U+FFFF and U+FFFD, unlike code point or UTF-8 order.
        assert_eq!(
            stringify(
                r#"{"\uffff":1,"😀":2,"\ufffd":3,"\ud800":4,"é":5}"#,
                KeyOrder::Sorted
            ),
            "{\"é\":5,\"\\ud800\":4,\"😀\":2,\"\u{fffd}\":3,\"\u{ffff}\":1}"
        );
        // Raw tokens are copied; escaped ones are rewritten.
        assert_eq!(
            stringify("\"\u{7f}\u{2028}\"", KeyOrder::Sorted),
            "\"\u{7f}\u{2028}\""
        );
        assert_eq!(
            stringify(r#""\"\\\b\f\n\r\t\u007f""#, KeyOrder::Sorted),
            "\"\\\"\\\\\\b\\f\\n\\r\\t\u{7f}\""
        );
        assert_eq!(
            stringify(r#""\uDBFF\uDFFF\uDFFF\uD800x""#, KeyOrder::Sorted),
            "\"\u{10FFFF}\\udfff\\ud800x\""
        );
        // __proto__ is an ordinary key.
        assert_eq!(
            stringify(r#"{"__proto__":{"a":1},"b":2}"#, KeyOrder::Sorted),
            r#"{"__proto__":{"a":1},"b":2}"#
        );
        let index = Index::new(r#"{"b":1,"a":2,"b":3,"1":4}"#).unwrap();
        let properties: Vec<_> = index
            .root()
            .properties()
            .into_iter()
            .map(|(k, v)| (k.raw(), v.raw()))
            .collect();
        assert_eq!(properties, [("\"1\"", "4"), ("\"b\"", "3"), ("\"a\"", "2")]);
    }

    #[test]
    fn array_index_keys() {
        let text =
            r#"{"4294967294":1,"4294967295":2,"0":3,"00":4,"-1":5,"1.0":6,"10":7,"9":8,"":9}"#;
        assert_eq!(
            stringify(text, KeyOrder::Property),
            r#"{"0":3,"9":8,"10":7,"4294967294":1,"4294967295":2,"00":4,"-1":5,"1.0":6,"":9}"#
        );
        // The tree parser agrees.
        assert_eq!(
            parse(text).unwrap().stringify(),
            stringify(text, KeyOrder::Property)
        );
    }

    /// The index holds at most HEAP_PER_TEXT_BYTE bytes per text byte, plus
    /// that once; writing holds at most WRITE_SCRATCH_PER_TEXT_BYTE (twice
    /// for property order).
    #[test]
    fn memory_is_bounded_per_text_byte() {
        let n = 20_000;
        let texts = [
            format!("[{}0]", "0,".repeat(n)),
            format!("{{{}\"\":0}}", "\"\":0,".repeat(n)),
            format!(
                "{{{}\"\":0}}",
                (0..n)
                    .map(|i| format!("\"{}\":0,", i % 10))
                    .collect::<String>()
            ),
            format!("[{}[]]", "[],".repeat(n)),
            format!("[{}{{}}]", "{},".repeat(n)),
            format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH)),
            format!("{}0{}", "{\"\":".repeat(MAX_DEPTH), "}".repeat(MAX_DEPTH)),
            format!(
                "{{{}\"z\":{{{}\"\":0}}}}",
                "\"\":0,".repeat(n),
                "\"\":0,".repeat(n)
            ),
            "0".into(),
            "[0]".into(),
            "\"x\"".into(),
            // Smaller than a growing vector's first allocation.
            r#"{"":0}"#.into(),
            r#"{"a":{"":0}}"#.into(),
        ];
        for text in &texts {
            let index = Index::new(text).unwrap();
            let bound = HEAP_PER_TEXT_BYTE * (text.len() + 1);
            assert!(
                index.heap_bytes() <= bound,
                "{} > {bound}",
                index.heap_bytes()
            );
            for (order, per_byte) in [
                (KeyOrder::Sorted, WRITE_SCRATCH_PER_TEXT_BYTE),
                (KeyOrder::Property, 2 * WRITE_SCRATCH_PER_TEXT_BYTE),
            ] {
                let mut arena = match order {
                    KeyOrder::Sorted => Arena::Sorted(Vec::new()),
                    KeyOrder::Property => Arena::Property(Vec::new()),
                };
                let mut out = String::new();
                write_with(index.root(), order, &mut out, &mut arena);
                let bound = per_byte * (text.len() + 1) + WRITE_SCRATCH_FLOOR;
                assert!(
                    arena.capacity_bytes() <= bound,
                    "{} > {bound}",
                    arena.capacity_bytes()
                );
            }
        }
        // The densest text, one node per two bytes, fills the bound exactly.
        let dense = format!("[{}0]", "0,".repeat(n));
        assert_eq!(
            Index::new(&dense).unwrap().nodes.len(),
            dense.len().div_ceil(2)
        );
    }

    #[test]
    fn walks_are_stack_safe() {
        let handle = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let text = format!(
                    "{}1{}",
                    r#"{"a":["#.repeat(MAX_DEPTH / 2),
                    "]}".repeat(MAX_DEPTH / 2)
                );
                let index = Index::new(&text).unwrap();
                assert_eq!(index.root().stringify(KeyOrder::Sorted), text);
                assert_eq!(index.root().stringify(KeyOrder::Property), text);
                assert_eq!(index.root().raw(), text);
                assert_eq!(
                    Index::new(&"[".repeat(200_000)).err(),
                    Some(IndexError::TooDeep)
                );
            })
            .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn many_keys_stay_fast() {
        let keys: Vec<String> = (0..50_000)
            .map(|i| format!(r#""k{}":{i}"#, i % 25_000))
            .collect();
        let text = format!("{{{}}}", keys.join(","));
        let started = std::time::Instant::now();
        let index = Index::new(&text).unwrap();
        let sorted = index.root().stringify(KeyOrder::Sorted);
        let property = index.root().stringify(KeyOrder::Property);
        assert!(started.elapsed().as_secs() < 5, "{:?}", started.elapsed());
        let tree = parse(&text).unwrap();
        assert_eq!(property, tree.stringify());
        let JsValue::Object(props) = &tree else {
            panic!()
        };
        assert_eq!(props.len(), 25_000);
        assert!(sorted.starts_with(r#"{"k0":25000,"k1":25001,"k10":25010,"#));
    }
}
