use std::{
    error::Error as StdError,
    fmt,
    io::{self, Read},
    path::Path,
};

use flate2::read::ZlibDecoder;

const SRS_MAGIC: &[u8; 3] = b"SRS";
const RULE_TYPE_DEFAULT: u8 = 0;
const RULE_ITEM_DOMAIN: u8 = 2;
const RULE_ITEM_FINAL: u8 = 0xff;

// Старый формат domain matcher (SRS v1)
const DOMAIN_MATCHER_VERSION_V1: u8 = 1;
// SuccinctSet version (SRS v2+)
const SUCCINCT_SET_VERSION: u8 = 0;

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(&'static str),
    UnsupportedSrsVersion(u8),
    UnsupportedDomainVersion(u8),
    UnsupportedSuccinctSetVersion(u8),
    UnsupportedRuleType(u8),
    UnsupportedRuleItem(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Invalid(msg) => write!(f, "invalid SRS: {msg}"),
            Self::UnsupportedSrsVersion(v) => {
                write!(f, "unsupported SRS version: {v}")
            }
            Self::UnsupportedDomainVersion(v) => {
                write!(f, "unsupported domain matcher version: {v}")
            }
            Self::UnsupportedSuccinctSetVersion(v) => {
                write!(f, "unsupported succinct set version: {v}")
            }
            Self::UnsupportedRuleType(v) => {
                write!(f, "unsupported rule type: {v}")
            }
            Self::UnsupportedRuleItem(v) => {
                write!(f, "unsupported rule item: {v}")
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct SrsGeoSite {
    matcher: Matcher,
}

impl SrsGeoSite {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);

        // --------------------------------------------------------
        // SRS header
        // --------------------------------------------------------
        if reader.read_exact(3)? != SRS_MAGIC {
            return Err(Error::Invalid("invalid SRS magic"));
        }

        let version = reader.read_u8()?;
        if version != 1 && version != 2 {
            return Err(Error::UnsupportedSrsVersion(version));
        }

        // --------------------------------------------------------
        // zlib payload
        // --------------------------------------------------------
        let compressed = reader.remaining();
        let mut decoder = ZlibDecoder::new(compressed);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        let mut reader = Reader::new(&decompressed);

        // --------------------------------------------------------
        // Rules
        // --------------------------------------------------------
        let rule_count = reader.read_uvarint()?;
        if rule_count != 1 {
            return Err(Error::Invalid("expected exactly one rule"));
        }

        let rule_type = reader.read_u8()?;
        if rule_type != RULE_TYPE_DEFAULT {
            return Err(Error::UnsupportedRuleType(rule_type));
        }

        let item_type = reader.read_u8()?;
        if item_type != RULE_ITEM_DOMAIN {
            return Err(Error::UnsupportedRuleItem(item_type));
        }

        // --------------------------------------------------------
        // Domain matcher
        // --------------------------------------------------------
        let matcher = if version == 1 {
            // SRS v1: domain matcher version byte + SuccinctSet (без version)
            let domain_version = reader.read_u8()?;
            if domain_version != DOMAIN_MATCHER_VERSION_V1 {
                return Err(Error::UnsupportedDomainVersion(domain_version));
            }
            Matcher {
                set: SuccinctSet::read_v1(&mut reader)?,
            }
        } else {
            // SRS v2+: SuccinctSet сразу (с version byte = 0)
            Matcher {
                set: SuccinctSet::read_v2(&mut reader)?,
            }
        };

        // --------------------------------------------------------
        // Final rule item
        // --------------------------------------------------------
        let final_item = reader.read_u8()?;
        if final_item != RULE_ITEM_FINAL {
            return Err(Error::Invalid("missing final rule item"));
        }

        // invert
        let invert = reader.read_u8()?;
        if invert != 0 {
            return Err(Error::Invalid("inverted domain rules are not supported"));
        }

        // There should be nothing after the rule.
        if !reader.remaining().is_empty() {
            return Err(Error::Invalid("trailing data after SRS rule"));
        }

        Ok(Self { matcher })
    }

    #[inline]
    pub fn contains(&self, domain: &str) -> bool {
        self.matcher.matches(domain)
    }

    #[inline]
    pub fn list(&self) -> (Vec<String>, Vec<String>) {
        self.matcher.dump()
    }
}

// ============================================================
// Domain matcher
// ============================================================

struct Matcher {
    set: SuccinctSet,
}

impl Matcher {
    #[inline]
    fn matches(&self, domain: &str) -> bool {
        let reversed = reverse_domain(domain);
        self.has(&reversed)
    }

    // This intentionally mirrors sing/common/domain/matcher.go.
    fn has(&self, key: &[u8]) -> bool {
        let mut node_id = 0usize;
        let mut bm_idx = 0usize;

        for &current_char in key {
            loop {
                // End of current node's children.
                if self.set.get_bit(bm_idx) != 0 {
                    return false;
                }

                let next_label = self.set.labels[bm_idx - node_id];

                // Prefix rule.
                if next_label == PREFIX_LABEL {
                    return true;
                }

                // Root/suffix rule.
                if next_label == ROOT_LABEL {
                    let next_node_id = self.set.count_zeros(bm_idx + 1);
                    let has_next = self.set.get_leaf(next_node_id);
                    if current_char == b'.' && has_next {
                        return true;
                    }
                }

                if next_label == current_char {
                    break;
                }

                bm_idx += 1;
            }

            node_id = self.set.count_zeros(bm_idx + 1);
            bm_idx = self.set.select_ith_one(node_id - 1) + 1;
        }

        // Exact match.
        if self.set.get_leaf(node_id) {
            return true;
        }

        // Prefix/root match after the complete key.
        loop {
            if self.set.get_bit(bm_idx) != 0 {
                return false;
            }

            let next_label = self.set.labels[bm_idx - node_id];
            if next_label == PREFIX_LABEL || next_label == ROOT_LABEL {
                return true;
            }

            bm_idx += 1;
        }
    }
    /// Возвращает все домены, которые лежат в матчере.
    ///
    /// - `domains`  — точные совпадения (domain)
    /// - `prefixes` — суффиксы / префиксы (domain_suffix)
    pub fn dump(&self) -> (Vec<String>, Vec<String>) {
        let mut domain_map = std::collections::HashMap::new();
        let mut prefix_map = std::collections::HashMap::new();
        let mut root_list = Vec::new();

        for key in self.set.keys() {
            let reversed = reverse_domain_bytes(&key);

            if reversed.is_empty() {
                continue;
            }

            match reversed[0] {
                PREFIX_LABEL => {
                    // \r + domain  →  prefix (domain_suffix)
                    let s = String::from_utf8_lossy(&reversed[1..]).into_owned();
                    prefix_map.insert(s, true);
                }
                ROOT_LABEL => {
                    // \n + domain  →  root/suffix
                    let s = String::from_utf8_lossy(&reversed[1..]).into_owned();
                    root_list.push(s);
                }
                _ => {
                    // обычный точный домен
                    let s = String::from_utf8_lossy(&reversed).into_owned();
                    domain_map.insert(s, true);
                }
            }
        }

        // Логика как в sing: если есть и точный домен, и prefix вида ".domain",
        // то это считается domain_suffix.
        for raw_prefix in prefix_map.keys() {
            if let Some(rest) = raw_prefix.strip_prefix('.') {
                if domain_map.remove(rest).is_some() {
                    root_list.push(rest.to_string());
                    continue;
                }
            }
            root_list.push(raw_prefix.clone());
        }

        let mut domains: Vec<String> = domain_map.into_keys().collect();
        let mut prefixes = root_list;

        domains.sort();
        prefixes.sort();
        prefixes.dedup();

        (domains, prefixes)
    }
}

// ============================================================
// Succinct set
// ============================================================

struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    // Same idea as sing's ranks/selects.
    ranks: Vec<u32>,
    selects: Vec<u32>,
}

impl SuccinctSet {
    /// SRS v1: без version-байта в начале set
    fn read_v1(reader: &mut Reader<'_>) -> Result<Self> {
        Self::read_inner(reader)
    }

    /// SRS v2+: version byte (должен быть 0) + leaves/bitmap/labels
    fn read_v2(reader: &mut Reader<'_>) -> Result<Self> {
        let version = reader.read_u8()?;
        if version != SUCCINCT_SET_VERSION {
            return Err(Error::UnsupportedSuccinctSetVersion(version));
        }
        Self::read_inner(reader)
    }

    fn read_inner(reader: &mut Reader<'_>) -> Result<Self> {
        let leaves = reader.read_u64_slice()?;
        let label_bitmap = reader.read_u64_slice()?;
        let labels = reader.read_byte_slice()?;

        let (selects, ranks) = build_indexes(&label_bitmap);

        Ok(Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
            selects,
        })
    }

    #[inline]
    fn get_bit(&self, index: usize) -> u64 {
        let word = index >> 6;
        if word >= self.label_bitmap.len() {
            return 1;
        }
        (self.label_bitmap[word] >> (index & 63)) & 1
    }

    #[inline]
    fn get_leaf(&self, index: usize) -> bool {
        let word = index >> 6;
        if word >= self.leaves.len() {
            return false;
        }
        ((self.leaves[word] >> (index & 63)) & 1) != 0
    }

    /// Number of zero bits before `index`.
    ///
    /// This is sing's countZeros().
    #[inline]
    fn count_zeros(&self, index: usize) -> usize {
        let word_index = index >> 6;
        if word_index >= self.label_bitmap.len() {
            return 0;
        }

        let rank_ones = self.ranks[word_index] as usize;
        let bit = index & 63;
        let word = self.label_bitmap[word_index];
        let ones_inside = (word & mask_low_bits(bit)).count_ones() as usize;

        index - rank_ones - ones_inside
    }

    /// Return position of the `i`-th one bit.
    ///
    /// Same semantics as sing's selectIthOne().
    #[inline]
    fn select_ith_one(&self, index: usize) -> usize {
        let base = self.selects[index >> 6] as usize;
        let mut remaining = index - self.ranks[base >> 6] as usize;
        let mut word_index = base >> 6;

        while word_index < self.label_bitmap.len() {
            let mut word = self.label_bitmap[word_index];
            let mut bit_offset = 0usize;

            while word != 0 {
                let tz = word.trailing_zeros() as usize;
                word >>= tz;
                bit_offset += tz;

                if remaining == 0 {
                    return (word_index << 6) + bit_offset;
                }

                word >>= 1;
                bit_offset += 1;
                remaining -= 1;
            }

            word_index += 1;
        }

        panic!("select_ith_one: index out of range");
    }
    /// Восстанавливает все ключи, которые были закодированы в set.
    pub fn keys(&self) -> Vec<Vec<u8>> {
        let mut result = Vec::new();
        let mut current = Vec::new();

        self.traverse(0, 0, &mut current, &mut result);
        result
    }

    fn traverse(
        &self,
        node_id: usize,
        mut bm_idx: usize,
        current: &mut Vec<u8>,
        result: &mut Vec<Vec<u8>>,
    ) {
        // лист?
        if self.get_leaf(node_id) {
            result.push(current.clone());
        }

        loop {
            if self.get_bit(bm_idx) != 0 {
                return; // конец детей этого узла
            }

            let next_label = self.labels[bm_idx - node_id];
            current.push(next_label);

            let next_node_id = self.count_zeros(bm_idx + 1);
            let next_bm_idx = self.select_ith_one(next_node_id - 1) + 1;

            self.traverse(next_node_id, next_bm_idx, current, result);

            current.pop();
            bm_idx += 1;
        }
    }
}

/// Разворачивает байты так же, как reverse_domain, но работает с &[u8]
fn reverse_domain_bytes(data: &[u8]) -> Vec<u8> {
    // data уже в "перевёрнутом" виде (как хранится внутри set),
    // поэтому просто делаем UTF-8 safe reverse
    let s = String::from_utf8_lossy(data);
    let mut result = Vec::with_capacity(data.len());
    for ch in s.chars().rev() {
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        result.extend_from_slice(encoded.as_bytes());
    }
    result
}

// ============================================================
// Bitmap indexes
// ============================================================

fn build_indexes(bitmap: &[u64]) -> (Vec<u32>, Vec<u32>) {
    let mut ranks = Vec::with_capacity(bitmap.len() + 1);
    ranks.push(0);

    let mut total = 0u32;
    for &word in bitmap {
        total += word.count_ones();
        ranks.push(total);
    }

    let mut selects = Vec::new();
    let mut ones = 0usize;

    for (word_index, &word) in bitmap.iter().enumerate() {
        let mut w = word;
        while w != 0 {
            let bit = w.trailing_zeros() as usize;
            if ones & 63 == 0 {
                selects.push(((word_index << 6) + bit) as u32);
            }
            ones += 1;
            w &= w - 1;
        }
    }

    (selects, ranks)
}

#[inline]
fn mask_low_bits(n: usize) -> u64 {
    match n {
        0 => 0,
        64.. => u64::MAX,
        _ => (1u64 << n) - 1,
    }
}

// ============================================================
// Domain reversal
// ============================================================

/// Same algorithm as sing/common/domain/matcher.go.
///
/// It reverses UTF-8 codepoints, not raw bytes.
fn reverse_domain(domain: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len());
    for ch in domain.chars().rev() {
        let mut buf = [0u8; 4];
        let encoded = ch.encode_utf8(&mut buf);
        result.extend_from_slice(encoded.as_bytes());
    }
    result
}

// ============================================================
// Binary reader
// ============================================================

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::Invalid("unexpected EOF"));
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(Error::Invalid("integer overflow"))?;
        if end > self.data.len() {
            return Err(Error::Invalid("unexpected EOF"));
        }
        let result = &self.data[self.pos..end];
        self.pos = end;
        Ok(result)
    }

    fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn read_uvarint(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            if shift >= 64 {
                return Err(Error::Invalid("invalid uvarint"));
            }
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    fn read_u64_slice(&mut self) -> Result<Vec<u64>> {
        let len = self.read_uvarint()?;
        let len = usize::try_from(len).map_err(|_| Error::Invalid("slice is too large"))?;
        let mut result = Vec::with_capacity(len);
        for _ in 0..len {
            result.push(self.read_u64_be()?);
        }
        Ok(result)
    }

    fn read_byte_slice(&mut self) -> Result<Vec<u8>> {
        let len = self.read_uvarint()?;
        let len = usize::try_from(len).map_err(|_| Error::Invalid("byte slice is too large"))?;
        Ok(self.read_exact(len)?.to_vec())
    }
}
