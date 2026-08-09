use std::{
    error::Error as StdError,
    fmt,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use flate2::read::ZlibDecoder;

const MAGIC: &[u8; 3] = b"SRS";

const RULE_DEFAULT: u8 = 0;
const RULE_LOGICAL: u8 = 1;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;

const ITEM_FINAL: u8 = 0xff;

const IPSET_VERSION: u8 = 1;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),

    Invalid(&'static str),
    InvalidMagic([u8; 3]),
    UnsupportedVersion(u8),

    UnexpectedEof,
    InvalidVarint,
    InvalidUtf8,

    InvalidRuleType(u8),
    InvalidItemType(u8),

    UnsupportedItemType { item_type: u8, srs_version: u8 },

    InvalidIpSetVersion(u8),
    InvalidIpLength(usize),

    InvalidLogicalMode(u8),

    TrailingData,

    UnsupportedDomainVersion(u8),
    UnsupportedSuccinctSetVersion(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Invalid(msg) => write!(f, "invalid SRS: {msg}"),

            Self::InvalidMagic(magic) => {
                write!(f, "invalid SRS magic: {magic:02x?}")
            }

            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported SRS version: {version}")
            }

            Self::UnexpectedEof => {
                write!(f, "unexpected end of SRS data")
            }

            Self::InvalidVarint => {
                write!(f, "invalid uvarint")
            }

            Self::InvalidUtf8 => {
                write!(f, "invalid UTF-8")
            }

            Self::InvalidRuleType(value) => {
                write!(f, "invalid rule type: {value}")
            }

            Self::InvalidItemType(value) => {
                write!(f, "invalid item type: {value}")
            }

            Self::UnsupportedItemType {
                item_type,
                srs_version,
            } => {
                write!(
                    f,
                    "unsupported item type {item_type} for SRS version {srs_version}"
                )
            }

            Self::InvalidIpSetVersion(version) => {
                write!(f, "invalid IPSet version: {version}")
            }

            Self::InvalidIpLength(len) => {
                write!(f, "invalid IP address length: {len}")
            }

            Self::InvalidLogicalMode(mode) => {
                write!(f, "invalid logical rule mode: {mode}")
            }

            Self::TrailingData => {
                write!(f, "trailing data after SRS")
            }

            Self::UnsupportedDomainVersion(v) => {
                write!(f, "unsupported domain matcher version: {v}")
            }
            Self::UnsupportedSuccinctSetVersion(v) => {
                write!(f, "unsupported succinct set version: {v}")
            }
        }
    }
}

impl StdError for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Srs {
    pub version: u8,
    pub rules: Vec<Rule>,
}

#[derive(Debug)]
pub enum Rule {
    Default(DefaultRule),
    Logical(LogicalRule),
}

#[derive(Debug)]
pub struct DefaultRule {
    pub items: Vec<RuleItem>,
    pub invert: bool,
}

#[derive(Debug)]
pub struct LogicalRule {
    pub mode: LogicalMode,
    pub rules: Vec<Rule>,
    pub invert: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum LogicalMode {
    And,
    Or,
}

#[derive(Debug)]
pub enum RuleItem {
    QueryType(Vec<u16>),
    Network(Vec<String>),

    Domain(DomainMatcher),
    DomainKeyword(Vec<String>),
    DomainRegex(Vec<String>),

    SourceIpCidr(IpSet),
    IpCidr(IpSet),

    SourcePort(Vec<u16>),
    SourcePortRange(Vec<String>),

    Port(Vec<u16>),
    PortRange(Vec<String>),

    ProcessName(Vec<String>),
    ProcessPath(Vec<String>),
    PackageName(Vec<String>),

    WifiSsid(Vec<String>),
    WifiBssid(Vec<String>),

    AdGuardDomain,

    ProcessPathRegex(Vec<String>),

    NetworkType(Vec<u8>),
    NetworkIsExpensive,
    NetworkIsConstrained,

    NetworkInterfaceAddress,
    DefaultInterfaceAddress,
}

#[derive(Debug)]
pub struct IpSet {
    pub ranges: Vec<IpRange>,
}

#[derive(Debug, Clone, Copy)]
pub struct IpRange {
    pub from: IpAddr,
    pub to: IpAddr,
}

impl Srs {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);

        let magic = reader.read_array::<3>()?;

        if &magic != MAGIC {
            return Err(Error::InvalidMagic(magic));
        }

        let version = reader.read_u8()?;

        if !(1..=4).contains(&version) {
            return Err(Error::UnsupportedVersion(version));
        }

        // Всё после header — zlib.
        let compressed = reader.remaining();

        let mut decoder = ZlibDecoder::new(compressed);

        let mut decompressed = Vec::new();

        decoder.read_to_end(&mut decompressed)?;

        let mut reader = Reader::new(&decompressed);

        let rule_count = reader.read_uvarint()?;

        let rule_count = usize::try_from(rule_count).map_err(|_| Error::InvalidVarint)?;

        let mut rules = Vec::with_capacity(rule_count);

        for _ in 0..rule_count {
            rules.push(read_rule(&mut reader, version)?);
        }

        if !reader.remaining().is_empty() {
            return Err(Error::TrailingData);
        }

        Ok(Self { version, rules })
    }
}

fn read_rule(reader: &mut Reader<'_>, version: u8) -> Result<Rule> {
    match reader.read_u8()? {
        RULE_DEFAULT => Ok(Rule::Default(read_default_rule(reader, version)?)),

        RULE_LOGICAL => Ok(Rule::Logical(read_logical_rule(reader, version)?)),

        value => Err(Error::InvalidRuleType(value)),
    }
}

fn read_default_rule(reader: &mut Reader<'_>, version: u8) -> Result<DefaultRule> {
    let mut items = Vec::new();

    loop {
        let item_type = reader.read_u8()?;

        if item_type == ITEM_FINAL {
            break;
        }

        items.push(read_item(reader, item_type, version)?);
    }

    let invert = reader.read_bool()?;

    Ok(DefaultRule { items, invert })
}

fn read_logical_rule(reader: &mut Reader<'_>, version: u8) -> Result<LogicalRule> {
    let mode = match reader.read_u8()? {
        0 => LogicalMode::And,
        1 => LogicalMode::Or,
        value => return Err(Error::InvalidLogicalMode(value)),
    };

    let count = reader.read_uvarint()?;

    let count = usize::try_from(count).map_err(|_| Error::InvalidVarint)?;

    let mut rules = Vec::with_capacity(count);

    for _ in 0..count {
        rules.push(read_rule(reader, version)?);
    }

    let invert = reader.read_bool()?;

    Ok(LogicalRule {
        mode,
        rules,
        invert,
    })
}

fn read_item(reader: &mut Reader<'_>, item_type: u8, version: u8) -> Result<RuleItem> {
    match item_type {
        ITEM_QUERY_TYPE => Ok(RuleItem::QueryType(reader.read_u16_array()?)),

        ITEM_NETWORK => Ok(RuleItem::Network(reader.read_string_array()?)),

        ITEM_DOMAIN => Ok(RuleItem::Domain(read_domain_matcher(reader)?)),

        ITEM_DOMAIN_KEYWORD => Ok(RuleItem::DomainKeyword(reader.read_string_array()?)),

        ITEM_DOMAIN_REGEX => Ok(RuleItem::DomainRegex(reader.read_string_array()?)),

        ITEM_SOURCE_IP_CIDR => Ok(RuleItem::SourceIpCidr(read_ip_set(reader)?)),

        ITEM_IP_CIDR => Ok(RuleItem::IpCidr(read_ip_set(reader)?)),

        ITEM_SOURCE_PORT => Ok(RuleItem::SourcePort(reader.read_u16_array()?)),

        ITEM_SOURCE_PORT_RANGE => Ok(RuleItem::SourcePortRange(reader.read_string_array()?)),

        ITEM_PORT => Ok(RuleItem::Port(reader.read_u16_array()?)),

        ITEM_PORT_RANGE => Ok(RuleItem::PortRange(reader.read_string_array()?)),

        ITEM_PROCESS_NAME => Ok(RuleItem::ProcessName(reader.read_string_array()?)),

        ITEM_PROCESS_PATH => Ok(RuleItem::ProcessPath(reader.read_string_array()?)),

        ITEM_PACKAGE_NAME => Ok(RuleItem::PackageName(reader.read_string_array()?)),

        ITEM_WIFI_SSID => Ok(RuleItem::WifiSsid(reader.read_string_array()?)),

        ITEM_WIFI_BSSID => Ok(RuleItem::WifiBssid(reader.read_string_array()?)),

        ITEM_ADGUARD_DOMAIN => {
            if version < 2 {
                return Err(Error::UnsupportedItemType {
                    item_type,
                    srs_version: version,
                });
            }

            Ok(RuleItem::AdGuardDomain)
        }

        ITEM_PROCESS_PATH_REGEX => Ok(RuleItem::ProcessPathRegex(reader.read_string_array()?)),

        ITEM_NETWORK_TYPE => {
            if version < 3 {
                return Err(Error::UnsupportedItemType {
                    item_type,
                    srs_version: version,
                });
            }

            let count = reader.read_uvarint()?;

            let count = usize::try_from(count).map_err(|_| Error::InvalidVarint)?;

            let mut values = Vec::with_capacity(count);

            for _ in 0..count {
                values.push(reader.read_u8()?);
            }

            Ok(RuleItem::NetworkType(values))
        }

        ITEM_NETWORK_IS_EXPENSIVE => {
            if version < 3 {
                return Err(Error::UnsupportedItemType {
                    item_type,
                    srs_version: version,
                });
            }

            Ok(RuleItem::NetworkIsExpensive)
        }

        ITEM_NETWORK_IS_CONSTRAINED => {
            if version < 3 {
                return Err(Error::UnsupportedItemType {
                    item_type,
                    srs_version: version,
                });
            }

            Ok(RuleItem::NetworkIsConstrained)
        }

        ITEM_NETWORK_INTERFACE_ADDRESS => {
            if version < 4 {
                return Err(Error::UnsupportedItemType {
                    item_type,
                    srs_version: version,
                });
            }

            // Пока не реализуем TypedMap.
            todo!("network_interface_address")
        }

        ITEM_DEFAULT_INTERFACE_ADDRESS => {
            if version < 4 {
                return Err(Error::UnsupportedItemType {
                    item_type,
                    srs_version: version,
                });
            }

            todo!("default_interface_address")
        }

        value => Err(Error::InvalidItemType(value)),
    }
}

fn read_ip_set(reader: &mut Reader<'_>) -> Result<IpSet> {
    let version = reader.read_u8()?;

    if version != IPSET_VERSION {
        return Err(Error::InvalidIpSetVersion(version));
    }

    let count = reader.read_u64_be()?;

    let count = usize::try_from(count).map_err(|_| Error::InvalidVarint)?;

    let mut ranges = Vec::with_capacity(count);

    for _ in 0..count {
        let from = read_ip(reader)?;
        let to = read_ip(reader)?;

        ranges.push(IpRange { from, to });
    }
    ranges.sort_by_key(|range| range.from_value());

    Ok(IpSet { ranges })
}

fn read_ip(reader: &mut Reader<'_>) -> Result<IpAddr> {
    let len = reader.read_uvarint()?;

    let len = usize::try_from(len).map_err(|_| Error::InvalidVarint)?;

    let bytes = reader.read_exact(len)?;

    match len {
        4 => {
            let octets: [u8; 4] = bytes.try_into().unwrap();

            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }

        16 => {
            let octets: [u8; 16] = bytes.try_into().unwrap();

            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }

        value => Err(Error::InvalidIpLength(value)),
    }
}

impl<'a> Reader<'a> {
    fn read_string_array(&mut self) -> Result<Vec<String>> {
        let count = self.read_uvarint()?;

        let count = usize::try_from(count).map_err(|_| Error::InvalidVarint)?;

        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            let len = self.read_uvarint()?;

            let len = usize::try_from(len).map_err(|_| Error::InvalidVarint)?;

            let bytes = self.read_exact(len)?;

            let value = std::str::from_utf8(bytes)
                .map_err(|_| Error::InvalidUtf8)?
                .to_owned();

            result.push(value);
        }

        Ok(result)
    }

    fn read_u16_array(&mut self) -> Result<Vec<u16>> {
        let count = self.read_uvarint()?;

        let count = usize::try_from(count).map_err(|_| Error::InvalidVarint)?;

        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            result.push(self.read_u16_be()?);
        }

        Ok(result)
    }
}

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
            return Err(Error::UnexpectedEof);
        }

        let value = self.data[self.pos];

        self.pos += 1;

        Ok(value)
    }

    fn read_bool(&mut self) -> Result<bool> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(Error::Invalid("invalid boolean value")),
        }
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(Error::UnexpectedEof)?;

        if end > self.data.len() {
            return Err(Error::UnexpectedEof);
        }

        let result = &self.data[self.pos..end];

        self.pos = end;

        Ok(result)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.read_exact(N)?
            .try_into()
            .map_err(|_| Error::UnexpectedEof)
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u64_be(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    fn read_uvarint(&mut self) -> Result<u64> {
        let mut result = 0u64;
        let mut shift = 0;

        loop {
            if shift >= 64 {
                return Err(Error::InvalidVarint);
            }

            let byte = self.read_u8()?;

            result |= ((byte & 0x7f) as u64) << shift;

            if byte & 0x80 == 0 {
                return Ok(result);
            }

            shift += 7;
        }
    }
}

#[derive(Debug)]
struct DomainMatcher {
    set: SuccinctSet,
}

#[derive(Debug)]
struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,

    ranks: Vec<i32>,
    selects: Vec<i32>,
}

fn read_domain_matcher(reader: &mut Reader<'_>) -> Result<DomainMatcher> {
    let version = reader.read_u8()?;

    if version != 0 {
        return Err(Error::UnsupportedSuccinctSetVersion(version));
    }

    let leaves = reader.read_u64_slice()?;
    let label_bitmap = reader.read_u64_slice()?;
    let labels = reader.read_byte_slice()?;

    let mut set = SuccinctSet {
        leaves,
        label_bitmap,
        labels,
        ranks: Vec::new(),
        selects: Vec::new(),
    };

    set.init();

    Ok(DomainMatcher { set })
}

#[derive(Debug, Clone, Copy)]
pub struct Prefix {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

fn read_prefix(reader: &mut Reader<'_>) -> Result<IpRange> {
    let from = read_ip(reader)?;
    let to = read_ip(reader)?;

    Ok(IpRange { from, to })
}

fn read_default_interface_address(reader: &mut Reader<'_>) -> Result<Vec<IpRange>> {
    let count = reader.read_uvarint()?;

    let mut result = Vec::with_capacity(
        usize::try_from(count).map_err(|_| Error::Invalid("too many prefixes"))?,
    );

    for _ in 0..count {
        result.push(read_prefix(reader)?);
    }

    Ok(result)
}

fn read_network_interface_address(reader: &mut Reader<'_>) -> Result<Vec<(u8, Vec<IpRange>)>> {
    let size = reader.read_uvarint()?;

    let mut result = Vec::with_capacity(
        usize::try_from(size).map_err(|_| Error::Invalid("too many interface addresses"))?,
    );

    for _ in 0..size {
        let key = reader.read_u8()?;

        let prefix_count = reader.read_uvarint()?;

        let mut prefixes = Vec::with_capacity(
            usize::try_from(prefix_count).map_err(|_| Error::Invalid("too many prefixes"))?,
        );

        for _ in 0..prefix_count {
            prefixes.push(read_prefix(reader)?);
        }

        result.push((key, prefixes));
    }

    Ok(result)
}

#[inline]
fn mask_low_bits(n: usize) -> u64 {
    match n {
        0 => 0,
        64 => u64::MAX,
        n => (1u64 << n) - 1,
    }
}

#[inline]
fn get_bit(bitmap: &[u64], index: usize) -> u64 {
    let word = index >> 6;

    if word >= bitmap.len() {
        return 0;
    }

    (bitmap[word] >> (index & 63)) & 1
}

fn reverse_domain(domain: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len());

    for ch in domain.chars().rev() {
        let mut buf = [0u8; 4];

        result.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }

    result
}

impl SuccinctSet {
    fn init(&mut self) {
        let mut ranks = Vec::with_capacity(self.label_bitmap.len() + 1);

        let mut total = 0i32;
        ranks.push(total);

        for &word in &self.label_bitmap {
            total += word.count_ones() as i32;
            ranks.push(total);
        }

        self.ranks = ranks;

        let mut selects = Vec::new();
        let mut ones = 0usize;

        for (word_index, &word) in self.label_bitmap.iter().enumerate() {
            let mut w = word;

            while w != 0 {
                let bit = w.trailing_zeros() as usize;

                if ones & 31 == 0 {
                    selects.push((word_index * 64 + bit) as i32);
                }

                ones += 1;
                w &= w - 1;
            }
        }

        self.selects = selects;
    }

    #[inline]
    fn count_zeros(&self, index: usize) -> usize {
        let word_index = index >> 6;

        if word_index >= self.label_bitmap.len() {
            return index;
        }

        let rank = self.ranks[word_index] as usize;

        let bit = index & 63;

        let ones_inside =
            (self.label_bitmap[word_index] & mask_low_bits(bit)).count_ones() as usize;

        index - rank - ones_inside
    }

    fn select_ith_one(&self, index: usize) -> Option<usize> {
        let base_index = index / 32;

        let mut remaining = index % 32;

        let start = *self.selects.get(base_index)? as usize;

        let mut word_index = start / 64;

        let mut word = self.label_bitmap[word_index];

        word &= !0u64 << (start & 63);

        loop {
            let count = word.count_ones() as usize;

            if remaining < count {
                let bit = nth_set_bit(word, remaining)?;
                return Some(word_index * 64 + bit);
            }

            remaining -= count;
            word_index += 1;

            if word_index >= self.label_bitmap.len() {
                return None;
            }

            word = self.label_bitmap[word_index];
        }
    }
}

fn nth_set_bit(mut value: u64, n: usize) -> Option<usize> {
    let mut n = n;

    while value != 0 {
        let bit = value.trailing_zeros() as usize;

        if n == 0 {
            return Some(bit);
        }

        n -= 1;
        value &= value - 1;
    }

    None
}
impl DomainMatcher {
    fn matches(&self, domain: &str) -> bool {
        let key = reverse_domain(domain);
        self.has(&key)
    }

    fn has(&self, key: &[u8]) -> bool {
        let mut node_id = 0usize;
        let mut bm_idx = 0usize;

        for &current_char in key {
            loop {
                if get_bit(&self.set.label_bitmap, bm_idx) != 0 {
                    return false;
                }

                let label_index = bm_idx - node_id;

                if label_index >= self.set.labels.len() {
                    return false;
                }

                let next_label = self.set.labels[label_index];

                // \r = prefix
                if next_label == b'\r' {
                    return true;
                }

                // \n = root/suffix
                if next_label == b'\n' {
                    let next_node_id = self.set.count_zeros(bm_idx + 1);

                    let has_next = get_bit(&self.set.leaves, next_node_id) != 0;

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

            bm_idx = match self.set.select_ith_one(node_id - 1) {
                Some(v) => v + 1,
                None => return false,
            };
        }

        // Exact match.
        if get_bit(&self.set.leaves, node_id) != 0 {
            return true;
        }

        // Prefix/root match after complete key.
        loop {
            if get_bit(&self.set.label_bitmap, bm_idx) != 0 {
                return false;
            }

            let label_index = bm_idx - node_id;

            if label_index >= self.set.labels.len() {
                return false;
            }

            let next_label = self.set.labels[label_index];

            if next_label == b'\r' || next_label == b'\n' {
                return true;
            }

            bm_idx += 1;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IpValue {
    V4(u32),
    V6(u128),
}

impl IpSet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let value = match ip {
            IpAddr::V4(ip) => IpValue::V4(u32::from(ip)),
            IpAddr::V6(ip) => IpValue::V6(u128::from(ip)),
        };

        let index = self
            .ranges
            .partition_point(|range| range.from_value() <= value);

        index > 0 && self.ranges[index - 1].contains(ip)
    }
}

impl IpRange {
    fn from_value(&self) -> IpValue {
        match self.from {
            IpAddr::V4(ip) => IpValue::V4(u32::from(ip)),
            IpAddr::V6(ip) => IpValue::V6(u128::from(ip)),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.from, self.to, ip) {
            (IpAddr::V4(from), IpAddr::V4(to), IpAddr::V4(ip)) => {
                let from = u32::from(from);
                let to = u32::from(to);
                let ip = u32::from(ip);

                from <= ip && ip <= to
            }

            (IpAddr::V6(from), IpAddr::V6(to), IpAddr::V6(ip)) => {
                let from = u128::from(from);
                let to = u128::from(to);
                let ip = u128::from(ip);

                from <= ip && ip <= to
            }

            _ => false,
        }
    }
}

impl<'a> Reader<'a> {
    fn read_u64_slice(&mut self) -> Result<Vec<u64>> {
        let len = self.read_uvarint()?;

        let len = usize::try_from(len).map_err(|_| Error::Invalid("slice is too large"))?;

        let mut result = Vec::with_capacity(len);

        for _ in 0..len {
            let value = self.read_exact(8)?;
            result.push(u64::from_be_bytes(value.try_into().unwrap()));
        }

        Ok(result)
    }

    fn read_byte_slice(&mut self) -> Result<Vec<u8>> {
        let len = self.read_uvarint()?;

        let len = usize::try_from(len).map_err(|_| Error::Invalid("slice is too large"))?;

        Ok(self.read_exact(len)?.to_vec())
    }
}
