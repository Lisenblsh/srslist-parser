use std::{
    error::Error as StdError,
    fmt,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use flate2::read::ZlibDecoder;

const SRS_MAGIC: &[u8; 3] = b"SRS";
const RULE_TYPE_DEFAULT: u8 = 0;
const RULE_ITEM_IP_CIDR: u8 = 6;
const RULE_ITEM_FINAL: u8 = 0xff;
const IPSET_VERSION: u8 = 1;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Invalid(&'static str),
    UnsupportedVersion(u8),
    UnsupportedRuleType(u8),
    UnsupportedRuleItem(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Invalid(msg) => write!(f, "invalid SRS: {msg}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "unsupported SRS version: {v}")
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

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy)]
struct Ipv4Range {
    from: u32,
    to: u32,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6Range {
    from: u128,
    to: u128,
}

#[derive(Debug)]
pub struct SrsGeoIp {
    ipv4: Vec<Ipv4Range>,
    ipv6: Vec<Ipv6Range>,
}

impl SrsGeoIp {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::parse(&data)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(data);

        let magic = reader.read_exact(3)?;

        if magic != SRS_MAGIC {
            return Err(Error::Invalid("invalid SRS magic"));
        }

        let version = reader.read_u8()?;

        // Для твоего ru.srs это 2.
        //
        // Сам формат SRS сейчас имеет несколько версий,
        // но для IP CIDR структура IPSet здесь одинаковая.
        if version == 0 {
            return Err(Error::Invalid("invalid SRS version"));
        }

        let compressed = reader.remaining();

        let mut decoder = ZlibDecoder::new(compressed);

        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;

        let mut reader = Reader::new(&decompressed);

        let rule_count = reader.read_uvarint()?;

        if rule_count != 1 {
            return Err(Error::Invalid("expected exactly one rule in GeoIP SRS"));
        }

        let rule_type = reader.read_u8()?;

        if rule_type != RULE_TYPE_DEFAULT {
            return Err(Error::UnsupportedRuleType(rule_type));
        }

        let mut result = SrsGeoIp {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };

        loop {
            let item_type = reader.read_u8()?;

            match item_type {
                RULE_ITEM_IP_CIDR => {
                    let ipset = read_ipset(&mut reader)?;

                    result.ipv4.extend(ipset.ipv4);
                    result.ipv6.extend(ipset.ipv6);
                }

                RULE_ITEM_FINAL => {
                    let invert = reader.read_u8()?;

                    if invert != 0 {
                        return Err(Error::Invalid("inverted GeoIP rule is not supported"));
                    }

                    break;
                }

                item => {
                    return Err(Error::UnsupportedRuleItem(item));
                }
            }
        }

        Ok(result)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let value = u32::from(ip);

                self.ipv4
                    .binary_search_by(|range| {
                        if value < range.from {
                            std::cmp::Ordering::Greater
                        } else if value > range.to {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }

            IpAddr::V6(ip) => {
                let value = u128::from(ip);

                self.ipv6
                    .binary_search_by(|range| {
                        if value < range.from {
                            std::cmp::Ordering::Greater
                        } else if value > range.to {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Equal
                        }
                    })
                    .is_ok()
            }
        }
    }

    pub fn ipv4_ranges(&self) -> usize {
        self.ipv4.len()
    }

    pub fn ipv6_ranges(&self) -> usize {
        self.ipv6.len()
    }
}

struct IpSet {
    ipv4: Vec<Ipv4Range>,
    ipv6: Vec<Ipv6Range>,
}

fn read_ipset(reader: &mut Reader<'_>) -> Result<IpSet> {
    let version = reader.read_u8()?;

    if version != IPSET_VERSION {
        return Err(Error::Invalid("unsupported IPSet version"));
    }

    let count = reader.read_u64_be()?;

    let count = usize::try_from(count).map_err(|_| Error::Invalid("IPSet is too large"))?;

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    ipv4.reserve(count);
    ipv6.reserve(count);

    for _ in 0..count {
        let from = reader.read_bytes()?;
        let to = reader.read_bytes()?;

        match (from.len(), to.len()) {
            (4, 4) => {
                let from = u32::from_be_bytes(from.try_into().unwrap());
                let to = u32::from_be_bytes(to.try_into().unwrap());

                ipv4.push(Ipv4Range { from, to });
            }

            (16, 16) => {
                let from = u128::from_be_bytes(from.try_into().unwrap());
                let to = u128::from_be_bytes(to.try_into().unwrap());

                ipv6.push(Ipv6Range { from, to });
            }

            _ => {
                return Err(Error::Invalid(
                    "IP range must contain either 4 or 16 byte addresses",
                ));
            }
        }
    }

    Ok(IpSet { ipv4, ipv6 })
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
            return Err(Error::Invalid("unexpected EOF"));
        }

        let value = self.data[self.pos];
        self.pos += 1;

        Ok(value)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return Err(Error::Invalid("unexpected EOF"));
        }

        let result = &self.data[self.pos..self.pos + len];

        self.pos += len;

        Ok(result)
    }

    fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self.read_exact(8)?;

        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn read_uvarint(&mut self) -> Result<u64> {
        let mut result = 0u64;

        for shift in (0..64).step_by(7) {
            let byte = self.read_u8()?;

            let value = (byte & 0x7f) as u64;

            result |= value << shift;

            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }

        Err(Error::Invalid("invalid uvarint"))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_uvarint()?;

        let len = usize::try_from(len).map_err(|_| Error::Invalid("byte array is too large"))?;

        self.read_exact(len)
    }
}
