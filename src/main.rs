use std::net::IpAddr;
use std::result::Result;

mod parser;
mod utils;

use parser::geoip::SrsGeoIp;
use parser::geosite::SrsGeoSite;
use parser::srs::{Rule, RuleItem, Srs};
use utils::SrsList;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = "https://raw.githubusercontent.com/throneproj/routeprofiles/rule-set/srslist.h";
    let srsl = SrsList::new(url).await?;
    let mut name = "geoip-ru";
    let mut path = srsl.download_list(name).await?;

    // Версия по докам
    let mut srs = Srs::open(path)?;

    println!("SRS version: {}", srs.version);
    println!("rules: {}", srs.rules.len());

    let ip: IpAddr = "77.88.44.55".parse()?;

    for rule in &srs.rules {
        if let Rule::Default(rule) = rule {
            for item in &rule.items {
                if let RuleItem::IpCidr(ipset) = item {
                    println!("ip: {}", ipset.contains(ip));
                }
            }
        }
    }

    name = "geosite-ru-blocked";
    path = srsl.download_list(name).await?;

    // Версия по докам
    let geosite = SrsGeoSite::open(path)?;
    let (domains, prefixes) = geosite.list();

    println!("=== Exact domains ({}) ===", domains.len());
    for d in &domains {
        println!("  {d}");
    }

    println!("\n=== Domain suffixes / prefixes ({}) ===", prefixes.len());
    for p in &prefixes {
        println!("  {p}");
    }

    println!("{}", geosite.contains("googlevideo.com"));

    // Первая версия
    /*if name.starts_with("geoip") {
        match SrsGeoIp::open(&path) {
            Ok(geoip) => {
                println!("1.1.1.1: {}", geoip.contains("1.1.1.1".parse()?));
                println!("77.88.44.55: {}", geoip.contains("77.88.44.55".parse()?));
            }
            Err(err) => {
                println!("{err}");
            }
        }
    } else if name.starts_with("geosite") {
        match SrsGeoSite::open(&path) {
            Ok(geo) => {
                println!("yandex.ru:  {}", geo.contains("yandex.ru"));
                println!("vk.ru:  {}", geo.contains("vk.ru"));
                println!("google.com: {}", geo.contains("google.com"));
                println!("chatgpt.com: {}", geo.contains("chatgpt.com"));
            }
            Err(err) => {
                println!("{err}");
            }
        }
    } else {
        println!("name non correct");
    }*/

    //Проверка SrsGeoIp и SrsGeoSite на работоспособность
    /*for ele in srsl.rules.iter() {
        println!("{}", ele.key);
        let path = srsl.download_list(ele.key.as_str()).await?;
        if ele.key.starts_with("geoip") {
            match SrsGeoIp::open(&path) {
                Ok(geoip) => {
                    println!("1.1.1.1: {}", geoip.contains("1.1.1.1".parse()?));
                    println!("IPv4 ranges: {}", geoip.ipv4_ranges());
                    println!("IPv6 ranges: {}", geoip.ipv6_ranges());
                }
                Err(err) => {
                    println!("{err}");
                }
            }
        } else if ele.key.starts_with("geosite") {
            match SrsGeoSite::open(&path) {
                Ok(geo) => {
                    println!("example.com:  {}", geo.contains("example.com"));
                }
                Err(err) => {
                    println!("{err}");
                }
            }
        } else {
            println!("{}: {}", ele.key, ele.value);
        }
        tokio::fs::remove_file(path).await?;
    }*/

    Ok(())
}
