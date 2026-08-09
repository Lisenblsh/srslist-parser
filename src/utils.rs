use futures_util::StreamExt;
use regex::Regex;
use reqwest;
use serde::{Deserialize, Serialize};
use std::{fs::File, str};
use tokio::io::AsyncWriteExt;

pub struct SrsList {
    pub rules: Vec<Rule>,
}

impl SrsList {
    pub async fn new(url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let text = reqwest::get(url).await?.error_for_status()?.text().await?;

        let re = Regex::new(r#"\{"([^"]+)",\s*"([^"]+)"\}"#)?;

        let rules: Vec<Rule> = re
            .captures_iter(&text)
            .map(|caps| Rule {
                key: caps[1].to_owned(),
                value: caps[2].to_owned(),
            })
            .collect();

        let json = serde_json::to_string_pretty(&rules)?;

        tokio::fs::write("rules.json", json).await?;
        Ok(Self { rules })
    }

    pub async fn download_list(&self, name: &str) -> Result<String, Box<dyn std::error::Error>> {
        let rule = self
            .rules
            .iter()
            .find(|rule| rule.key == name)
            .ok_or("Rule not found")?;

        let path = format!("geodb/{}", rule.key);
        self.download_geodb(path.as_str(), rule.value.as_str())
            .await?;

        Ok(path)
    }

    async fn download_geodb(
        &self,
        filename: &str,
        url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = reqwest::get(url).await?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()).into());
        }

        let mut file = tokio::fs::File::create(filename).await?;
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk?).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Rule {
    pub key: String,
    pub value: String,
}
