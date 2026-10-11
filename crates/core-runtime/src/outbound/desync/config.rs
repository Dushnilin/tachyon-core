use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesyncPreset {
    FakeSplit,
    Split,
    Disorder,
    TlsRec,
    Fake,
    Oob,
    Auto,
}

impl FromStr for DesyncPreset {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "fake_split" | "fakesplit" => Ok(Self::FakeSplit),
            "split" => Ok(Self::Split),
            "disorder" => Ok(Self::Disorder),
            "tlsrec" | "tls_rec" => Ok(Self::TlsRec),
            "fake" => Ok(Self::Fake),
            "oob" => Ok(Self::Oob),
            "auto" => Ok(Self::Auto),
            _ => Err(format!("unknown desync preset: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesyncMode {
    FakeSplit,
    Split,
    Disorder,
    TlsRec,
    Fake,
    Oob,
    None,
}

impl FromStr for DesyncMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "fake_split" | "fakesplit" => Ok(Self::FakeSplit),
            "split" => Ok(Self::Split),
            "disorder" => Ok(Self::Disorder),
            "tlsrec" | "tls_rec" => Ok(Self::TlsRec),
            "fake" => Ok(Self::Fake),
            "oob" => Ok(Self::Oob),
            "none" | "off" | "disabled" => Ok(Self::None),
            _ => Err(format!("unknown desync mode: {s}")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SplitPos {
    Byte(usize),
    Sni,
    #[default]
    MidSld,
}

impl<'de> Deserialize<'de> for SplitPos {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SplitPosVisitor;

        impl<'de> Visitor<'de> for SplitPosVisitor {
            type Value = SplitPos;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a positive integer or 'sni' or 'midsld'")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v <= 0 {
                    return Err(E::custom("split_pos must be positive"));
                }
                Ok(SplitPos::Byte(v as usize))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v == 0 {
                    return Err(E::custom("split_pos must be positive"));
                }
                Ok(SplitPos::Byte(v as usize))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match v.to_ascii_lowercase().as_str() {
                    "sni" | "sniext" => Ok(SplitPos::Sni),
                    "midsld" | "sld" | "host" => Ok(SplitPos::MidSld),
                    other => {
                        if let Ok(n) = other.parse::<usize>()
                            && n > 0
                        {
                            return Ok(SplitPos::Byte(n));
                        }
                        Err(E::custom(format!("invalid split_pos: {v}")))
                    }
                }
            }
        }

        deserializer.deserialize_any(SplitPosVisitor)
    }
}

#[derive(Debug, Clone)]
pub struct DesyncConfig {
    pub preset: Option<DesyncPreset>,
    pub mode: DesyncMode,
    pub split_pos: SplitPos,
    pub fake_ttl: u8,
    pub fake_sni: String,
    pub fake_payload: Box<[u8]>,
    pub repeats: u32,
    pub split_delay_ms: u64,
    pub udp_fake: bool,
    pub udp_repeats: u32,
    pub udp_fake_ttl: u8,
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            preset: Some(DesyncPreset::FakeSplit),
            mode: DesyncMode::FakeSplit,
            split_pos: SplitPos::MidSld,
            fake_ttl: 6,
            fake_sni: "www.google.com".to_string(),
            fake_payload: super::payload::build_fake_tls_client_hello("www.google.com")
                .into_boxed_slice(),
            repeats: 1,
            split_delay_ms: 1,
            udp_fake: true,
            udp_repeats: 3,
            udp_fake_ttl: 6,
        }
    }
}

impl DesyncConfig {
    pub fn from_json(obj: &serde_json::Map<String, serde_json::Value>) -> Result<Self, String> {
        let preset: Option<DesyncPreset> = if let Some(p) = obj.get("preset") {
            if let Some(s) = p.as_str() {
                Some(DesyncPreset::from_str(s)?)
            } else {
                return Err("preset must be a string".to_string());
            }
        } else {
            None
        };

        let mut config = Self::default();

        if let Some(p) = preset {
            config.preset = Some(p);
            match p {
                DesyncPreset::FakeSplit | DesyncPreset::Auto => {
                    config.mode = DesyncMode::FakeSplit;
                    config.split_pos = SplitPos::MidSld;
                    config.fake_ttl = 6;
                    config.udp_fake = true;
                }
                DesyncPreset::Split => {
                    config.mode = DesyncMode::Split;
                    config.split_pos = SplitPos::MidSld;
                    config.udp_fake = false;
                }
                DesyncPreset::Disorder => {
                    config.mode = DesyncMode::Disorder;
                    config.split_pos = SplitPos::Byte(1);
                    config.udp_fake = false;
                }
                DesyncPreset::TlsRec => {
                    config.mode = DesyncMode::TlsRec;
                    config.split_pos = SplitPos::Sni;
                    config.udp_fake = false;
                }
                DesyncPreset::Fake => {
                    config.mode = DesyncMode::Fake;
                    config.fake_ttl = 6;
                    config.udp_fake = true;
                }
                DesyncPreset::Oob => {
                    config.mode = DesyncMode::Oob;
                    config.split_pos = SplitPos::Byte(1);
                    config.udp_fake = false;
                }
            }
        }

        if let Some(m) = obj.get("mode") {
            if let Some(s) = m.as_str() {
                config.mode = DesyncMode::from_str(s)?;
            } else {
                return Err("mode must be a string".to_string());
            }
        }

        if let Some(sp) = obj.get("split_pos") {
            config.split_pos = serde_json::from_value(sp.clone())
                .map_err(|e| format!("invalid split_pos: {e}"))?;
        }

        if let Some(ttl) = obj.get("fake_ttl") {
            if let Some(n) = ttl.as_u64() {
                if !(1..=128).contains(&n) {
                    return Err("fake_ttl must be between 1 and 128".to_string());
                }
                config.fake_ttl = n as u8;
            } else {
                return Err("fake_ttl must be an integer".to_string());
            }
        }

        if let Some(sni) = obj.get("fake_sni") {
            if let Some(s) = sni.as_str() {
                if s.is_empty() {
                    return Err("fake_sni cannot be empty".to_string());
                }
                config.fake_sni = s.to_string();
            } else {
                return Err("fake_sni must be a string".to_string());
            }
        }

        if let Some(rep) = obj.get("repeats") {
            if let Some(n) = rep.as_u64() {
                config.repeats = n.clamp(1, 100) as u32;
            } else {
                return Err("repeats must be an integer".to_string());
            }
        }

        if let Some(delay) = obj.get("split_delay_ms") {
            if let Some(n) = delay.as_u64() {
                config.split_delay_ms = n.min(1000);
            } else {
                return Err("split_delay_ms must be an integer".to_string());
            }
        }

        if let Some(uf) = obj.get("udp_fake") {
            if let Some(b) = uf.as_bool() {
                config.udp_fake = b;
            } else {
                return Err("udp_fake must be a boolean".to_string());
            }
        }

        if let Some(urep) = obj.get("udp_repeats") {
            if let Some(n) = urep.as_u64() {
                config.udp_repeats = n.clamp(1, 50) as u32;
            } else {
                return Err("udp_repeats must be an integer".to_string());
            }
        }

        if let Some(uttl) = obj.get("udp_fake_ttl") {
            if let Some(n) = uttl.as_u64() {
                config.udp_fake_ttl = n.clamp(1, 128) as u8;
            } else {
                return Err("udp_fake_ttl must be an integer".to_string());
            }
        }

        config.fake_payload =
            super::payload::build_fake_tls_client_hello(&config.fake_sni).into_boxed_slice();

        Ok(config)
    }
}
