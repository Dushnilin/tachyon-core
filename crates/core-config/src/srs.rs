//! SRS — the sing-box binary rule-set container (`common/srs`).
//!
//! Layout: the `SRS` magic, a version byte, a zlib stream (best compression
//! upstream) holding a varint rule count and the encoded rules. Rules are
//! either a `default` headless rule (a tagged item list terminated by
//! `final` + `invert`) or a `logical` rule (`mode` + nested rules). The
//! zlib *bytes* differ between deflate implementations, so this module
//! guarantees wire compatibility of the payload, not of the container:
//! a file written here is read by the reference and the other way round.

use std::io::{Read, Write};

use serde_json::{Map, Value};

pub const MAGIC: [u8; 3] = [0x53, 0x52, 0x53];
pub const VERSION_CURRENT: u8 = 5;

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
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xFF;

const MAX_LOGICAL_DEPTH: usize = 100;
/// `prefixLabel` / `rootLabel` of sing's domain matcher.
const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

// ------------------------------------------------------------------ reading

/// Parse an SRS container into its rules (`Vec<Value>` of headless rules).
pub fn read(data: &[u8]) -> Result<Vec<Value>, String> {
    if data.len() < 4 || data[..3] != MAGIC {
        return Err("invalid sing-box rule-set file".to_string());
    }
    let version = data[3];
    if version > VERSION_CURRENT {
        return Err(format!("unsupported version: {version}"));
    }
    let mut decoder = flate2::read::ZlibDecoder::new(&data[4..]);
    let mut payload = Vec::new();
    decoder
        .read_to_end(&mut payload)
        .map_err(|err| format!("decompress rule-set: {err}"))?;
    let mut reader = Reader::new(&payload);
    let count = reader.uvarint()?;
    let mut rules = Vec::with_capacity(count as usize);
    for index in 0..count {
        rules.push(
            read_rule(&mut reader, version, 0)
                .map_err(|err| format!("read rule[{index}]: {err}"))?,
        );
    }
    Ok(rules)
}

/// Read an SRS container and report the version it was written with.
pub fn read_with_version(data: &[u8]) -> Result<(u8, Vec<Value>), String> {
    if data.len() < 4 || data[..3] != MAGIC {
        return Err("invalid sing-box rule-set file".to_string());
    }
    Ok((data[3], read(data)?))
}

fn read_rule(reader: &mut Reader<'_>, version: u8, depth: usize) -> Result<Value, String> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err("logical rule nested too deep".to_string());
    }
    let rule_type = reader.u8()?;
    let mut rule = Map::new();
    match rule_type {
        0 => {
            read_default_rule(reader, version, &mut rule)?;
        }
        1 => {
            rule.insert("type".into(), Value::String("logical".into()));
            let mode = reader.u8()?;
            rule.insert(
                "mode".into(),
                Value::String(match mode {
                    0 => "and".to_string(),
                    1 => "or".to_string(),
                    other => return Err(format!("unknown logical mode: {other}")),
                }),
            );
            let count = reader.uvarint()?;
            let mut rules = Vec::with_capacity(count as usize);
            for index in 0..count {
                rules.push(read_rule(reader, version, depth + 1)?);
                let _ = index;
            }
            rule.insert("rules".into(), Value::Array(rules));
            if reader.u8()? != 0 {
                rule.insert("invert".into(), Value::Bool(true));
            }
        }
        other => return Err(format!("unknown rule type: {other}")),
    }
    Ok(Value::Object(rule))
}

fn read_default_rule(
    reader: &mut Reader<'_>,
    version: u8,
    rule: &mut Map<String, Value>,
) -> Result<(), String> {
    let mut last_item = 0u8;
    loop {
        let item = reader.u8()?;
        match item {
            ITEM_QUERY_TYPE => {
                let values = reader.u16_vec()?;
                let names: Vec<Value> = values
                    .into_iter()
                    .map(|value| Value::String(query_type_name(value).to_string()))
                    .collect();
                rule.insert("query_type".into(), Value::Array(names));
            }
            ITEM_NETWORK => {
                rule.insert("network".into(), Value::Array(reader.str_values()?));
            }
            ITEM_DOMAIN => {
                let (domains, suffixes) = read_domain_matcher(reader, version == 1)?;
                if !domains.is_empty() {
                    rule.insert("domain".into(), Value::Array(domains));
                }
                if !suffixes.is_empty() {
                    rule.insert("domain_suffix".into(), Value::Array(suffixes));
                }
            }
            ITEM_DOMAIN_KEYWORD => {
                rule.insert("domain_keyword".into(), Value::Array(reader.str_values()?));
            }
            ITEM_DOMAIN_REGEX => {
                rule.insert("domain_regex".into(), Value::Array(reader.str_values()?));
            }
            ITEM_SOURCE_IP_CIDR => {
                rule.insert("source_ip_cidr".into(), read_ip_set(reader)?);
            }
            ITEM_IP_CIDR => {
                rule.insert("ip_cidr".into(), read_ip_set(reader)?);
            }
            ITEM_SOURCE_PORT => {
                rule.insert("source_port".into(), port_values(reader.u16_vec()?));
            }
            ITEM_SOURCE_PORT_RANGE => {
                rule.insert(
                    "source_port_range".into(),
                    Value::Array(reader.str_values()?),
                );
            }
            ITEM_PORT => {
                rule.insert("port".into(), port_values(reader.u16_vec()?));
            }
            ITEM_PORT_RANGE => {
                rule.insert("port_range".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PROCESS_NAME => {
                rule.insert("process_name".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PROCESS_PATH => {
                rule.insert("process_path".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PROCESS_PATH_REGEX => {
                rule.insert(
                    "process_path_regex".into(),
                    Value::Array(reader.str_values()?),
                );
            }
            ITEM_PACKAGE_NAME => {
                rule.insert("package_name".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PACKAGE_NAME_REGEX => {
                rule.insert(
                    "package_name_regex".into(),
                    Value::Array(reader.str_values()?),
                );
            }
            ITEM_WIFI_SSID => {
                rule.insert("wifi_ssid".into(), Value::Array(reader.str_values()?));
            }
            ITEM_WIFI_BSSID => {
                rule.insert("wifi_bssid".into(), Value::Array(reader.str_values()?));
            }
            ITEM_ADGUARD_DOMAIN => {
                let list = read_adguard_matcher(reader)?;
                if !list.is_empty() {
                    rule.insert("domain_keyword".into(), Value::Array(list));
                }
            }
            ITEM_NETWORK_TYPE => {
                let values = reader.u8_vec()?;
                let names: Vec<Value> = values
                    .into_iter()
                    .map(|value| Value::String(network_type_name(value).to_string()))
                    .collect();
                rule.insert("network_type".into(), Value::Array(names));
            }
            ITEM_NETWORK_IS_EXPENSIVE => {
                rule.insert("network_is_expensive".into(), Value::Bool(true));
            }
            ITEM_NETWORK_IS_CONSTRAINED => {
                rule.insert("network_is_constrained".into(), Value::Bool(true));
            }
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                let count = reader.uvarint()?;
                let mut map = Map::new();
                for _ in 0..count {
                    let key = reader.u8()?;
                    let prefixes = reader.prefix_vec()?;
                    map.insert(network_type_name(key).to_string(), Value::Array(prefixes));
                }
                rule.insert("network_interface_address".into(), Value::Object(map));
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => {
                let prefixes = reader.prefix_vec()?;
                rule.insert("default_interface_address".into(), Value::Array(prefixes));
            }
            ITEM_FINAL => {
                let invert = reader.u8()? != 0;
                if invert {
                    rule.insert("invert".into(), Value::Bool(true));
                }
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown rule item type: {other}, last type: {last_item}"
                ));
            }
        }
        last_item = item;
    }
}

fn query_type_name(value: u16) -> &'static str {
    match value {
        1 => "A",
        2 => "AAAA",
        28 => "HTTPS",
        65 => "HTTPS",
        _ => "A",
    }
}

fn network_type_name(value: u8) -> &'static str {
    match value {
        0 => "wifi",
        1 => "cellular",
        2 => "ethernet",
        3 => "other",
        _ => "",
    }
}

// ------------------------------------------------------------------ writing

/// `downgradeRuleSetVersion`: the reference compiler lowers the container
/// version to the oldest one that still carries every rule item.
pub fn downgrade_version(value: &Value, version: u8) -> u8 {
    let rules: Vec<Value> = value
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has = |field: &str| {
        rules.iter().any(|rule| {
            rule.get(field)
                .is_some_and(|value| !listable(Some(value)).unwrap_or_default().is_empty())
                || rule.get(field) == Some(&Value::Bool(true))
        })
    };
    let mut version = version;
    if version == 5 && !has("package_name_regex") {
        version = 4;
    }
    if version == 4 && !has("network_interface_address") && !has("default_interface_address") {
        version = 3;
    }
    if version == 3
        && !has("network_type")
        && !has("network_is_expensive")
        && !has("network_is_constrained")
    {
        version = 2;
    }
    version
}

/// Compile a source rule-set (`{version, rules}` or `{rules}`) into an SRS
/// container.
pub fn compile(value: &Value, version: u8) -> Result<Vec<u8>, String> {
    if version == 0 || version > VERSION_CURRENT {
        return Err(format!("unknown rule-set version: {version}"));
    }
    let rules = match value.get("rules") {
        Some(Value::Array(rules)) => rules.clone(),
        Some(other) => return Err(format!("rules must be an array, got {}", kind(other))),
        None => Vec::new(),
    };
    let mut writer = Writer::default();
    writer.uvarint(rules.len() as u64);
    for rule in &rules {
        write_rule(&mut writer, rule, version)?;
    }
    let mut payload = Vec::new();
    flate2::write::ZlibEncoder::new(&mut payload, flate2::Compression::best())
        .write_all(&writer.out)
        .map_err(|err| format!("compress rule-set: {err}"))?;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&MAGIC);
    out.push(version);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn write_rule(writer: &mut Writer, rule: &Value, version: u8) -> Result<(), String> {
    let rule = rule
        .as_object()
        .ok_or_else(|| "rule must be an object".to_string())?;
    let rule_type = rule
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("default");
    match rule_type {
        "default" => {
            writer.u8(0);
            write_default_rule(writer, rule, version)
        }
        "logical" => {
            writer.u8(1);
            let mode = match rule
                .get("mode")
                .and_then(Value::as_str)
                .ok_or_else(|| "logical rule is missing mode".to_string())?
            {
                "and" => 0u8,
                "or" => 1u8,
                other => return Err(format!("unknown logical mode: {other}")),
            };
            writer.u8(mode);
            let rules = rule
                .get("rules")
                .and_then(Value::as_array)
                .ok_or_else(|| "logical rule is missing rules".to_string())?;
            writer.uvarint(rules.len() as u64);
            for sub in rules {
                write_rule(writer, sub, version)?;
            }
            writer.u8(u8::from(rule.get("invert") == Some(&Value::Bool(true))));
            Ok(())
        }
        other => Err(format!("unknown rule type: {other}")),
    }
}

fn write_default_rule(
    writer: &mut Writer,
    rule: &Map<String, Value>,
    version: u8,
) -> Result<(), String> {
    if let Some(values) = rule.get("query_type") {
        let mut encoded = Vec::new();
        for value in strings(values)? {
            encoded.push(query_type_code(&value)?);
        }
        writer.item_u16_vec(ITEM_QUERY_TYPE, &encoded);
    }
    if let Some(values) = rule.get("network") {
        writer.item_str_vec(ITEM_NETWORK, &strings(values)?);
    }
    let domains = listable(rule.get("domain"))?;
    let suffixes = listable(rule.get("domain_suffix"))?;
    if !domains.is_empty() || !suffixes.is_empty() {
        writer.u8(ITEM_DOMAIN);
        write_domain_matcher(writer, &domains, &suffixes, version == 1)?;
    }
    if let Some(values) = rule.get("domain_keyword") {
        writer.item_str_vec(ITEM_DOMAIN_KEYWORD, &strings(values)?);
    }
    if let Some(values) = rule.get("domain_regex") {
        writer.item_str_vec(ITEM_DOMAIN_REGEX, &strings(values)?);
    }
    if let Some(values) = rule.get("source_ip_cidr") {
        writer.item_ip_set(ITEM_SOURCE_IP_CIDR, &strings(values)?);
    }
    if let Some(values) = rule.get("ip_cidr") {
        writer.item_ip_set(ITEM_IP_CIDR, &strings(values)?);
    }
    if let Some(values) = rule.get("source_port") {
        writer.item_u16_vec(ITEM_SOURCE_PORT, &ports(values)?);
    }
    if let Some(values) = rule.get("source_port_range") {
        writer.item_str_vec(ITEM_SOURCE_PORT_RANGE, &strings(values)?);
    }
    if let Some(values) = rule.get("port") {
        writer.item_u16_vec(ITEM_PORT, &ports(values)?);
    }
    if let Some(values) = rule.get("port_range") {
        writer.item_str_vec(ITEM_PORT_RANGE, &strings(values)?);
    }
    if let Some(values) = rule.get("process_name") {
        writer.item_str_vec(ITEM_PROCESS_NAME, &strings(values)?);
    }
    if let Some(values) = rule.get("process_path") {
        writer.item_str_vec(ITEM_PROCESS_PATH, &strings(values)?);
    }
    if let Some(values) = rule.get("process_path_regex") {
        writer.item_str_vec(ITEM_PROCESS_PATH_REGEX, &strings(values)?);
    }
    if let Some(values) = rule.get("package_name") {
        writer.item_str_vec(ITEM_PACKAGE_NAME, &strings(values)?);
    }
    if let Some(values) = rule.get("package_name_regex")
        && !listable(Some(values))?.is_empty()
    {
        if version < 5 {
            return Err(
                "`package_name_regex` rule item is only supported in version 5 or later".into(),
            );
        }
        writer.item_str_vec(ITEM_PACKAGE_NAME_REGEX, &strings(values)?);
    }
    if let Some(values) = rule.get("network_type") {
        let list = listable(Some(values))?;
        if !list.is_empty() {
            if version < 3 {
                return Err(
                    "`network_type` rule item is only supported in version 3 or later".into(),
                );
            }
            let mut encoded = Vec::new();
            for value in &list {
                encoded.push(network_type_code(value)?);
            }
            writer.item_u8_vec(ITEM_NETWORK_TYPE, &encoded);
        }
    }
    if rule.get("network_is_expensive") == Some(&Value::Bool(true)) {
        if version < 3 {
            return Err(
                "`network_is_expensive` rule item is only supported in version 3 or later".into(),
            );
        }
        writer.u8(ITEM_NETWORK_IS_EXPENSIVE);
    }
    if rule.get("network_is_constrained") == Some(&Value::Bool(true)) {
        if version < 3 {
            return Err(
                "`network_is_constrained` rule item is only supported in version 3 or later".into(),
            );
        }
        writer.u8(ITEM_NETWORK_IS_CONSTRAINED);
    }
    if let Some(Value::Object(map)) = rule.get("network_interface_address")
        && !map.is_empty()
    {
        if version < 4 {
            return Err(
                "`network_interface_address` rule item is only supported in version 4 or later"
                    .into(),
            );
        }
        writer.u8(ITEM_NETWORK_INTERFACE_ADDRESS);
        writer.uvarint(map.len() as u64);
        for (key, value) in map {
            let code = network_type_code(key)?;
            writer.u8(code);
            let prefixes = listable(Some(value))?;
            writer.uvarint(prefixes.len() as u64);
            for prefix in &prefixes {
                write_prefix(writer, prefix)?;
            }
        }
    }
    if let Some(values) = rule.get("default_interface_address") {
        let prefixes = listable(Some(values))?;
        if !prefixes.is_empty() {
            if version < 4 {
                return Err(
                    "`default_interface_address` rule item is only supported in version 4 or later"
                        .into(),
                );
            }
            writer.u8(ITEM_DEFAULT_INTERFACE_ADDRESS);
            writer.uvarint(prefixes.len() as u64);
            for prefix in &prefixes {
                write_prefix(writer, prefix)?;
            }
        }
    }
    if let Some(values) = rule.get("wifi_ssid") {
        writer.item_str_vec(ITEM_WIFI_SSID, &strings(values)?);
    }
    if let Some(values) = rule.get("wifi_bssid") {
        writer.item_str_vec(ITEM_WIFI_BSSID, &strings(values)?);
    }
    writer.u8(ITEM_FINAL);
    writer.u8(u8::from(rule.get("invert") == Some(&Value::Bool(true))));
    Ok(())
}

// ------------------------------------------------------------- domain trie

/// `domain.NewMatcher(...).Write`: the succinct set of reversed domain keys.
fn write_domain_matcher(
    writer: &mut Writer,
    domains: &[String],
    suffixes: &[String],
    legacy: bool,
) -> Result<(), String> {
    let mut list: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for suffix in suffixes {
        if seen.iter().any(|entry| entry == suffix) {
            continue;
        }
        seen.push(suffix.clone());
        if suffix.starts_with('.') {
            list.push(reverse_domain(&format!("{}{suffix}", PREFIX_LABEL as char)));
        } else if legacy {
            list.push(reverse_domain(suffix));
            let dotted = format!(".{suffix}");
            if !seen.contains(&dotted) {
                seen.push(dotted.clone());
                list.push(reverse_domain(&format!("{}{dotted}", PREFIX_LABEL as char)));
            }
        } else {
            list.push(reverse_domain(&format!("{}{suffix}", ROOT_LABEL as char)));
        }
    }
    for domain in domains {
        if seen.iter().any(|entry| entry == domain) {
            continue;
        }
        seen.push(domain.clone());
        list.push(reverse_domain(domain));
    }
    list.sort();
    let set = SuccinctSet::build(&list);
    writer.u8(0);
    writer.u64_slice(&set.leaves);
    writer.u64_slice(&set.label_bitmap);
    writer.bytes(&set.labels);
    Ok(())
}

/// `domain.Matcher.Dump()`: un-reverse every key and split it by its label.
fn read_domain_matcher(
    reader: &mut Reader<'_>,
    _legacy: bool,
) -> Result<(Vec<Value>, Vec<Value>), String> {
    let _version = reader.u8()?;
    let leaves = reader.u64_slice()?;
    let label_bitmap = reader.u64_slice()?;
    let labels = reader.bytes()?;
    let set = SuccinctSet {
        leaves,
        label_bitmap,
        labels,
    };
    let mut domains: Vec<String> = Vec::new();
    let mut prefixes: Vec<String> = Vec::new();
    for key in set.keys()? {
        let key = reverse_domain(&key);
        let Some(label) = key.as_bytes().first().copied() else {
            continue;
        };
        match label {
            PREFIX_LABEL => {
                let raw = key[1..].to_string();
                // a prefix that also exists as an exact domain is a suffix only
                if let Some(root) = raw.strip_prefix('.') {
                    let root = root.to_string();
                    if domains.contains(&root) {
                        domains.retain(|domain| *domain != root);
                        prefixes.push(root);
                        continue;
                    }
                }
                prefixes.push(raw);
            }
            ROOT_LABEL => prefixes.push(key[1..].to_string()),
            _ => domains.push(key),
        }
    }
    domains.sort();
    prefixes.sort();
    Ok((
        domains.into_iter().map(Value::String).collect(),
        prefixes.into_iter().map(Value::String).collect(),
    ))
}

/// The AdGuard matcher is a plain string list upstream.
fn read_adguard_matcher(reader: &mut Reader<'_>) -> Result<Vec<Value>, String> {
    reader.str_values()
}

/// sing's `succinctSet`, bit for bit (`common/domain/set.go`).
struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
}

impl SuccinctSet {
    fn build(keys: &[String]) -> Self {
        struct Element {
            start: usize,
            end: usize,
            column: usize,
        }
        let mut leaves: Vec<u64> = Vec::new();
        let mut label_bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();
        let mut label_index = 0usize;
        let mut queue = vec![Element {
            start: 0,
            end: keys.len(),
            column: 0,
        }];
        let mut index = 0usize;
        while index < queue.len() {
            let element = &queue[index];
            let mut start = element.start;
            let end = element.end;
            let column = element.column;
            if column == keys[element.start].len() {
                set_bit(&mut leaves, index, 1);
                start += 1;
            }
            let mut cursor = start;
            while cursor < end {
                let from = cursor;
                let first = keys[from].as_bytes()[column];
                while cursor < end && keys[cursor].as_bytes()[column] == first {
                    cursor += 1;
                }
                queue.push(Element {
                    start: from,
                    end: cursor,
                    column: column + 1,
                });
                labels.push(first);
                set_bit(&mut label_bitmap, label_index, 0);
                label_index += 1;
            }
            set_bit(&mut label_bitmap, label_index, 1);
            label_index += 1;
            index += 1;
        }
        Self {
            leaves,
            label_bitmap,
            labels,
        }
    }

    /// `succinctSet.keys()`: walk the set back into its keys.
    fn keys(&self) -> Result<Vec<String>, String> {
        let mut result = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        self.traverse(0, 0, &mut current, &mut result);
        Ok(result)
    }

    fn traverse(
        &self,
        node_id: usize,
        bitmap_index: usize,
        current: &mut Vec<u8>,
        result: &mut Vec<String>,
    ) {
        if get_bit(&self.leaves, node_id) != 0 {
            result.push(String::from_utf8_lossy(current).to_string());
        }
        let mut cursor = bitmap_index;
        while get_bit(&self.label_bitmap, cursor) == 0 {
            let Some(label) = self.labels.get(cursor.saturating_sub(node_id)).copied() else {
                return;
            };
            current.push(label);
            let next_node = count_zeros(&self.label_bitmap, cursor + 1);
            let next_bitmap = match select_ith_one(&self.label_bitmap, next_node.saturating_sub(1))
            {
                Some(index) => index + 1,
                None => {
                    current.pop();
                    return;
                }
            };
            self.traverse(next_node, next_bitmap, current, result);
            current.pop();
            cursor += 1;
        }
    }
}

fn set_bit(bits: &mut Vec<u64>, index: usize, value: u64) {
    let word = index >> 6;
    while word >= bits.len() {
        bits.push(0);
    }
    bits[word] |= value << (index & 63);
}

fn get_bit(bits: &[u64], index: usize) -> u64 {
    let word = index >> 6;
    if word >= bits.len() {
        return 0;
    }
    (bits[word] >> (index & 63)) & 1
}

/// `countZeros(bm, i)` = `i - popcount(bm[0..i))`.
fn count_zeros(bits: &[u64], index: usize) -> usize {
    let mut ones = 0usize;
    for (word_index, word) in bits.iter().enumerate() {
        let start = word_index * 64;
        if start >= index {
            break;
        }
        let end = (index - start).min(64);
        let mask = if end == 0 {
            0
        } else if end >= 64 {
            u64::MAX
        } else {
            (1u64 << end) - 1
        };
        ones += (word & mask).count_ones() as usize;
    }
    index - ones
}

/// `selectIthOne(bm, i)`: the bit index of the `i`-th set bit.
fn select_ith_one(bits: &[u64], index: usize) -> Option<usize> {
    let mut seen = 0usize;
    for (word_index, word) in bits.iter().enumerate() {
        let mut word = *word;
        while word != 0 {
            let bit = word.trailing_zeros() as usize;
            if seen == index {
                return Some(word_index * 64 + bit);
            }
            seen += 1;
            word &= word - 1;
        }
    }
    None
}

// ------------------------------------------------------------- ip encoding

fn write_prefix(writer: &mut Writer, prefix: &str) -> Result<(), String> {
    let (addr, bits) = split_prefix(prefix)?;
    write_addr(writer, &addr);
    writer.u8(bits);
    Ok(())
}

fn write_addr(writer: &mut Writer, addr: &std::net::IpAddr) {
    let bytes = match addr {
        std::net::IpAddr::V4(addr) => addr.octets().to_vec(),
        std::net::IpAddr::V6(addr) => addr.octets().to_vec(),
    };
    writer.uvarint(bytes.len() as u64);
    writer.out.extend_from_slice(&bytes);
}

fn read_ip_set(reader: &mut Reader<'_>) -> Result<Value, String> {
    let version = reader.u8()?;
    if version != 1 {
        return Err("invalid IP set version".to_string());
    }
    let count = reader.u64()?;
    let mut ranges = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let from = read_addr(reader)?;
        let to = read_addr(reader)?;
        ranges.push((from, to));
    }
    // the reference stores merged ranges; rebuild the covered prefixes
    let mut prefixes: Vec<String> = Vec::new();
    for (from, to) in ranges {
        prefixes.extend(range_to_prefixes(&from, &to));
    }
    Ok(Value::Array(
        prefixes.into_iter().map(Value::String).collect(),
    ))
}

fn read_addr(reader: &mut Reader<'_>) -> Result<std::net::IpAddr, String> {
    let len = reader.uvarint()?;
    if len != 4 && len != 16 {
        return Err("invalid IP set address".to_string());
    }
    let bytes = reader.take(len as usize)?;
    match bytes.len() {
        4 => {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(bytes);
            Ok(std::net::IpAddr::from(raw))
        }
        _ => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(bytes);
            Ok(std::net::IpAddr::from(raw))
        }
    }
}

fn range_to_prefixes(from: &std::net::IpAddr, to: &std::net::IpAddr) -> Vec<String> {
    // An inclusive range is reported as the aligned CIDR blocks that cover it.
    match (from, to) {
        (std::net::IpAddr::V4(from), std::net::IpAddr::V4(to)) => {
            blocks(u128::from(u32::from(*from)), u128::from(u32::from(*to)), 32)
                .into_iter()
                .map(|(start, bits)| format!("{}/{}", std::net::Ipv4Addr::from(start as u32), bits))
                .collect()
        }
        (std::net::IpAddr::V6(from), std::net::IpAddr::V6(to)) => {
            blocks(u128::from(*from), u128::from(*to), 128)
                .into_iter()
                .map(|(start, bits)| format!("{}/{}", std::net::Ipv6Addr::from(start), bits))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// The aligned power-of-two blocks covering `start..=end`.
fn blocks(mut start: u128, end: u128, width: u32) -> Vec<(u128, u32)> {
    let mut out = Vec::new();
    while start <= end {
        // the largest block that is aligned at `start`
        let max_size = if start == 0 {
            1u128 << width
        } else {
            1u128 << start.trailing_zeros().min(width)
        };
        let room = (end - start) + 1;
        let mut size = max_size;
        while size > room {
            size >>= 1;
        }
        let bits = width - size.trailing_zeros();
        out.push((start, bits.min(width)));
        match start.checked_add(size) {
            Some(next) => start = next,
            None => break,
        }
    }
    out
}

fn split_prefix(prefix: &str) -> Result<(std::net::IpAddr, u8), String> {
    let (addr, bits) = prefix
        .split_once('/')
        .ok_or_else(|| format!("invalid prefix: {prefix}"))?;
    let addr: std::net::IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid prefix address: {addr}"))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| format!("invalid prefix bits: {bits}"))?;
    Ok((addr, bits))
}

fn read_prefix(reader: &mut Reader<'_>) -> Result<String, String> {
    let addr = read_addr(reader)?;
    let bits = reader.u8()?;
    Ok(format!("{addr}/{bits}"))
}

// ------------------------------------------------------------------ helpers

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn listable(value: Option<&Value>) -> Result<Vec<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(text)) => Ok(vec![text.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => Err(format!("expected a string, got {}", kind(other))),
            })
            .collect(),
        Some(other) => Err(format!("expected a string, got {}", kind(other))),
    }
}

fn strings(value: &Value) -> Result<Vec<String>, String> {
    listable(Some(value))
}

fn ports(value: &Value) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    match value {
        Value::Number(number) => out.push(
            number
                .as_u64()
                .filter(|value| *value <= u64::from(u16::MAX))
                .ok_or_else(|| "port out of range".to_string())? as u16,
        ),
        Value::Array(items) => {
            for item in items {
                let number = item
                    .as_u64()
                    .ok_or_else(|| "port must be a number".to_string())?;
                if number > u64::from(u16::MAX) {
                    return Err("port out of range".to_string());
                }
                out.push(number as u16);
            }
        }
        other => return Err(format!("port must be a number, got {}", kind(other))),
    }
    Ok(out)
}

fn port_values(values: Vec<u16>) -> Value {
    Value::Array(values.into_iter().map(Value::from).collect())
}

fn query_type_code(name: &str) -> Result<u16, String> {
    match name {
        "A" | "1" => Ok(1),
        "AAAA" | "28" => Ok(28),
        "HTTPS" | "65" => Ok(65),
        other => Err(format!("unsupported query_type: {other}")),
    }
}

fn network_type_code(name: &str) -> Result<u8, String> {
    match name {
        "wifi" | "0" => Ok(0),
        "cellular" | "1" => Ok(1),
        "ethernet" | "2" => Ok(2),
        "other" | "3" => Ok(3),
        other => Err(format!("unsupported network_type: {other}")),
    }
}

fn reverse_domain(domain: &str) -> String {
    domain.chars().rev().collect()
}

// ------------------------------------------------------------------ codecs

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn uvarint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.out.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.out.push(value as u8);
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.uvarint(value.len() as u64);
        self.out.extend_from_slice(value);
    }

    fn u64_slice(&mut self, values: &[u64]) {
        self.uvarint(values.len() as u64);
        for value in values {
            self.u64(*value);
        }
    }

    fn str_vec(&mut self, values: &[String]) {
        self.uvarint(values.len() as u64);
        for value in values {
            self.bytes(value.as_bytes());
        }
    }

    fn u8_vec(&mut self, values: &[u8]) {
        self.uvarint(values.len() as u64);
        self.out.extend_from_slice(values);
    }

    fn u16_vec(&mut self, values: &[u16]) {
        self.uvarint(values.len() as u64);
        for value in values {
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn item_str_vec(&mut self, item: u8, values: &[String]) {
        if values.is_empty() {
            return;
        }
        self.u8(item);
        self.str_vec(values);
    }

    fn item_u8_vec(&mut self, item: u8, values: &[u8]) {
        if values.is_empty() {
            return;
        }
        self.u8(item);
        self.u8_vec(values);
    }

    fn item_u16_vec(&mut self, item: u8, values: &[u16]) {
        if values.is_empty() {
            return;
        }
        self.u8(item);
        self.u16_vec(values);
    }

    fn item_ip_set(&mut self, item: u8, prefixes: &[String]) {
        if prefixes.is_empty() {
            return;
        }
        self.u8(item);
        let ranges = merge_prefixes(prefixes);
        self.u8(1);
        self.u64(ranges.len() as u64);
        for (from, to) in ranges {
            write_addr(self, &from);
            write_addr(self, &to);
        }
    }
}

/// Cover the given prefixes with the minimal set of aligned ranges, the shape
/// `netipx.IPSet` stores.
fn merge_prefixes(prefixes: &[String]) -> Vec<(std::net::IpAddr, std::net::IpAddr)> {
    let mut v4: Vec<(u32, u8)> = Vec::new();
    let mut v6: Vec<(u128, u8)> = Vec::new();
    for prefix in prefixes {
        let Ok((addr, bits)) = split_prefix(prefix) else {
            continue;
        };
        match addr {
            std::net::IpAddr::V4(addr) => {
                let value = u32::from(addr);
                let start = value & (!0u32 << (32 - bits.min(32)));
                v4.push((start, bits.min(32)));
            }
            std::net::IpAddr::V6(addr) => {
                let value = u128::from(addr);
                let start = if bits >= 128 {
                    value
                } else {
                    value & (!0u128 << (128 - bits))
                };
                v6.push((start, bits));
            }
        }
    }
    let mut out = Vec::new();
    v4.sort_unstable();
    let mut index = 0usize;
    while index < v4.len() {
        let (start, bits) = v4[index];
        let size = 1u32 << (32 - bits);
        let end = start.saturating_add(size.saturating_sub(1));
        let mut next = index + 1;
        while next < v4.len() && v4[next].0 <= end.saturating_add(1) {
            let (other, other_bits) = v4[next];
            let other_end = other.saturating_add((1u32 << (32 - other_bits)).saturating_sub(1));
            let end = end.max(other_end);
            let _ = end;
            next += 1;
        }
        out.push((
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(start)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(end)),
        ));
        index = next;
    }
    v6.sort_unstable();
    let mut index = 0usize;
    while index < v6.len() {
        let (start, bits) = v6[index];
        let size = 1u128 << (128 - bits.min(128));
        let mut end = start.saturating_add(size.saturating_sub(1));
        let mut next = index + 1;
        while next < v6.len() && v6[next].0 <= end.saturating_add(1) {
            let (other, other_bits) = v6[next];
            let other_end = other.saturating_add((1u128 << (128 - other_bits)).saturating_sub(1));
            end = end.max(other_end);
            next += 1;
        }
        out.push((
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(start)),
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(end)),
        ));
        index = next;
    }
    out
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "rule-set read overflow".to_string())?;
        let slice = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| "unexpected end of rule-set".to_string())?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(raw))
    }

    fn uvarint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err("rule-set varint overflow".to_string());
            }
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self.uvarint()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn str(&mut self) -> Result<String, String> {
        let bytes = self.bytes()?;
        String::from_utf8(bytes).map_err(|_| "invalid utf-8 in rule-set".to_string())
    }

    fn str_values(&mut self) -> Result<Vec<Value>, String> {
        Ok(self.str_vec()?.into_iter().map(Value::String).collect())
    }

    fn str_vec(&mut self) -> Result<Vec<String>, String> {
        let count = self.uvarint()? as usize;
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            out.push(self.str()?);
        }
        Ok(out)
    }

    fn u8_vec(&mut self) -> Result<Vec<u8>, String> {
        let count = self.uvarint()? as usize;
        Ok(self.take(count)?.to_vec())
    }

    fn u16_vec(&mut self) -> Result<Vec<u16>, String> {
        let count = self.uvarint()? as usize;
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let bytes = self.take(2)?;
            out.push(u16::from_be_bytes([bytes[0], bytes[1]]));
        }
        Ok(out)
    }

    fn u64_slice(&mut self) -> Result<Vec<u64>, String> {
        let count = self.uvarint()? as usize;
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            out.push(self.u64()?);
        }
        Ok(out)
    }

    fn prefix_vec(&mut self) -> Result<Vec<Value>, String> {
        let count = self.uvarint()? as usize;
        let mut out = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            out.push(Value::String(read_prefix(self)?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip(source: Value, version: u8) -> Value {
        let compiled = compile(&source, version).expect("compile");
        let rules = read(&compiled).expect("read");
        json!({ "version": version, "rules": rules })
    }

    #[test]
    fn container_shape() {
        let compiled = compile(&json!({"rules": [{"domain": ["a.com"]}]}), 2).expect("compile");
        assert_eq!(&compiled[..3], b"SRS");
        assert_eq!(compiled[3], 2);
        assert!(read(&compiled).is_ok());
        assert!(read(b"XXX\x02").is_err());
        assert!(read(b"SRS\x09").is_err(), "version gate");
    }

    #[test]
    fn domain_matcher_round_trip() {
        let source = json!({
            "rules": [
                {"domain": ["example.com"], "domain_suffix": ["a.com", "b.org"]},
                {"domain_suffix": [".ads.net"]},
            ]
        });
        let out = round_trip(source.clone(), 3);
        assert_eq!(out["rules"][0]["domain"], json!(["example.com"]));
        assert_eq!(out["rules"][0]["domain_suffix"], json!(["a.com", "b.org"]));
        assert_eq!(out["rules"][1]["domain_suffix"], json!([".ads.net"]));
    }

    #[test]
    fn ip_and_port_items() {
        let source = json!({
            "rules": [
                {"ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"], "port": [80, 443]},
                {
                    "source_ip_cidr": ["2001:db8::/32"],
                    "source_port": [1000],
                    "port_range": ["8000-9000"]
                },
            ]
        });
        let out = round_trip(source.clone(), 3);
        assert_eq!(
            out["rules"][0]["ip_cidr"],
            json!(["10.0.0.0/8", "192.168.0.0/16"])
        );
        assert_eq!(out["rules"][0]["port"], json!([80, 443]));
        assert_eq!(out["rules"][1]["source_ip_cidr"], json!(["2001:db8::/32"]));
        assert_eq!(out["rules"][1]["source_port"], json!([1000]));
        assert_eq!(out["rules"][1]["port_range"], json!(["8000-9000"]));
    }

    #[test]
    fn network_flags_and_interface_addresses() {
        let source = json!({
            "rules": [{
                "network_type": ["wifi"],
                "network_is_expensive": true,
                "network_is_constrained": true,
            }]
        });
        let out = round_trip(source, 3);
        assert_eq!(out["rules"][0]["network_type"], json!(["wifi"]));
        assert_eq!(out["rules"][0]["network_is_expensive"], json!(true));
        assert_eq!(out["rules"][0]["network_is_constrained"], json!(true));

        let source = json!({
            "rules": [{
                "network_interface_address": {"wifi": ["192.168.1.0/24"]},
                "default_interface_address": ["10.0.0.0/8"],
            }]
        });
        let out = round_trip(source, 4);
        assert_eq!(
            out["rules"][0]["network_interface_address"],
            json!({"wifi": ["192.168.1.0/24"]})
        );
        assert_eq!(
            out["rules"][0]["default_interface_address"],
            json!(["10.0.0.0/8"])
        );
    }

    #[test]
    fn logical_rules_carry_their_own_invert() {
        let source = json!({
            "rules": [{
                "type": "logical",
                "mode": "or",
                "rules": [{"domain_suffix": ["a.com"]}, {"port": [443]}],
                "invert": true,
            }]
        });
        let out = round_trip(source, 3);
        assert_eq!(out["rules"][0]["type"], json!("logical"));
        assert_eq!(out["rules"][0]["mode"], json!("or"));
        assert_eq!(out["rules"][0]["invert"], json!(true));
        assert_eq!(out["rules"][0]["rules"][1]["port"], json!([443]));
    }

    #[test]
    fn version_gates_and_downgrade() {
        let source = json!({"rules": [{"package_name_regex": [r"^com\."]}]});
        assert!(
            compile(&source, 4).is_err(),
            "package_name_regex needs version 5"
        );
        let source = json!({"rules": [{"network_type": ["wifi"]}]});
        assert!(compile(&source, 2).is_err(), "network_type needs version 3");
        let source = json!({"rules": [{"default_interface_address": ["10.0.0.0/8"]}]});
        assert!(
            compile(&source, 3).is_err(),
            "default_interface_address needs version 4"
        );
        // the compiler lowers the container version to what the rules need
        let source = json!({"rules": [{"domain": ["a.com"]}]});
        assert_eq!(downgrade_version(&source, 5), 2);
        let source = json!({"rules": [{"network_type": ["wifi"]}]});
        assert_eq!(downgrade_version(&source, 5), 3);
        let source = json!({"rules": [{"default_interface_address": ["10.0.0.0/8"]}]});
        assert_eq!(downgrade_version(&source, 5), 4);
        let source = json!({"rules": [{"package_name_regex": [r"^com\."]}]});
        assert_eq!(downgrade_version(&source, 5), 5);
    }

    #[test]
    fn query_type_and_wifi_items() {
        let source = json!({
            "rules": [{
                "query_type": ["HTTPS"],
                "wifi_ssid": ["home"],
                "wifi_bssid": ["aa:bb:cc:dd:ee:ff"],
            }]
        });
        let out = round_trip(source, 3);
        assert_eq!(out["rules"][0]["query_type"], json!(["HTTPS"]));
        assert_eq!(out["rules"][0]["wifi_ssid"], json!(["home"]));
        assert_eq!(out["rules"][0]["wifi_bssid"], json!(["aa:bb:cc:dd:ee:ff"]));
    }

    #[test]
    fn legacy_v1_suffixes_use_the_legacy_matcher() {
        // version 1 keeps a suffix as both the domain and its ".domain" form
        let compiled =
            compile(&json!({"rules": [{"domain_suffix": ["legacy.com"]}]}), 1).expect("compile");
        let out = read(&compiled).expect("read");
        let suffix = out[0]
            .get("domain_suffix")
            .and_then(|v| v.as_array())
            .cloned();
        assert!(suffix.is_some_and(|list| list.contains(&json!("legacy.com"))));
    }
}
