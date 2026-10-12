use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

fn flag_value(args: &[String], short: &str, long: &str) -> Option<String> {
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if arg == short || arg == long {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix(&format!("{long}=")) {
            return Some(value.to_string());
        }
        if let Some(value) = arg.strip_prefix(&format!("{short}=")) {
            return Some(value.to_string());
        }
        index += 1;
    }
    None
}

fn positional_args(args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-o"
            || arg == "--output"
            || arg == "-d"
            || arg == "--domain"
            || arg == "-i"
            || arg == "--ip"
            || arg == "-f"
            || arg == "--format"
        {
            index += 2;
            continue;
        }
        if arg.starts_with("--output=")
            || arg.starts_with("-o=")
            || arg.starts_with("--domain=")
            || arg.starts_with("-d=")
            || arg.starts_with("--ip=")
            || arg.starts_with("-i=")
            || arg.starts_with("--format=")
            || arg.starts_with("-f=")
        {
            index += 1;
            continue;
        }
        if arg.starts_with("-") {
            index += 1;
            continue;
        }
        positional.push(arg.clone());
        index += 1;
    }
    positional
}

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    if path == "stdin" || path == "-" {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|e| format!("read stdin: {e}"))?;
        return Ok(buffer);
    }
    std::fs::read(path).map_err(|e| format!("open {path}: {}", go_io_error(path, &e)))
}

/// `*fs.PathError` text: Go prints the bare syscall message, and the message is
/// localized on this host, so the Windows codes are mapped like the reference.
fn go_io_error(_path: &str, err: &std::io::Error) -> String {
    if let Some(code) = err.raw_os_error() {
        let text = match code {
            2 => "The system cannot find the file specified.",
            3 => "The system cannot find the path specified.",
            5 => "Access is denied.",
            1 => "Incorrect function.",
            267 => "The directory name is invalid.",
            _ => "",
        };
        if !text.is_empty() {
            return text.to_string();
        }
    }
    let raw = err.to_string();
    let text = match raw.rfind(" (os error ") {
        Some(index) => raw[..index].to_string(),
        None => raw,
    };
    if cfg!(windows) {
        text
    } else {
        let mut chars = text.chars();
        match chars.next() {
            Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
            None => text,
        }
    }
}

fn default_output(source: &str, suffix: &str) -> PathBuf {
    let path = Path::new(source);
    if path.extension().is_some_and(|ext| ext == "srs") {
        return path.with_extension("json");
    }
    PathBuf::from(format!("{source}.{suffix}"))
}

fn cmd_rule_set_compile(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: sing-box rule-set compile [flags] [source-path]");
        return Ok(());
    }
    let positional = positional_args(args);
    let source = positional
        .first()
        .ok_or("rule-set compile: missing [source-path]")?
        .clone();
    let explicit = flag_value(args, "-o", "--output");
    let data = read_input(&source)?;
    let text = String::from_utf8(data).map_err(|_| "rule-set: source is not utf-8".to_string())?;
    let value: Value =
        serde_json::from_str(&text).map_err(|e| format!("rule-set: parse source: {e}"))?;
    let version = match value.get("version") {
        Some(Value::Number(number)) => number.as_u64().unwrap_or(0) as u8,
        Some(Value::Null) | None => 0,
        Some(other) => {
            return Err(format!(
                "rule-set: version: json: cannot unmarshal {} into Go struct field _PlainRuleSetCompat.version of type uint8",
                json_kind(other)
            ));
        }
    };
    if version == 0 || version > core_config::srs::VERSION_CURRENT {
        return Err(format!("rule-set: unknown rule-set version: {version}"));
    }
    let output = explicit.unwrap_or_else(|| {
        let path = Path::new(&source);
        if path.extension().is_some_and(|ext| ext == "json") {
            path.with_extension("srs").to_string_lossy().to_string()
        } else {
            format!("{source}.srs")
        }
    });
    let version = core_config::srs::downgrade_version(&value, version);
    let compiled = core_config::srs::compile(&value, version)?;
    std::fs::write(&output, compiled)
        .map_err(|e| format!("rule-set: write {output}: {}", go_io_error(&output, &e)))?;
    Ok(())
}

/// `badoption.Listable[T]` marshals a single element as the bare value, which
/// is what the reference `rule-set decompile` prints.
const LISTABLE_FIELDS: &[&str] = &[
    "query_type",
    "network",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "source_ip_cidr",
    "ip_cidr",
    "source_port",
    "source_port_range",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "process_path_regex",
    "package_name",
    "package_name_regex",
    "network_type",
    "wifi_ssid",
    "wifi_bssid",
    "default_interface_address",
];

fn collapse_listables(rule: &mut Value) {
    // the typed map values are Listable too
    let Some(object) = rule.as_object_mut() else {
        return;
    };
    if let Some(Value::Object(nested)) = object.get_mut("network_interface_address") {
        for (_, value) in nested.iter_mut() {
            if let Value::Array(items) = value
                && items.len() == 1
                && let Some(Value::String(text)) = items.first()
            {
                *value = Value::String(text.clone());
            }
        }
    }
    for field in LISTABLE_FIELDS {
        let Some(Value::Array(items)) = object.get(*field) else {
            continue;
        };
        if items.len() != 1 {
            continue;
        }
        match items.first() {
            Some(Value::String(text)) => {
                object.insert((*field).to_string(), Value::String(text.clone()));
            }
            Some(value @ Value::Number(_)) => {
                object.insert((*field).to_string(), value.clone());
            }
            _ => {}
        }
    }
    if object.get("type").and_then(Value::as_str) == Some("logical")
        && let Some(Value::Array(rules)) = object.get_mut("rules")
    {
        for rule in rules.iter_mut() {
            collapse_listables(rule);
        }
    }
}

fn document(version: u8, rules: Vec<Value>) -> Value {
    let rules: Vec<Value> = rules
        .into_iter()
        .map(|mut rule| {
            collapse_listables(&mut rule);
            rule
        })
        .collect();
    let mut document = Map::new();
    document.insert("version".into(), Value::from(version));
    document.insert("rules".into(), Value::Array(rules));
    Value::Object(document)
}

fn cmd_rule_set_decompile(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: sing-box rule-set decompile [flags] [binary-path]");
        return Ok(());
    }
    let positional = positional_args(args);
    let source = positional
        .first()
        .ok_or("rule-set decompile: missing [binary-path]")?
        .clone();
    let explicit = flag_value(args, "-o", "--output");
    let data = read_input(&source)?;
    let (version, rules) = core_config::srs::read_with_version(&data)?;
    let output = explicit.unwrap_or_else(|| {
        default_output(&source, "json")
            .to_string_lossy()
            .to_string()
    });
    let text = serde_json::to_string_pretty(&document(version, rules))
        .map_err(|e| format!("rule-set: encode json: {e}"))?;
    std::fs::write(&output, format!("{text}\n"))
        .map_err(|e| format!("rule-set: write {output}: {}", go_io_error(&output, &e)))?;
    Ok(())
}

fn cmd_rule_set_match(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: sing-box rule-set match [flags] [rule-set-path]");
        return Ok(());
    }
    let positional = positional_args(args);
    let source = positional
        .first()
        .ok_or("rule-set match: missing [rule-set-path]")?
        .clone();
    let data = read_input(&source)?;
    let rules = if data.starts_with(b"SRS") {
        core_config::srs::read(&data)?
    } else {
        let text =
            String::from_utf8(data).map_err(|_| "rule-set: source is not utf-8".to_string())?;
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("rule-set: parse source: {e}"))?;
        value
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut domain = flag_value(args, "-d", "--domain");
    let mut ip = flag_value(args, "-i", "--ip");
    if domain.is_none() && ip.is_none() {
        if let Some(target) = positional.get(1) {
            if target.parse::<std::net::IpAddr>().is_ok() {
                ip = Some(target.clone());
            } else {
                domain = Some(target.clone());
            }
        } else {
            return Err("rule-set match: one of --domain or --ip is required".to_string());
        }
    }
    let mut hits = 0usize;
    for (index, rule) in rules.iter().enumerate() {
        if rule_matches(rule, domain.as_deref(), ip.as_deref()) {
            println!("[{index}] match");
            hits += 1;
        }
    }
    if hits == 0 {
        println!("no match");
    }
    Ok(())
}

fn rule_matches(rule: &Value, domain: Option<&str>, ip: Option<&str>) -> bool {
    let Some(rule) = rule.as_object() else {
        return false;
    };
    if rule.get("type").and_then(Value::as_str) == Some("logical") {
        let mode = rule.get("mode").and_then(Value::as_str).unwrap_or("and");
        let rules: Vec<Value> = rule
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        return match mode {
            "or" => rules.iter().any(|sub| rule_matches(sub, domain, ip)),
            _ => rules.iter().all(|sub| rule_matches(sub, domain, ip)),
        };
    }
    let mut matched = false;
    if let Some(domain) = domain {
        for value in listable(rule.get("domain")) {
            if domain == value {
                matched = true;
            }
        }
        for value in listable(rule.get("domain_suffix")) {
            let suffix = value.trim_start_matches('.');
            if domain == suffix
                || domain
                    .strip_suffix(suffix)
                    .is_some_and(|head| head.ends_with('.'))
            {
                matched = true;
            }
        }
        for value in listable(rule.get("domain_keyword")) {
            if domain.contains(&value) {
                matched = true;
            }
        }
    }
    if let Some(address) = ip.and_then(|value| rule_ip_match(rule, value)) {
        matched |= address;
    }
    if rule.get("invert") == Some(&Value::Bool(true)) {
        return !matched;
    }
    matched
}

fn rule_ip_match(rule: &Map<String, Value>, ip: &str) -> Option<bool> {
    let Ok(address) = ip.parse::<std::net::IpAddr>() else {
        return None;
    };
    for field in ["ip_cidr", "source_ip_cidr"] {
        for entry in listable(rule.get(field)) {
            if prefix_contains(&entry, address) {
                return Some(true);
            }
        }
    }
    Some(false)
}

/// Whether  falls inside the  CIDR.
fn prefix_contains(prefix: &str, address: std::net::IpAddr) -> bool {
    let Some((base, bits)) = prefix.split_once('/') else {
        return false;
    };
    let (Ok(base), Ok(bits)) = (base.parse::<std::net::IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (base, address) {
        (std::net::IpAddr::V4(base), std::net::IpAddr::V4(address)) => {
            let mask = if bits >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(base) & mask == u32::from(address) & mask
        }
        (std::net::IpAddr::V6(base), std::net::IpAddr::V6(address)) => {
            let mask = if bits >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(base) & mask == u128::from(address) & mask
        }
        _ => false,
    }
}

fn listable(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn cmd_rule_set_format(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: sing-box rule-set format [flags] [rule-set-path]");
        return Ok(());
    }
    let positional = positional_args(args);
    let path = positional
        .first()
        .ok_or("rule-set format: missing [rule-set-path]")?
        .clone();
    let data = read_input(&path)?;
    let (version, rules) = if data.starts_with(b"SRS") {
        core_config::srs::read_with_version(&data)?
    } else {
        let text =
            String::from_utf8(data).map_err(|_| "rule-set: source is not utf-8".to_string())?;
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("rule-set: parse source: {e}"))?;
        let version = value
            .get("version")
            .and_then(Value::as_u64)
            .unwrap_or(core_config::srs::VERSION_CURRENT as u64) as u8;
        let rules = value
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        (version, rules)
    };
    let mut document = Map::new();
    document.insert("version".into(), Value::from(version));
    document.insert("rules".into(), Value::Array(rules));
    let text = serde_json::to_string_pretty(&Value::Object(document))
        .map_err(|e| format!("rule-set: encode json: {e}"))?;
    println!("{text}");
    Ok(())
}

fn cmd_rule_set_upgrade(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("Usage: sing-box rule-set upgrade [flags] [rule-set-path]");
        return Ok(());
    }
    let positional = positional_args(args);
    let path = positional
        .first()
        .ok_or("rule-set upgrade: missing [rule-set-path]")?
        .clone();
    let data = read_input(&path)?;
    let (version, rules) = if data.starts_with(b"SRS") {
        core_config::srs::read_with_version(&data)?
    } else {
        let text =
            String::from_utf8(data).map_err(|_| "rule-set: source is not utf-8".to_string())?;
        let value: Value =
            serde_json::from_str(&text).map_err(|e| format!("rule-set: parse source: {e}"))?;
        let version = value.get("version").and_then(Value::as_u64).unwrap_or(0) as u8;
        if version == 0 {
            return Err("rule-set: missing rule-set version".to_string());
        }
        let rules = value
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        (version, rules)
    };
    let text = serde_json::to_string_pretty(&document(core_config::srs::VERSION_CURRENT, rules))
        .map_err(|e| format!("rule-set: encode json: {e}"))?;
    println!("{text}");
    let _ = version;
    Ok(())
}

pub fn cmd_rule_set(args: &[String]) -> Result<(), String> {
    let sub = args
        .first()
        .ok_or("rule-set: missing subcommand (compile, decompile, match, format, upgrade)")?
        .clone();
    if sub == "-h" || sub == "--help" {
        println!(
            "Usage: sing-box rule-set [subcommand] (compile, decompile, match, format, upgrade)"
        );
        return Ok(());
    }
    let rest: Vec<String> = args[1..].to_vec();
    match sub.as_str() {
        "compile" => cmd_rule_set_compile(&rest),
        "decompile" => cmd_rule_set_decompile(&rest),
        "match" => cmd_rule_set_match(&rest),
        "format" => cmd_rule_set_format(&rest),
        "upgrade" => cmd_rule_set_upgrade(&rest),
        other => Err(format!(
            "rule-set: unknown subcommand '{other}' (compile, decompile, match, format, upgrade)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_positional_args_flag_ordering() {
        let args1 = vec![
            "--output".to_string(),
            "out.json".to_string(),
            "in.srs".to_string(),
        ];
        assert_eq!(positional_args(&args1), vec!["in.srs".to_string()]);
        assert_eq!(
            flag_value(&args1, "-o", "--output"),
            Some("out.json".to_string())
        );

        let args2 = vec![
            "in.srs".to_string(),
            "-o".to_string(),
            "out.json".to_string(),
        ];
        assert_eq!(positional_args(&args2), vec!["in.srs".to_string()]);
        assert_eq!(
            flag_value(&args2, "-o", "--output"),
            Some("out.json".to_string())
        );

        let args3 = vec!["--output=out.json".to_string(), "in.srs".to_string()];
        assert_eq!(positional_args(&args3), vec!["in.srs".to_string()]);
        assert_eq!(
            flag_value(&args3, "-o", "--output"),
            Some("out.json".to_string())
        );

        let args4 = vec![
            "in.srs".to_string(),
            "youtube.com".to_string(),
            "-f".to_string(),
            "binary".to_string(),
        ];
        assert_eq!(
            positional_args(&args4),
            vec!["in.srs".to_string(), "youtube.com".to_string()]
        );
    }

    #[test]
    fn test_cmd_rule_set_match_positional() {
        let temp_dir = std::env::temp_dir();
        let rule_path = temp_dir.join("test_ruleset_match.json");
        let json_content = r#"{
            "version": 1,
            "rules": [
                {
                    "domain_suffix": ["youtube.com"],
                    "ip_cidr": ["192.168.1.0/24"]
                }
            ]
        }"#;
        std::fs::write(&rule_path, json_content).unwrap();
        let p_str = rule_path.to_str().unwrap().to_string();

        // Positional domain with -f binary
        assert!(cmd_rule_set_match(&[p_str.clone(), "www.youtube.com".into(), "-f".into(), "binary".into()]).is_ok());

        // Positional IP
        assert!(cmd_rule_set_match(&[p_str.clone(), "192.168.1.50".into()]).is_ok());

        // Explicit domain flag
        assert!(cmd_rule_set_match(&[p_str.clone(), "--domain".into(), "youtube.com".into()]).is_ok());

        // Missing both domain and ip
        assert!(cmd_rule_set_match(&[p_str.clone()]).is_err());

        let _ = std::fs::remove_file(rule_path);
    }
}
