pub mod asn1_x509;
pub mod fptn;
pub mod netip_parse;
pub mod srs;
pub mod validate;
pub mod vless_enc;

use serde_json::Value;

/// Full `sing-box check` equivalent plus the reference's warning lines
/// (deprecated `route.lx_idle_*` aliases and friends), which do not fail the
/// check. FPTN token outbounds are validated as written, then expanded into
/// per-server outbounds + urltest group and validated again.
///
/// The config is read as a `Value` and every section is taken apart by the
/// module that needs it: a struct with one `Option<Value>` per section was only
/// ever a second copy of the schema.
pub fn check_str_warnings(raw: &str) -> Result<Vec<String>, String> {
    let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    // as written first (an fptn `token` field is not part of the schema)
    validate::validate(&value)?;
    match fptn::expand(&value) {
        Ok(Some(expanded)) => validate::validate_with_warnings(&expanded),
        Ok(None) => Ok(validate::take_warnings()),
        Err(e) => Err(e),
    }
}

/// Full `sing-box check` equivalent: schema parse + semantic validation.
pub fn check_str(raw: &str) -> Result<(), String> {
    check_str_warnings(raw).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_json() {
        assert!(check_str("{not json").is_err());
    }

    #[test]
    fn accepts_a_minimal_config() {
        check_str(r#"{"log":{"level":"warn"},"outbounds":[{"type":"direct"}]}"#).unwrap();
    }

    #[test]
    fn a_section_it_knows_nothing_about_fails_the_check() {
        // the permissive struct this used to parse into is gone; the reference
        // rejects a section it does not know, and so do we
        let err = check_str(r#"{"futureSection":{"a":1}}"#).unwrap_err();
        assert!(err.contains("futureSection"), "{err}");
    }
}
