use super::Config;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preferences {
    pub(crate) target: Option<String>,
    pub(crate) witness: Option<String>,
    pub(crate) port: u16,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            target: None,
            witness: None,
            port: 43531,
        }
    }
}
impl Preferences {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.port < 1024
            || [self.target.as_deref(), self.witness.as_deref()]
                .into_iter()
                .flatten()
                .any(|n| n.is_empty() || n.len() > 256 || n.chars().any(char::is_control))
        {
            return Err("invalid_desktop_preferences".into());
        }
        if self.target.is_some() && self.target == self.witness {
            return Err("same_distribution".into());
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Document {
    pub(crate) revision: u64,
    pub(crate) profile: Config,
    pub(crate) desktop: Preferences,
}
pub(crate) fn decode_policy(bytes: &[u8]) -> Result<Config, String> {
    // Console users can still supply a plain policy. The desktop stores preferences and
    // revision atomically in a typed envelope; neither format can contain passwords.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Input {
        Plain(Config),
        Desktop(Document),
    }
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    match serde_json::from_slice::<Input>(bytes)
        .map_err(|_| "invalid policy JSON or unsupported policy field")?
    {
        Input::Plain(c) => Ok(c),
        Input::Desktop(d) if d.revision > 0 => Ok(d.profile),
        _ => Err("invalid desktop policy revision".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::decode_policy;

    #[test]
    fn accepts_utf8_bom_from_legacy_windows_editors() {
        let mut bytes = b"{\"first_hop\":\"127.0.0.1:7892\",\"credential\":\"demo\",\"dns_upstream\":\"223.5.5.5:443\",\"dns_tls_name\":\"dns.example\",\"direct_ips\":[],\"direct_domains\":[],\"direct_suffixes\":[]}".to_vec();
        bytes.splice(0..0, [0xef, 0xbb, 0xbf]);
        assert!(decode_policy(&bytes).is_ok());
    }
}
