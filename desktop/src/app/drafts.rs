//! 每页只保存自己的字段：规则页存直连规则，设置页存代理链、DNS 和转发限制，环境页存
//! 正在看的那个环境的住宅代理和 Windows 入口端口（决策 40）。后台每次保存整份共用配置，
//! 所以规则页、设置页的保存请求以已保存的值打底，只换上本页输入框里的内容；环境页的
//! 保存是单独的请求，只写那一个环境。

use serde_json::{Value, json};

/// 有保存动作的三个页面。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaveScope {
    /// 环境页：正在看的环境的住宅代理和 Windows 入口端口。
    Environment,
    /// 规则页：直连规则。
    Policy,
    /// 设置页：代理链、DNS 和转发限制。
    Settings,
}

impl SaveScope {
    pub(crate) fn page_name(self) -> &'static str {
        match self {
            Self::Environment => "环境页",
            Self::Policy => "规则页",
            Self::Settings => "设置页",
        }
    }

    /// 失败提示里的动作名，例如「保存规则失败：…」。
    pub(crate) fn action(self) -> &'static str {
        match self {
            Self::Environment => "保存住宅代理",
            Self::Policy => "保存规则",
            Self::Settings => "保存设置",
        }
    }

    pub(crate) fn saved_notice(self) -> &'static str {
        match self {
            Self::Environment => "住宅代理已保存；下次启动这个环境的接管时生效。",
            Self::Policy => "规则已保存；不会立即改变当前接管。",
            Self::Settings => "设置已保存；不会立即改变当前接管。",
        }
    }
}

/// 输入框里的文字怎么写进策略。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FieldKind {
    /// 原样保存。
    Text,
    /// 每行一项，去掉首尾空白，空行忽略。
    Lines,
    /// 整数；留空表示用后台默认值，策略里不写这个字段。
    Number,
    /// 有默认值、可以关闭的文字：策略里没有这个字段时显示默认值；填默认值不写；
    /// 留空写 `null`，表示关闭。
    Optional(&'static str),
    /// 有默认值的文字：策略里没有这个字段时显示默认值；留空或填默认值都不写。
    Defaulted(&'static str),
}

/// 早先一个版本写进策略的预建链路设置；现在预建链路是自适应的，保存设置时去掉。
const LEGACY_KEYS: [&str; 2] = ["tunnel_pool_max", "tunnel_pool_demand_seconds"];

/// 白名单域名直接问的国内 DoH 上游的默认值，和后台策略的默认值一致。
pub(crate) const DEFAULT_DIRECT_DNS_UPSTREAM: &str = "223.5.5.5:443";
pub(crate) const DEFAULT_DIRECT_DNS_TLS_NAME: &str = "dns.alidns.com";

/// 写进策略的字段。用枚举而不是字段名字符串：输入框的对应关系由穷尽匹配给出，
/// 新增字段漏写对应关系时编译不过，而不是运行时才出错。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProfileField {
    FirstHop,
    DnsUpstream,
    DnsTlsName,
    HealthDomain,
    DirectDnsUpstream,
    DirectDnsTlsName,
    DirectIps,
    DirectDomains,
    DirectSuffixes,
    MaxTcpConnections,
    TcpIdleTimeout,
    TcpHalfCloseTimeout,
}

impl ProfileField {
    pub(crate) const ALL: [Self; 12] = [
        Self::FirstHop,
        Self::DnsUpstream,
        Self::DnsTlsName,
        Self::HealthDomain,
        Self::DirectDnsUpstream,
        Self::DirectDnsTlsName,
        Self::DirectIps,
        Self::DirectDomains,
        Self::DirectSuffixes,
        Self::MaxTcpConnections,
        Self::TcpIdleTimeout,
        Self::TcpHalfCloseTimeout,
    ];

    /// 策略里的字段名。
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::FirstHop => "first_hop",
            Self::DnsUpstream => "dns_upstream",
            Self::DnsTlsName => "dns_tls_name",
            Self::HealthDomain => "health_domain",
            Self::DirectDnsUpstream => "direct_dns_upstream",
            Self::DirectDnsTlsName => "direct_dns_tls_name",
            Self::DirectIps => "direct_ips",
            Self::DirectDomains => "direct_domains",
            Self::DirectSuffixes => "direct_suffixes",
            Self::MaxTcpConnections => "max_tcp_connections",
            Self::TcpIdleTimeout => "tcp_idle_timeout_seconds",
            Self::TcpHalfCloseTimeout => "tcp_half_close_timeout_seconds",
        }
    }

    /// 在哪一页编辑、由哪一页保存。
    pub(crate) fn scope(self) -> SaveScope {
        match self {
            Self::DirectIps | Self::DirectDomains | Self::DirectSuffixes => SaveScope::Policy,
            _ => SaveScope::Settings,
        }
    }

    pub(crate) fn kind(self) -> FieldKind {
        match self {
            Self::DirectIps | Self::DirectDomains | Self::DirectSuffixes => FieldKind::Lines,
            Self::MaxTcpConnections | Self::TcpIdleTimeout | Self::TcpHalfCloseTimeout => {
                FieldKind::Number
            }
            Self::DirectDnsUpstream => FieldKind::Optional(DEFAULT_DIRECT_DNS_UPSTREAM),
            Self::DirectDnsTlsName => FieldKind::Defaulted(DEFAULT_DIRECT_DNS_TLS_NAME),
            _ => FieldKind::Text,
        }
    }
}

/// 某一页写进策略的字段。
pub(crate) fn profile_fields(scope: SaveScope) -> impl Iterator<Item = ProfileField> {
    ProfileField::ALL
        .into_iter()
        .filter(move |field| field.scope() == scope)
}

/// 已保存的策略开没开远端解析（fake-ip）。策略里没有这个字段就是开着。
pub(crate) fn saved_fake_ip(saved: &Value) -> bool {
    saved["fake_ip"].as_bool().unwrap_or(true)
}

/// 已保存的值在输入框里显示成什么文字；也用来判断输入框有没有改过。
pub(crate) fn saved_text(saved: &Value, field: ProfileField) -> String {
    let value = &saved[field.key()];
    match field.kind() {
        FieldKind::Lines => value
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        FieldKind::Optional(default) | FieldKind::Defaulted(default) if value.is_null() => {
            // 没有这个字段（用默认值）和显式 `null`（关闭）在 JSON 里不同。
            if saved.get(field.key()).is_some() {
                String::new()
            } else {
                default.to_owned()
            }
        }
        FieldKind::Text | FieldKind::Number | FieldKind::Optional(_) | FieldKind::Defaulted(_) => {
            value
                .as_str()
                .map(str::trim)
                .map(str::to_owned)
                .or_else(|| value.as_u64().map(|value| value.to_string()))
                .unwrap_or_default()
        }
    }
}

/// 这一页写进策略的输入框和已保存的值不一样。`draft` 给出每个字段输入框里的文字。
pub(crate) fn profile_changed(
    saved: &Value,
    scope: SaveScope,
    draft: impl Fn(ProfileField) -> String,
) -> bool {
    profile_fields(scope).any(|field| draft(field) != saved_text(saved, field))
}

/// 把 `scope` 这一页的输入合进已保存的策略，其他页的字段保持已保存的值。
pub(crate) fn merge_profile(
    saved: &Value,
    scope: SaveScope,
    draft: impl Fn(ProfileField) -> String,
) -> Value {
    let mut profile = saved.as_object().cloned().unwrap_or_default();
    for field in profile_fields(scope) {
        let key = field.key();
        let text = draft(field);
        match field.kind() {
            FieldKind::Text => {
                profile.insert(key.into(), json!(text));
            }
            FieldKind::Lines => {
                profile.insert(
                    key.into(),
                    json!(
                        text.lines()
                            .map(str::trim)
                            .filter(|line| !line.is_empty())
                            .collect::<Vec<_>>()
                    ),
                );
            }
            FieldKind::Optional(_) if text.is_empty() => {
                profile.insert(key.into(), Value::Null);
            }
            FieldKind::Optional(default) | FieldKind::Defaulted(default)
                if text.is_empty() || text == default =>
            {
                profile.remove(key);
            }
            FieldKind::Optional(_) | FieldKind::Defaulted(_) => {
                profile.insert(key.into(), json!(text));
            }
            FieldKind::Number if text.is_empty() => {
                // 空着就用后台的默认值。
                profile.remove(key);
            }
            FieldKind::Number => {
                profile.insert(
                    key.into(),
                    text.parse::<u64>()
                        .map_or_else(|_| json!(text), |value| json!(value)),
                );
            }
        }
    }
    profile.insert("credential".into(), json!("desktop-residence"));
    // Pool settings from one earlier build; the pool is adaptive now.
    if scope == SaveScope::Settings {
        for key in LEGACY_KEYS {
            profile.remove(key);
        }
    }
    Value::Object(profile)
}

/// 住宅代理的协议：后台字段值和界面上的名字。
pub(crate) const RESIDENTIAL_PROTOCOLS: [(&str, &str); 2] =
    [("socks5", "SOCKS5"), ("http", "HTTP")];

/// 已保存的住宅代理协议；没存过协议的旧配置是 SOCKS5。
pub(crate) fn saved_residential_protocol(residential: &Value) -> &'static str {
    match residential["protocol"].as_str() {
        Some("http") => "http",
        _ => "socks5",
    }
}

/// 环境页住宅代理要保存的值，参数是协议和输入框里去掉首尾空白的文字。四项都空表示
/// 还没配置，按后台的空记录发（端口为 0）；填了任何一项，端口就必须是 1–65535 的
/// 整数，其余由后台校验。
pub(crate) fn residential_value(
    protocol: &str,
    ip: &str,
    port: &str,
    username: &str,
    password: &str,
) -> Result<Value, &'static str> {
    if ip.is_empty() && username.is_empty() && password.is_empty() && matches!(port, "" | "0") {
        return Ok(
            json!({"protocol": protocol, "ip": "", "port": 0, "username": "", "password": ""}),
        );
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or("住宅服务器端口需为 1–65535 的整数。")?;
    if protocol == "http" && username.contains(':') {
        return Err("HTTP 代理的用户名不能含英文冒号（:）。");
    }
    Ok(
        json!({"protocol": protocol, "ip": ip, "port": port, "username": username, "password": password}),
    )
}

/// 已保存的住宅代理在输入框里显示成什么文字；也用来判断输入框有没有改过。
/// 端口 0 是「还没配置」，显示成空。
pub(crate) fn saved_residential_text(residential: &Value, key: &str) -> String {
    match &residential[key] {
        Value::String(text) => text.trim().to_owned(),
        Value::Number(number) => number
            .as_u64()
            .filter(|port| *port != 0)
            .map(|port| port.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// 后台最近一次返回的已保存配置里，规则页、设置页保存时要原样带上的部分。
pub(crate) struct Saved<'a> {
    pub(crate) profile: &'a Value,
    pub(crate) revision: &'a Value,
}

/// 规则页、设置页一次保存里本页的内容；输入框的值已经校验过。
pub(crate) enum PageDraft {
    /// 规则页：直连规则全在策略里，由 `draft` 给出。
    Policy,
    /// 设置页：远端解析开关，其余字段在策略里，由 `draft` 给出。
    Settings { fake_ip: bool },
}

impl PageDraft {
    pub(crate) fn scope(&self) -> SaveScope {
        match self {
            Self::Policy => SaveScope::Policy,
            Self::Settings { .. } => SaveScope::Settings,
        }
    }
}

/// 规则页、设置页一次保存的请求：只有本页的内容取输入，其他页的策略字段用已保存的值。
/// 住宅代理和入口端口不在这里，由环境页单独保存。
pub(crate) fn save_request(
    saved: &Saved<'_>,
    page: PageDraft,
    draft: impl Fn(ProfileField) -> String,
) -> Value {
    let mut profile = merge_profile(saved.profile, page.scope(), draft);
    if let PageDraft::Settings { fake_ip } = page
        && let Some(profile) = profile.as_object_mut()
    {
        // 开着是默认值，不写。
        if fake_ip {
            profile.remove("fake_ip");
        } else {
            profile.insert("fake_ip".into(), Value::Bool(false));
        }
    }
    json!({
        "command": "profile_save",
        "profile": profile,
        "expected_revision": saved.revision,
    })
}

/// 环境页的保存请求：这个环境的住宅代理和入口端口。`port` 为 `None` 时后台沿用已保存的
/// 端口，第一次保存时从 43531 起分一个别的环境没用的端口。`revision` 是这个环境已保存的
/// 版本，从没保存过时为 `null`。
pub(crate) fn environment_save_request(
    distro_id: &str,
    residential: Value,
    port: Option<u16>,
    revision: &Value,
) -> Value {
    json!({
        "command": "environment_residential_save",
        "distro_id": distro_id,
        "residential": residential,
        "ingress_port": port,
        "expected_revision": revision,
    })
}

/// 配置库里这个环境的那一行；没保存过时为 `None`。和后台一样，ID 不区分大小写。
pub(crate) fn environment_row<'a>(rows: &'a [Value], distro_id: &str) -> Option<&'a Value> {
    rows.iter().find(|row| {
        row["distro_id"]
            .as_str()
            .is_some_and(|id| id.eq_ignore_ascii_case(distro_id))
    })
}

/// 这个环境保存了能用的住宅代理：服务器地址和端口都填了。
pub(crate) fn residential_configured(row: Option<&Value>) -> bool {
    row.is_some_and(|row| {
        let residential = &row["residential"];
        residential["ip"].as_str().is_some_and(|ip| !ip.is_empty())
            && residential["port"].as_u64().is_some_and(|port| port != 0)
    })
}

/// 这个发行版就是 `target`。和后台认目标的规则一致：名称完全相同，
/// 或者 ID 不区分大小写相同。
pub(crate) fn names_target(distro: &Value, target: &str) -> bool {
    distro["name"].as_str() == Some(target)
        || distro["id"]
            .as_str()
            .is_some_and(|id| id.eq_ignore_ascii_case(target))
}

/// 环境页、规则页、设置页各自有没有没保存的输入。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Unsaved {
    pub(crate) environment: bool,
    pub(crate) policy: bool,
    pub(crate) settings: bool,
}

impl Unsaved {
    pub(crate) fn contains(self, scope: SaveScope) -> bool {
        match scope {
            SaveScope::Environment => self.environment,
            SaveScope::Policy => self.policy,
            SaveScope::Settings => self.settings,
        }
    }

    /// 没有未保存输入、可以直接换成已保存值的页面。
    pub(crate) fn clean_pages(self) -> impl Iterator<Item = SaveScope> {
        [
            SaveScope::Environment,
            SaveScope::Policy,
            SaveScope::Settings,
        ]
        .into_iter()
        .filter(move |scope| !self.contains(*scope))
    }

    /// 有未保存输入的页面，例如「规则页、设置页」；都保存了时为 `None`。
    pub(crate) fn pages(self) -> Option<String> {
        let pages = [
            SaveScope::Environment,
            SaveScope::Policy,
            SaveScope::Settings,
        ]
        .into_iter()
        .filter(|scope| self.contains(*scope))
        .map(SaveScope::page_name)
        .collect::<Vec<_>>();
        (!pages.is_empty()).then(|| pages.join("、"))
    }
}

/// 保存失败、之后还没重新保存或编辑过的页面。各页分开记，一页的保存不影响别页的标签。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FailedSaves {
    environment: bool,
    policy: bool,
    settings: bool,
}

impl FailedSaves {
    fn slot(&mut self, scope: SaveScope) -> &mut bool {
        match scope {
            SaveScope::Environment => &mut self.environment,
            SaveScope::Policy => &mut self.policy,
            SaveScope::Settings => &mut self.settings,
        }
    }

    pub(crate) fn contains(self, scope: SaveScope) -> bool {
        match scope {
            SaveScope::Environment => self.environment,
            SaveScope::Policy => self.policy,
            SaveScope::Settings => self.settings,
        }
    }

    pub(crate) fn insert(&mut self, scope: SaveScope) {
        *self.slot(scope) = true;
    }

    pub(crate) fn remove(&mut self, scope: SaveScope) {
        *self.slot(scope) = false;
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{
        FailedSaves, PageDraft, ProfileField, SaveScope, Saved, Unsaved, environment_row,
        environment_save_request, merge_profile, profile_changed, residential_configured,
        residential_value, save_request, saved_fake_ip, saved_residential_protocol,
        saved_residential_text, saved_text,
    };

    fn saved() -> Value {
        json!({
            "first_hop": "127.0.0.1:7892",
            "credential": "desktop-residence",
            "dns_upstream": "223.5.5.5:443",
            "dns_tls_name": "dns.alidns.com",
            "health_domain": "example.com",
            "direct_ips": ["192.0.2.0/24"],
            "direct_domains": [],
            "direct_suffixes": ["example.org"],
            "max_tcp_connections": 128,
            "allow_loopback_residential": false,
        })
    }

    /// 两页都改过的输入框。
    fn draft(field: ProfileField) -> String {
        match field {
            ProfileField::FirstHop => "127.0.0.1:1080",
            ProfileField::DnsUpstream => "223.5.5.5:443",
            ProfileField::DnsTlsName => "dns.alidns.com",
            ProfileField::HealthDomain => "example.com",
            ProfileField::DirectDnsUpstream => "223.5.5.5:443",
            ProfileField::DirectDnsTlsName => "dns.alidns.com",
            ProfileField::DirectIps => "192.0.2.0/24\n 198.51.100.7 \n\n",
            ProfileField::DirectDomains => "",
            ProfileField::DirectSuffixes => "example.org",
            ProfileField::MaxTcpConnections => "",
            ProfileField::TcpIdleTimeout => "600",
            ProfileField::TcpHalfCloseTimeout => "",
        }
        .to_owned()
    }

    fn request(page: PageDraft) -> Value {
        let profile = saved();
        let revision = json!("7");
        let record = Saved {
            profile: &profile,
            revision: &revision,
        };
        save_request(&record, page, draft)
    }

    #[test]
    fn saving_settings_drops_earlier_pool_settings() {
        let mut profile = saved();
        profile["tunnel_pool_max"] = json!(4);
        profile["tunnel_pool_demand_seconds"] = json!(30);
        let merged = merge_profile(&profile, SaveScope::Settings, draft);
        assert!(merged.get("tunnel_pool_max").is_none());
        assert!(merged.get("tunnel_pool_demand_seconds").is_none());
    }

    #[test]
    fn direct_dns_fields_keep_default_off_and_custom_apart() {
        let upstream = ProfileField::DirectDnsUpstream;
        let name = ProfileField::DirectDnsTlsName;
        // 没写这两个字段：显示默认值，原样保存时也不写进策略。
        let profile = saved();
        assert_eq!(saved_text(&profile, upstream), "223.5.5.5:443");
        assert_eq!(saved_text(&profile, name), "dns.alidns.com");
        let unchanged = |field| saved_text(&profile, field);
        assert!(!profile_changed(&profile, SaveScope::Settings, unchanged));
        let merged = merge_profile(&profile, SaveScope::Settings, draft);
        assert!(merged.get("direct_dns_upstream").is_none());
        assert!(merged.get("direct_dns_tls_name").is_none());
        // 上游留空就是关闭，写成 null；读回来仍是空。
        let off = merge_profile(&profile, SaveScope::Settings, |field| match field {
            ProfileField::DirectDnsUpstream => String::new(),
            other => draft(other),
        });
        assert_eq!(off["direct_dns_upstream"], Value::Null);
        assert!(off.get("direct_dns_upstream").is_some());
        assert_eq!(saved_text(&off, upstream), "");
        // 自定义值原样写入；TLS 名称留空回到默认（不写）。
        let custom = merge_profile(&profile, SaveScope::Settings, |field| match field {
            ProfileField::DirectDnsUpstream => "119.29.29.29:443".into(),
            ProfileField::DirectDnsTlsName => String::new(),
            other => draft(other),
        });
        assert_eq!(custom["direct_dns_upstream"], json!("119.29.29.29:443"));
        assert!(custom.get("direct_dns_tls_name").is_none());
        assert_eq!(saved_text(&custom, upstream), "119.29.29.29:443");
        // 这两个字段属于设置页。
        assert_eq!(upstream.scope(), SaveScope::Settings);
        assert_eq!(name.scope(), SaveScope::Settings);
    }

    #[test]
    fn every_profile_field_has_a_distinct_key() {
        for (index, field) in ProfileField::ALL.iter().enumerate() {
            assert!(
                ProfileField::ALL[..index]
                    .iter()
                    .all(|other| other.key() != field.key()),
                "duplicate key {}",
                field.key()
            );
        }
    }

    #[test]
    fn saving_rules_keeps_the_saved_settings() {
        let profile = merge_profile(&saved(), SaveScope::Policy, draft);
        assert_eq!(
            profile["direct_ips"],
            json!(["192.0.2.0/24", "198.51.100.7"])
        );
        assert_eq!(profile["first_hop"], "127.0.0.1:7892");
        assert_eq!(profile["max_tcp_connections"], 128);
        assert!(profile.get("tcp_idle_timeout_seconds").is_none());
        assert_eq!(profile["allow_loopback_residential"], false);
    }

    #[test]
    fn saving_settings_keeps_the_saved_rules() {
        let profile = merge_profile(&saved(), SaveScope::Settings, draft);
        assert_eq!(profile["first_hop"], "127.0.0.1:1080");
        assert_eq!(profile["tcp_idle_timeout_seconds"], 600);
        // 留空的转发限制回到默认值，字段不写进策略。
        assert!(profile.get("max_tcp_connections").is_none());
        assert_eq!(profile["direct_ips"], json!(["192.0.2.0/24"]));
    }

    #[test]
    fn the_environment_page_leaves_the_shared_profile_as_saved() {
        let profile = merge_profile(&saved(), SaveScope::Environment, draft);
        assert_eq!(profile, saved());
    }

    #[test]
    fn a_rules_save_carries_only_the_shared_profile() {
        let request = request(PageDraft::Policy);
        assert_eq!(request["command"], "profile_save");
        assert_eq!(request["expected_revision"], "7");
        // 住宅代理、入口端口和目标都不在共用配置里。
        for key in ["desktop", "residential"] {
            assert!(request.get(key).is_none(), "{key}");
        }
        assert_eq!(request["profile"]["first_hop"], "127.0.0.1:7892");
        assert_eq!(
            request["profile"]["direct_ips"],
            json!(["192.0.2.0/24", "198.51.100.7"])
        );
        let settings = super::save_request(
            &Saved {
                profile: &saved(),
                revision: &json!("7"),
            },
            PageDraft::Settings { fake_ip: true },
            draft,
        );
        assert_eq!(settings["profile"]["first_hop"], "127.0.0.1:1080");
        assert_eq!(settings["profile"]["direct_ips"], json!(["192.0.2.0/24"]));
    }

    #[test]
    fn the_fake_ip_switch_is_written_only_when_off_and_only_by_the_settings_page() {
        let off = request(PageDraft::Settings { fake_ip: false });
        assert_eq!(off["profile"]["fake_ip"], json!(false));
        let on = request(PageDraft::Settings { fake_ip: true });
        assert!(on["profile"].get("fake_ip").is_none());
        assert!(saved_fake_ip(&json!({})));
        assert!(!saved_fake_ip(&json!({"fake_ip": false})));
        // The rules page keeps a saved `false` as it is.
        let mut profile = saved();
        profile["fake_ip"] = json!(false);
        let revision = json!("7");
        let record = Saved {
            profile: &profile,
            revision: &revision,
        };
        let request = save_request(&record, PageDraft::Policy, draft);
        assert_eq!(request["profile"]["fake_ip"], json!(false));
    }

    #[test]
    fn an_environment_save_names_its_environment_and_revision() {
        let residential = json!({"protocol": "socks5", "ip": "203.0.113.9", "port": 1080, "username": "user", "password": "secret"});
        let first = environment_save_request("{4444}", residential.clone(), None, &Value::Null);
        assert_eq!(first["command"], "environment_residential_save");
        assert_eq!(first["distro_id"], "{4444}");
        assert_eq!(first["residential"], residential);
        // 不传端口：后台沿用或分配。
        assert_eq!(first["ingress_port"], Value::Null);
        assert_eq!(first["expected_revision"], Value::Null);
        let later = environment_save_request("{4444}", residential, Some(44000), &json!("3"));
        assert_eq!(later["ingress_port"], 44000);
        assert_eq!(later["expected_revision"], "3");
    }

    #[test]
    fn finds_an_environment_row_by_id_without_regard_to_case() {
        let rows = [
            json!({"distro_id": "{aaaa}", "revision": "1", "ingress_port": 43531,
                "residential": {"ip": "203.0.113.9", "port": 1080}}),
            json!({"distro_id": "{bbbb}", "revision": "2", "ingress_port": 43532,
                "residential": {"ip": "", "port": 0}}),
        ];
        assert_eq!(
            environment_row(&rows, "{AAAA}").map(|row| &row["ingress_port"]),
            Some(&json!(43531))
        );
        assert!(environment_row(&rows, "{cccc}").is_none());
        assert!(residential_configured(environment_row(&rows, "{aaaa}")));
        // 保存过空的住宅代理（例如清空后）不算配置好。
        assert!(!residential_configured(environment_row(&rows, "{bbbb}")));
        assert!(!residential_configured(None));
    }

    #[test]
    fn edits_on_one_page_do_not_mark_the_other_unsaved() {
        let rules_only = |field: ProfileField| match field {
            ProfileField::DirectDomains => "example.net".to_owned(),
            _ => saved_text(&saved(), field),
        };
        assert!(profile_changed(&saved(), SaveScope::Policy, rules_only));
        assert!(!profile_changed(&saved(), SaveScope::Settings, rules_only));
        // 环境页不写共用配置里的字段。
        assert!(!profile_changed(
            &saved(),
            SaveScope::Environment,
            rules_only
        ));
        assert_eq!(super::profile_fields(SaveScope::Environment).count(), 0);
    }

    #[test]
    fn names_the_pages_with_unsaved_edits() {
        assert_eq!(Unsaved::default().pages(), None);
        let settings = Unsaved {
            settings: true,
            ..Unsaved::default()
        };
        assert_eq!(settings.pages().as_deref(), Some("设置页"));
        assert!(!settings.contains(SaveScope::Policy));
        let both = Unsaved {
            policy: true,
            settings: true,
            ..Unsaved::default()
        };
        assert_eq!(both.pages().as_deref(), Some("规则页、设置页"));
        let all = Unsaved {
            environment: true,
            policy: true,
            settings: true,
        };
        assert_eq!(all.pages().as_deref(), Some("环境页、规则页、设置页"));
    }

    #[test]
    fn an_unconfigured_residential_proxy_can_be_saved_empty() {
        let empty =
            json!({"protocol": "socks5", "ip": "", "port": 0, "username": "", "password": ""});
        assert_eq!(
            residential_value("socks5", "", "", "", ""),
            Ok(empty.clone())
        );
        assert_eq!(
            residential_value("socks5", "", "0", "", ""),
            Ok(empty.clone())
        );
        // 已保存的空记录显示成四个空框，和输入框比较时不算改过。
        for key in ["ip", "port", "username", "password"] {
            assert_eq!(saved_residential_text(&empty, key), "");
        }
        assert_eq!(
            residential_value("socks5", "203.0.113.9", "1080", "user", "secret"),
            Ok(
                json!({"protocol": "socks5", "ip": "203.0.113.9", "port": 1080, "username": "user", "password": "secret"})
            )
        );
        assert_eq!(
            saved_residential_text(&json!({"port": 1080}), "port"),
            "1080"
        );
        // 填了一部分时端口必须有效。
        assert!(residential_value("socks5", "203.0.113.9", "", "", "").is_err());
        assert!(residential_value("socks5", "", "0", "user", "").is_err());
        assert!(residential_value("socks5", "203.0.113.9", "70000", "user", "secret").is_err());
    }

    #[test]
    fn an_http_residential_proxy_keeps_its_protocol_and_refuses_a_colon_username() {
        assert_eq!(
            residential_value("http", "203.0.113.9", "8080", "user", "secret"),
            Ok(
                json!({"protocol": "http", "ip": "203.0.113.9", "port": 8080, "username": "user", "password": "secret"})
            )
        );
        assert!(residential_value("http", "203.0.113.9", "8080", "a:b", "secret").is_err());
        assert!(residential_value("socks5", "203.0.113.9", "1080", "a:b", "secret").is_ok());
        assert_eq!(
            saved_residential_protocol(&json!({"protocol": "http"})),
            "http"
        );
        // 没存过协议的旧配置按 SOCKS5。
        assert_eq!(saved_residential_protocol(&json!({"ip": ""})), "socks5");
        assert_eq!(saved_residential_protocol(&Value::Null), "socks5");
    }

    #[test]
    fn a_reconnect_reloads_only_pages_without_edits() {
        let settings_edited = Unsaved {
            settings: true,
            ..Unsaved::default()
        };
        assert_eq!(
            settings_edited.clean_pages().collect::<Vec<_>>(),
            [SaveScope::Environment, SaveScope::Policy]
        );
        assert_eq!(
            Unsaved::default().clean_pages().collect::<Vec<_>>(),
            [
                SaveScope::Environment,
                SaveScope::Policy,
                SaveScope::Settings
            ]
        );
    }

    #[test]
    fn a_failed_save_stays_on_its_own_page() {
        let mut failed = FailedSaves::default();
        failed.insert(SaveScope::Policy);
        failed.insert(SaveScope::Settings);
        failed.remove(SaveScope::Settings);
        assert!(failed.contains(SaveScope::Policy));
        assert!(!failed.contains(SaveScope::Settings));
        assert!(!failed.contains(SaveScope::Environment));
    }
}
