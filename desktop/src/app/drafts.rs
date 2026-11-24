//! 每页只保存自己的字段：规则页存直连规则，设置页存代理链、DNS、转发限制、入口端口和
//! 住宅代理，环境页确认后只存接管目标。后台每次保存整份配置，所以保存请求以已保存的值
//! 打底，只换上本页输入框里的内容。

use serde_json::{Value, json};

/// 有保存动作的三个页面。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaveScope {
    /// 环境页：接管目标。点「设为目标」确认后立即保存，没有未保存状态。
    Environment,
    /// 规则页：直连规则。
    Policy,
    /// 设置页：代理链、DNS、转发限制、Windows 入口端口和住宅代理。
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
            Self::Environment => "保存接管目标",
            Self::Policy => "保存规则",
            Self::Settings => "保存设置",
        }
    }

    pub(crate) fn saved_notice(self) -> &'static str {
        match self {
            Self::Environment => "接管目标已保存；不会立即改变当前接管。",
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
    Value::Object(profile)
}

/// 设置页住宅代理四项要保存的值，参数是输入框里去掉首尾空白的文字。四项都空表示还没
/// 配置，按后台的空记录发（端口为 0）；填了任何一项，端口就必须是 1–65535 的整数，
/// 其余由后台校验。
pub(crate) fn residential_value(
    ip: &str,
    port: &str,
    username: &str,
    password: &str,
) -> Result<Value, &'static str> {
    if ip.is_empty() && username.is_empty() && password.is_empty() && matches!(port, "" | "0") {
        return Ok(json!({"ip": "", "port": 0, "username": "", "password": ""}));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
        .ok_or("住宅服务器端口需为 1–65535 的整数。")?;
    Ok(json!({"ip": ip, "port": port, "username": username, "password": password}))
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

/// 后台最近一次返回的已保存配置里，各页保存时要原样带上的部分。
pub(crate) struct Saved<'a> {
    pub(crate) profile: &'a Value,
    pub(crate) revision: &'a Value,
    pub(crate) target: Option<&'a str>,
    pub(crate) port: u16,
}

/// 一次保存里本页的内容；输入框的值已经校验过。
pub(crate) enum PageDraft {
    /// 环境页：要保存的接管目标，`None` 表示清除目标。
    Environment(Option<String>),
    /// 规则页：直连规则全在策略里，由 `draft` 给出。
    Policy,
    /// 设置页：Windows 入口端口和住宅代理，其余字段在策略里，由 `draft` 给出。
    Settings { port: u16, residential: Value },
}

impl PageDraft {
    pub(crate) fn scope(&self) -> SaveScope {
        match self {
            Self::Environment(_) => SaveScope::Environment,
            Self::Policy => SaveScope::Policy,
            Self::Settings { .. } => SaveScope::Settings,
        }
    }
}

/// 一次保存的请求：只有本页的内容取输入，目标、入口端口、住宅代理和其他页的策略字段
/// 都用已保存的值。不是设置页的保存不带住宅代理，后台沿用已保存的那份。
pub(crate) fn save_request(
    saved: &Saved<'_>,
    page: PageDraft,
    draft: impl Fn(ProfileField) -> String,
) -> Value {
    let profile = merge_profile(saved.profile, page.scope(), draft);
    let saved_target = saved.target.map(str::to_owned);
    let (target, port, residential) = match page {
        PageDraft::Environment(target) => (target, saved.port, None),
        PageDraft::Policy => (saved_target, saved.port, None),
        PageDraft::Settings { port, residential } => (saved_target, port, Some(residential)),
    };
    let mut request = json!({
        "command": "profile_save",
        "profile": profile,
        "expected_revision": saved.revision,
        "desktop": {"target": target, "port": port},
    });
    if let Some(residential) = residential {
        request["residential"] = residential;
    }
    request
}

/// 这个发行版就是保存的目标 `target`。和后台认目标的规则一致：名称完全相同，
/// 或者 ID 不区分大小写相同。
pub(crate) fn names_target(distro: &Value, target: &str) -> bool {
    distro["name"].as_str() == Some(target)
        || distro["id"]
            .as_str()
            .is_some_and(|id| id.eq_ignore_ascii_case(target))
}

/// 保存的接管目标已经不能用了：发行版列表里没有它，或者它不再是 WSL 2。
///
/// 列表里只要有一条不是后台的发行版格式（字符串 `id`、`name`，数字 `version`），
/// 就说明两边协议对不上，判断不了，一律当作「还在」：自动清除会改写用户保存的配置，
/// 宁可不清。
pub(crate) fn target_missing(saved: Option<&str>, distributions: &[Value]) -> bool {
    let well_formed = |distro: &Value| {
        distro["id"].is_string() && distro["name"].is_string() && distro["version"].is_u64()
    };
    saved.is_some_and(|target| {
        distributions.iter().all(well_formed)
            && !distributions
                .iter()
                .any(|distro| names_target(distro, target) && distro["version"] == 2)
    })
}

/// 规则页、设置页各自有没有没保存的输入。环境页选了目标就立即保存，没有草稿。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Unsaved {
    pub(crate) policy: bool,
    pub(crate) settings: bool,
}

impl Unsaved {
    pub(crate) fn contains(self, scope: SaveScope) -> bool {
        match scope {
            SaveScope::Environment => false,
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

    /// 第一个有未保存输入的页面。
    pub(crate) fn first(self) -> Option<SaveScope> {
        [SaveScope::Policy, SaveScope::Settings]
            .into_iter()
            .find(|scope| self.contains(*scope))
    }

    /// 有未保存输入的页面，例如「规则页、设置页」；都保存了时为 `None`。
    pub(crate) fn pages(self) -> Option<String> {
        let pages = [SaveScope::Policy, SaveScope::Settings]
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
        FailedSaves, PageDraft, ProfileField, SaveScope, Saved, Unsaved, merge_profile,
        profile_changed, residential_value, save_request, saved_residential_text, saved_text,
        target_missing,
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
            target: Some("{11111111-1111-1111-1111-111111111111}"),
            port: 43531,
        };
        save_request(&record, page, draft)
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
    fn saving_the_target_leaves_the_profile_as_saved() {
        let profile = merge_profile(&saved(), SaveScope::Environment, draft);
        assert_eq!(profile, saved());
    }

    #[test]
    fn a_rules_save_carries_the_saved_target_port_and_residential() {
        let request = request(PageDraft::Policy);
        assert_eq!(request["command"], "profile_save");
        assert_eq!(request["expected_revision"], "7");
        assert_eq!(
            request["desktop"],
            json!({"target": "{11111111-1111-1111-1111-111111111111}", "port": 43531})
        );
        // 不带住宅代理，后台沿用已保存的。
        assert!(request.get("residential").is_none());
        assert_eq!(request["profile"]["first_hop"], "127.0.0.1:7892");
        assert_eq!(
            request["profile"]["direct_ips"],
            json!(["192.0.2.0/24", "198.51.100.7"])
        );
    }

    #[test]
    fn a_settings_save_carries_its_port_and_residential_but_the_saved_target() {
        let residential =
            json!({"ip": "203.0.113.9", "port": 1080, "username": "user", "password": "secret"});
        let request = request(PageDraft::Settings {
            port: 44000,
            residential: residential.clone(),
        });
        assert_eq!(
            request["desktop"],
            json!({"target": "{11111111-1111-1111-1111-111111111111}", "port": 44000})
        );
        assert_eq!(request["residential"], residential);
        assert_eq!(request["profile"]["first_hop"], "127.0.0.1:1080");
        assert_eq!(request["profile"]["direct_ips"], json!(["192.0.2.0/24"]));
    }

    #[test]
    fn a_target_save_changes_only_the_target() {
        let chosen = request(PageDraft::Environment(Some(
            "{44444444-4444-4444-4444-444444444444}".into(),
        )));
        assert_eq!(
            chosen["desktop"],
            json!({"target": "{44444444-4444-4444-4444-444444444444}", "port": 43531})
        );
        assert!(chosen.get("residential").is_none());
        assert_eq!(chosen["profile"], saved());
        // 清除目标时发 null。
        let cleared = request(PageDraft::Environment(None));
        assert_eq!(cleared["desktop"]["target"], Value::Null);
        assert_eq!(cleared["desktop"]["port"], 43531);
    }

    #[test]
    fn edits_on_one_page_do_not_mark_the_other_unsaved() {
        let rules_only = |field: ProfileField| match field {
            ProfileField::DirectDomains => "example.net".to_owned(),
            _ => saved_text(&saved(), field),
        };
        assert!(profile_changed(&saved(), SaveScope::Policy, rules_only));
        assert!(!profile_changed(&saved(), SaveScope::Settings, rules_only));
        assert!(!profile_changed(
            &saved(),
            SaveScope::Environment,
            rules_only
        ));
    }

    #[test]
    fn a_saved_target_is_missing_only_when_no_wsl2_distribution_matches() {
        let distributions = [
            json!({"id": "{11111111-1111-1111-1111-111111111111}", "name": "Test-Target", "version": 2}),
            json!({"id": "{22222222-2222-2222-2222-222222222222}", "name": "Legacy-One", "version": 1}),
        ];
        assert!(!target_missing(None, &distributions));
        assert!(!target_missing(
            Some("{11111111-1111-1111-1111-111111111111}"),
            &distributions
        ));
        // 和后台一样，ID 不区分大小写。
        assert!(!target_missing(
            Some(
                "{11111111-1111-1111-1111-111111111111}"
                    .to_uppercase()
                    .as_str()
            ),
            &distributions
        ));
        // 旧版本按名称保存的目标也算存在。
        assert!(!target_missing(Some("Test-Target"), &distributions));
        // 已被删除或注销。
        assert!(target_missing(
            Some("{33333333-3333-3333-3333-333333333333}"),
            &distributions
        ));
        // 转成了 WSL 1。
        assert!(target_missing(
            Some("{22222222-2222-2222-2222-222222222222}"),
            &distributions
        ));
        assert!(target_missing(Some("Test-Target"), &[]));
        // 后台改了字段名或类型：判断不了，不能把用户保存的目标清掉。
        for drifted in [
            json!({"id": "{11111111-1111-1111-1111-111111111111}", "name": "Test-Target", "wsl_version": 2}),
            json!({"id": "{11111111-1111-1111-1111-111111111111}", "name": "Test-Target", "version": "2"}),
            json!({"distribution_id": "{11111111-1111-1111-1111-111111111111}", "name": "Test-Target", "version": 2}),
        ] {
            assert!(!target_missing(Some("Test-Target"), &[drifted]));
        }
    }

    #[test]
    fn names_the_pages_with_unsaved_edits() {
        assert_eq!(Unsaved::default().pages(), None);
        assert_eq!(Unsaved::default().first(), None);
        let settings = Unsaved {
            policy: false,
            settings: true,
        };
        assert_eq!(settings.pages().as_deref(), Some("设置页"));
        assert_eq!(settings.first(), Some(SaveScope::Settings));
        assert!(!settings.contains(SaveScope::Policy));
        let both = Unsaved {
            policy: true,
            settings: true,
        };
        assert_eq!(both.pages().as_deref(), Some("规则页、设置页"));
        assert_eq!(both.first(), Some(SaveScope::Policy));
    }

    #[test]
    fn an_unconfigured_residential_proxy_can_be_saved_empty() {
        let empty = json!({"ip": "", "port": 0, "username": "", "password": ""});
        assert_eq!(residential_value("", "", "", ""), Ok(empty.clone()));
        assert_eq!(residential_value("", "0", "", ""), Ok(empty.clone()));
        // 已保存的空记录显示成四个空框，和输入框比较时不算改过。
        for key in ["ip", "port", "username", "password"] {
            assert_eq!(saved_residential_text(&empty, key), "");
        }
        assert_eq!(
            residential_value("203.0.113.9", "1080", "user", "secret"),
            Ok(
                json!({"ip": "203.0.113.9", "port": 1080, "username": "user", "password": "secret"})
            )
        );
        assert_eq!(
            saved_residential_text(&json!({"port": 1080}), "port"),
            "1080"
        );
        // 填了一部分时端口必须有效。
        assert!(residential_value("203.0.113.9", "", "", "").is_err());
        assert!(residential_value("", "0", "user", "").is_err());
        assert!(residential_value("203.0.113.9", "70000", "user", "secret").is_err());
    }

    #[test]
    fn a_reconnect_reloads_only_pages_without_edits() {
        let settings_edited = Unsaved {
            policy: false,
            settings: true,
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
