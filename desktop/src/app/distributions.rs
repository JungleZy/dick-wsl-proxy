use gpui_kit::component::select::{SearchableVec, SelectGroup};

pub(crate) fn official_distributions() -> SearchableVec<SelectGroup<&'static str>> {
    let mut groups = SearchableVec::new(vec![]);
    groups.push(SelectGroup::new("Ubuntu").items([
        "Ubuntu-26.04",
        "Ubuntu-24.04",
        "Ubuntu-22.04",
        "Ubuntu",
    ]));
    groups.push(SelectGroup::new("Debian 系").items(["Debian", "kali-linux"]));
    groups.push(SelectGroup::new("openSUSE").items(["openSUSE-Tumbleweed", "openSUSE-Leap-16.1"]));
    groups.push(SelectGroup::new("SUSE 企业版").items([
        "SUSE-Linux-Enterprise-15-SP7",
        "SUSE-Linux-Enterprise-16.1",
        "SUSE-Linux-Enterprise-15-SP6",
    ]));
    groups.push(SelectGroup::new("RHEL 兼容").items([
        "RLCPPlus-9",
        "RLCPPlus-10",
        "AlmaLinux-8",
        "AlmaLinux-9",
        "AlmaLinux-Kitten-10",
        "AlmaLinux-10",
    ]));
    groups.push(SelectGroup::new("其他发行版").items([
        "archlinux",
        "FedoraLinux-45",
        "FedoraLinux-44",
        "eLxr",
        "AzureLinux-4",
        "OracleLinux_7_9",
        "OracleLinux_8_10",
        "OracleLinux_9_5",
    ]));
    groups
}
