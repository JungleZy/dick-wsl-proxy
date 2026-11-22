//! WSL distribution lifecycle helpers used by the desktop environment manager.
//!
//! The controller only ever handles registered distributions.  Import and export
//! are kept here so the desktop IPC layer can validate one request and delegate
//! all process execution to the host adapter without constructing shell commands.

use crate::host::{self, Distro};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

const IMPORT_DEADLINE: Duration = Duration::from_secs(10 * 60);
const CONFIGURE_DEADLINE: Duration = Duration::from_secs(20 * 60);
const EXPORT_DEADLINE: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InstallOptions {
    pub(crate) zsh: bool,
    pub(crate) chrome: bool,
    pub(crate) chinese: bool,
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn absolute_path(path: &str, field: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.contains('\0') {
        return Err(format!("{field}_required"));
    }
    let value = PathBuf::from(path);
    if !value.is_absolute() {
        return Err(format!("{field}_must_be_absolute"));
    }
    Ok(value)
}

fn locate(key: &str) -> Result<Distro, String> {
    let all = host::distributions()?;
    let mut matches = all.into_iter().filter(|distro| {
        distro.name.eq_ignore_ascii_case(key) || distro.id.eq_ignore_ascii_case(key)
    });
    let distro = matches
        .next()
        .ok_or_else(|| format!("environment_not_found:{key}"))?;
    if matches.next().is_some() {
        return Err(format!("environment_ambiguous:{key}"));
    }
    if distro.version != 2 {
        return Err(format!("environment_not_wsl2:{}", distro.name));
    }
    Ok(distro)
}

fn setup_script(options: InstallOptions) -> String {
    let install_zsh = if options.zsh { "1" } else { "0" };
    let install_chrome = if options.chrome { "1" } else { "0" };
    let install_chinese = if options.chinese { "1" } else { "0" };
    format!(
        r#"#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
install_zsh={install_zsh}
install_chrome={install_chrome}
install_chinese={install_chinese}

if [ "$install_zsh" = 1 ] || [ "$install_chrome" = 1 ] || [ "$install_chinese" = 1 ]; then
if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    packages=""
    if [ "$install_zsh" = 1 ] && apt-cache show zsh >/dev/null 2>&1; then
        packages="$packages zsh"
    fi
    if [ "$install_chinese" = 1 ]; then
        for package in locales language-pack-zh-hans fcitx5 fcitx5-chinese-addons im-config; do
            if apt-cache show "$package" >/dev/null 2>&1; then
                packages="$packages $package"
            fi
        done
    fi
    if [ -n "$packages" ]; then
        # The package list is assembled from fixed package names above.
        apt-get install -y --no-install-recommends $packages
    fi

    if [ "$install_chrome" = 1 ]; then
        apt-get update
        apt-get install -y --no-install-recommends ca-certificates wget gnupg
        install -d -m 0755 /etc/apt/keyrings
        wget -qO- https://dl.google.com/linux/linux_signing_key.pub \
            | gpg --dearmor --yes -o /etc/apt/keyrings/google-chrome.gpg
        printf '%s\n' \
            'deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main' \
            > /etc/apt/sources.list.d/google-chrome.list
        apt-get update
        apt-get install -y --no-install-recommends google-chrome-stable
    fi

    if [ "$install_chinese" = 1 ]; then
        if [ -f /etc/locale.gen ]; then
            sed -i 's/^# *zh_CN.UTF-8 UTF-8/zh_CN.UTF-8 UTF-8/' /etc/locale.gen || true
        fi
        if command -v locale-gen >/dev/null 2>&1; then
            locale-gen zh_CN.UTF-8 || true
        fi
        if command -v update-locale >/dev/null 2>&1; then
            update-locale LANG=zh_CN.UTF-8 LANGUAGE=zh_CN:zh LC_ALL=zh_CN.UTF-8 || true
        fi
        if command -v im-config >/dev/null 2>&1; then
            im-config -n fcitx5 || true
        fi
        install -d -m 0755 /etc/profile.d /etc/skel/.config/autostart
        cat > /etc/profile.d/wsl-proxy-chinese-input.sh <<'PROFILE'
export LANG=zh_CN.UTF-8
export LANGUAGE=zh_CN:zh
export LC_ALL=zh_CN.UTF-8
export GTK_IM_MODULE=fcitx
export QT_IM_MODULE=fcitx
export XMODIFIERS=@im=fcitx
if command -v fcitx5 >/dev/null 2>&1 && [ -n "${{DISPLAY:-}}${{WAYLAND_DISPLAY:-}}" ]; then
    fcitx5 -d >/dev/null 2>&1 || true
fi
PROFILE
        cat > /etc/skel/.config/autostart/fcitx5.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Fcitx 5
Exec=fcitx5 -d
X-GNOME-Autostart-enabled=true
DESKTOP
        if [ -d /root ]; then
            install -d -m 0755 /root/.config/autostart
            cp /etc/skel/.config/autostart/fcitx5.desktop /root/.config/autostart/fcitx5.desktop
        fi
    fi
else
    echo 'environment_setup_requires_apt' >&2
    exit 20
fi
fi
"#
    )
}

fn inspect_script() -> &'static str {
    r#"#!/bin/sh
set +e
has() {
    if command -v "$1" >/dev/null 2>&1; then
        printf true
        return 0
    fi
    printf false
    return 1
}
locale_name=""
if command -v locale >/dev/null 2>&1; then locale_name=$(locale 2>/dev/null | sed -n 's/^LANG=//p' | head -n 1); fi
input_method=false
if [ -f /etc/profile.d/wsl-proxy-chinese-input.sh ] || command -v fcitx5 >/dev/null 2>&1; then input_method=true; fi
chrome=false
if command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1; then chrome=true; fi
printf '{"zsh":%s,"chrome":%s,"chinese":%s,"input_method":%s,"locale":"%s"}\n' \
    "$(has zsh)" "$chrome" "$(has fcitx5)" "$input_method" "$locale_name"
"#
}

fn feature_view(distro: &Distro) -> Result<Value, String> {
    let output = host::guest_script_with_timeout(distro, inspect_script(), CONFIGURE_DEADLINE)?;
    let line = output
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or_else(|| "environment_inspect_invalid_output".to_owned())?;
    serde_json::from_str(line).map_err(|_| "environment_inspect_invalid_json".into())
}

fn distro_view(distro: &Distro, features: Value) -> Value {
    json!({
        "id": distro.id,
        "name": distro.name,
        "base_path": distro.base_path,
        "version": distro.version,
        "features": features,
    })
}

fn rollback_import(name: &str, setup_error: String) -> String {
    let args = vec!["--unregister".into(), name.into()];
    match host::wsl_command(&args, None, IMPORT_DEADLINE) {
        Ok(_) => format!("environment_setup_failed:{setup_error};environment_import_rolled_back"),
        Err(cleanup_error) => format!(
            "environment_setup_failed:{setup_error};environment_cleanup_failed:{cleanup_error}"
        ),
    }
}

pub(crate) fn view(key: &str) -> Result<Value, String> {
    let distro = locate(key)?;
    let features = feature_view(&distro)?;
    Ok(distro_view(&distro, features))
}

pub(crate) fn create(
    name: &str,
    source_tar: &str,
    install_dir: &str,
    options: InstallOptions,
) -> Result<Value, String> {
    if !valid_name(name) {
        return Err("environment_name_invalid".into());
    }
    if host::distributions()?
        .iter()
        .any(|distro| distro.name.eq_ignore_ascii_case(name))
    {
        return Err("environment_name_exists".into());
    }
    let source = absolute_path(source_tar, "environment_source")?;
    if !source.is_file() {
        return Err("environment_source_not_found".into());
    }
    let destination = absolute_path(install_dir, "environment_install_dir")?;
    if destination.exists() {
        return Err("environment_install_dir_exists".into());
    }
    let args = vec![
        "--import".into(),
        name.into(),
        destination.to_string_lossy().into_owned(),
        source.to_string_lossy().into_owned(),
        "--version".into(),
        "2".into(),
    ];
    host::wsl_command(&args, None, IMPORT_DEADLINE)?;
    let distro = match locate(name) {
        Ok(distro) => distro,
        Err(error) => return Err(rollback_import(name, error)),
    };
    if let Err(error) =
        host::guest_script_with_timeout(&distro, &setup_script(options), CONFIGURE_DEADLINE)
    {
        return Err(rollback_import(&distro.name, error));
    }
    view(name)
}

pub(crate) fn edit(key: &str, options: InstallOptions) -> Result<Value, String> {
    let distro = locate(key)?;
    host::guest_script_with_timeout(&distro, &setup_script(options), CONFIGURE_DEADLINE)
        .map_err(|error| format!("environment_setup_failed:{error}"))?;
    view(&distro.name)
}

pub(crate) fn backup(key: &str, destination: &str) -> Result<Value, String> {
    let distro = locate(key)?;
    let destination = absolute_path(destination, "environment_backup")?;
    if destination.exists() {
        return Err("environment_backup_exists".into());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "environment_backup_parent_invalid".to_owned())?;
    if !parent.is_dir() {
        return Err("environment_backup_parent_not_found".into());
    }
    let args = vec![
        "--export".into(),
        distro.name.clone(),
        destination.to_string_lossy().into_owned(),
    ];
    host::wsl_command(&args, None, EXPORT_DEADLINE)?;
    if !Path::new(&destination).is_file() {
        return Err("environment_backup_output_missing".into());
    }
    Ok(json!({"name":distro.name,"path":destination}))
}

#[cfg(test)]
mod tests {
    use super::{InstallOptions, setup_script, valid_name};

    #[test]
    fn validates_wsl_names_without_shell_metacharacters() {
        assert!(valid_name("Ubuntu-Dev_01"));
        assert!(!valid_name(""));
        assert!(!valid_name("../tmp"));
        assert!(!valid_name("name;touch"));
        assert!(!valid_name("中文"));
    }

    #[test]
    fn chinese_setup_script_configures_locale_and_fcitx() {
        let script = setup_script(InstallOptions {
            zsh: true,
            chrome: true,
            chinese: true,
        });
        assert!(script.contains("fcitx5-chinese-addons"));
        assert!(script.contains("GTK_IM_MODULE=fcitx"));
        assert!(script.contains("XMODIFIERS=@im=fcitx"));
        assert!(script.contains("zh_CN.UTF-8"));
        assert!(script.contains("google-chrome-stable"));
    }
}
