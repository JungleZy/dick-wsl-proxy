//! WSL distribution lifecycle helpers used by the desktop environment manager.
//!
//! The controller only ever handles registered distributions.  Import and export
//! are kept here so the desktop IPC layer can validate one request and delegate
//! all process execution to the host adapter without constructing shell commands.

use crate::host::{self, Distro};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const IMPORT_DEADLINE: Duration = Duration::from_secs(10 * 60);
const CONFIGURE_DEADLINE: Duration = Duration::from_secs(20 * 60);
const EXPORT_DEADLINE: Duration = Duration::from_secs(30 * 60);
const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug, Default)]
pub(crate) struct InstallOptions {
    pub(crate) zsh: bool,
    pub(crate) chrome: bool,
    pub(crate) chinese: bool,
    pub(crate) username: Option<String>,
    pub(crate) password: Option<String>,
    pub(crate) timezone: Option<String>,
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

fn valid_timezone(timezone: &str) -> bool {
    !timezone.is_empty()
        && timezone.len() <= 128
        && !timezone.starts_with('/')
        && !timezone.ends_with('/')
        && !timezone.contains("..")
        && timezone.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'+' | b'-' | b'.')
        })
}

fn valid_distribution(distribution: &str) -> bool {
    !distribution.is_empty()
        && distribution.len() <= 64
        && !distribution.contains("..")
        && distribution
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_username(username: &str) -> bool {
    let mut chars = username.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    matches!(first, 'a'..='z' | '_')
        && username.len() <= 32
        && chars.all(|character| matches!(character, 'a'..='z' | '0'..='9' | '_' | '-'))
}

fn valid_password(password: &str) -> bool {
    !password.is_empty()
        && password.len() <= 256
        && !password
            .bytes()
            .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn absolute_path(path: &str, field: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.contains('\0') {
        return Err(format!("{field}_required"));
    }
    let value = PathBuf::from(path);
    if !value.is_absolute() {
        return Err(format!("{field}_must_be_absolute"));
    }
    #[cfg(windows)]
    {
        let bytes = path.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'\\' | b'/')
            || path[2..].contains(':')
        {
            return Err(format!("{field}_must_be_local_drive_path"));
        }
    }
    Ok(value)
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn assert_no_reparse(path: &Path, field: &str) -> Result<(), String> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_reparse(&metadata) => {
                return Err(format!("{field}_reparse_point"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("{field}_metadata:{error}")),
        }
    }
    Ok(())
}

fn require_existing_parent(path: &Path, field: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{field}_parent_invalid"))?;
    if !parent.is_dir() {
        return Err(format!("{field}_parent_not_found"));
    }
    assert_no_reparse(parent, field)
}

fn reject_existing_path(path: &Path, field: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!("{field}_exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{field}_metadata:{error}")),
    }
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
    let username = options
        .username
        .as_deref()
        .map(shell_quote)
        .unwrap_or_else(|| "''".into());
    let password = options
        .password
        .as_deref()
        .map(shell_quote)
        .unwrap_or_else(|| "''".into());
    let timezone = options.timezone.as_deref().unwrap_or("");
    format!(
        r#"#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
install_zsh={install_zsh}
install_chrome={install_chrome}
install_chinese={install_chinese}
environment_user={username}
environment_password={password}
timezone={timezone}

if [ -n "$timezone" ]; then
    if [ -r "/usr/share/zoneinfo/$timezone" ]; then
        ln -sf "/usr/share/zoneinfo/$timezone" /etc/localtime
        printf '%s\n' "$timezone" > /etc/timezone
    else
        echo 'environment_timezone_not_found' >&2
        exit 21
    fi
fi

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
        chrome_packages="ca-certificates wget gnupg"
        for package in locales language-pack-zh-hans language-pack-zh-hans-base fonts-noto-cjk fonts-noto-color-emoji; do
            if apt-cache show "$package" >/dev/null 2>&1; then
                chrome_packages="$chrome_packages $package"
            fi
        done
        apt-get install -y --no-install-recommends $chrome_packages
        install -d -m 0755 /etc/apt/keyrings
        wget -qO- https://dl.google.com/linux/linux_signing_key.pub \
            | gpg --dearmor --yes -o /etc/apt/keyrings/google-chrome.gpg
        printf '%s\n' \
            'deb [arch=amd64 signed-by=/etc/apt/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main' \
            > /etc/apt/sources.list.d/google-chrome.list
        apt-get update
        apt-get install -y --no-install-recommends google-chrome-stable
        cat > /usr/local/bin/chrome <<'CHROME'
#!/bin/sh
set -eu
browser=""
if command -v google-chrome-stable >/dev/null 2>&1; then
    browser=google-chrome-stable
elif command -v google-chrome >/dev/null 2>&1; then
    browser=google-chrome
else
    exit 127
fi
launch_args="--lang=zh-CN --accept-lang=zh-CN,zh"
if [ "$(id -u)" = 0 ]; then
    launch_args="$launch_args --no-sandbox"
fi
nohup "$browser" $launch_args "$@" >/dev/null 2>&1 </dev/null &
exit 0
CHROME
        chmod 0755 /usr/local/bin/chrome
        install -d -m 0755 /etc/profile.d
        cat > /etc/profile.d/wsl-proxy-chrome.sh <<'PROFILE'
if [ -x /usr/local/bin/chrome ]; then
    alias chrome='/usr/local/bin/chrome'
fi
PROFILE
    fi

    if [ "$install_chinese" = 1 ] || [ "$install_chrome" = 1 ]; then
        if [ -f /etc/locale.gen ]; then
            sed -i 's/^# *zh_CN.UTF-8 UTF-8/zh_CN.UTF-8 UTF-8/' /etc/locale.gen || true
        fi
        if command -v locale-gen >/dev/null 2>&1; then
            locale-gen zh_CN.UTF-8 || true
        fi
        if command -v update-locale >/dev/null 2>&1; then
            update-locale LANG=zh_CN.UTF-8 LANGUAGE=zh_CN:zh LC_ALL=zh_CN.UTF-8 || true
        fi
    fi

    if [ "$install_chinese" = 1 ]; then
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

if [ -n "$environment_user" ]; then
    if ! command -v useradd >/dev/null 2>&1 || ! command -v chpasswd >/dev/null 2>&1; then
        echo 'environment_user_tools_not_found' >&2
        exit 22
    fi
    if ! id "$environment_user" >/dev/null 2>&1; then
        useradd --create-home --shell /bin/bash "$environment_user"
    fi
    printf '%s:%s\n' "$environment_user" "$environment_password" | chpasswd
    if command -v getent >/dev/null 2>&1 && getent group sudo >/dev/null 2>&1 && command -v usermod >/dev/null 2>&1; then
        usermod --append --groups sudo "$environment_user" || true
    fi
    cat > /etc/wsl.conf <<WSL_CONF
[user]
default=$environment_user
WSL_CONF
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
json_string() {
    printf '%s' "$1" | tr -d '\r\n' | sed 's/\\/\\\\/g; s/"/\\"/g'
}
locale_name=""
if command -v locale >/dev/null 2>&1; then locale_name=$(locale 2>/dev/null | sed -n 's/^LANG=//p' | head -n 1); fi
timezone_name=""
if [ -r /etc/timezone ]; then timezone_name=$(sed -n '1p' /etc/timezone); fi
if [ -z "$timezone_name" ]; then timezone_name=$(date +%Z 2>/dev/null | head -n 1); fi
distribution_name=""
if [ -r /etc/os-release ]; then
    distribution_name=$(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | head -n 1 | sed 's/^"//; s/"$//')
fi
kernel_name=$(uname -r 2>/dev/null | head -n 1)
architecture=$(uname -m 2>/dev/null | head -n 1)
input_method=false
if [ -f /etc/profile.d/wsl-proxy-chinese-input.sh ] || command -v fcitx5 >/dev/null 2>&1; then input_method=true; fi
chrome=false
if command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1; then chrome=true; fi
printf '{"zsh":%s,"chrome":%s,"chinese":%s,"input_method":%s,"locale":"%s","timezone":"%s","distribution":"%s","kernel":"%s","architecture":"%s"}\n' \
    "$(has zsh)" "$chrome" "$(has fcitx5)" "$input_method" \
    "$(json_string "$locale_name")" "$(json_string "$timezone_name")" \
    "$(json_string "$distribution_name")" "$(json_string "$kernel_name")" \
    "$(json_string "$architecture")"
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

fn registered_distribution(key: &str) -> Result<Option<Distro>, String> {
    let mut matches = host::distributions()?.into_iter().filter(|distro| {
        distro.name.eq_ignore_ascii_case(key) || distro.id.eq_ignore_ascii_case(key)
    });
    let first = matches.next();
    if matches.next().is_some() {
        return Err(format!("environment_ambiguous:{key}"));
    }
    Ok(first)
}

fn online_archive_path(name: &str) -> Result<PathBuf, String> {
    let directory = host::state_dir()?;
    fs::create_dir_all(&directory)
        .map_err(|error| format!("environment_download_directory:{error}"))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "environment_download_clock".to_owned())?
        .as_nanos();
    let archive = directory.join(format!("environment-{name}-{timestamp}.tar"));
    reject_existing_path(&archive, "environment_download_archive")?;
    Ok(archive)
}

fn import_online_distribution(
    name: &str,
    distribution: &str,
    destination: &Path,
) -> Result<(), String> {
    let archive = online_archive_path(name)?;
    let existing = registered_distribution(distribution)?;
    let (source, temporary) = if let Some(source) = existing {
        (source, false)
    } else {
        let install_args = vec![
            "--install".into(),
            "--web-download".into(),
            "--distribution".into(),
            distribution.into(),
            "--no-launch".into(),
        ];
        if let Err(error) = host::wsl_command(&install_args, None, DOWNLOAD_DEADLINE) {
            return Err(format!("environment_distribution_download_failed:{error}"));
        }
        let source = registered_distribution(distribution)?
            .ok_or_else(|| format!("environment_distribution_not_registered:{distribution}"))?;
        (source, true)
    };
    // A prior interrupted export can leave the source registered as Exporting.
    // Terminating only this source clears that stale runtime state before taking
    // the snapshot and leaves the registered distribution intact.
    let _ = host::wsl_command(
        &["--terminate".into(), source.name.clone()],
        None,
        IMPORT_DEADLINE,
    );
    let export_args = vec![
        "--export".into(),
        source.name.clone(),
        archive.to_string_lossy().into_owned(),
    ];
    let export_result = host::wsl_command(&export_args, None, EXPORT_DEADLINE).and_then(|_| {
        let metadata = fs::symlink_metadata(&archive)
            .map_err(|error| format!("environment_download_archive_metadata:{error}"))?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err("environment_download_archive_invalid".into());
        }
        Ok(())
    });
    let cleanup_source = if temporary {
        host::wsl_command(
            &["--unregister".into(), source.name.clone()],
            None,
            IMPORT_DEADLINE,
        )
        .map(|_| ())
    } else {
        Ok(())
    };
    if let Err(error) = export_result {
        let _ = fs::remove_file(&archive);
        if let Err(cleanup_error) = cleanup_source {
            return Err(format!(
                "environment_distribution_export_failed:{error};environment_distribution_cleanup_failed:{cleanup_error}"
            ));
        }
        return Err(format!("environment_distribution_export_failed:{error}"));
    }
    if let Err(error) = cleanup_source {
        let _ = fs::remove_file(&archive);
        return Err(format!("environment_distribution_cleanup_failed:{error}"));
    }
    let import_args = vec![
        "--import".into(),
        name.into(),
        destination.to_string_lossy().into_owned(),
        archive.to_string_lossy().into_owned(),
        "--version".into(),
        "2".into(),
    ];
    let result = host::wsl_command(&import_args, None, IMPORT_DEADLINE);
    let _ = fs::remove_file(&archive);
    result.map(|_| ())
}

pub(crate) fn view(key: &str) -> Result<Value, String> {
    let distro = locate(key)?;
    let features = feature_view(&distro)?;
    Ok(distro_view(&distro, features))
}

pub(crate) fn create(
    name: &str,
    distribution: &str,
    install_dir: &str,
    options: InstallOptions,
) -> Result<Value, String> {
    if !valid_name(name) {
        return Err("environment_name_invalid".into());
    }
    if !valid_distribution(distribution) {
        return Err("environment_distribution_invalid".into());
    }
    let username = options
        .username
        .as_deref()
        .ok_or("environment_username_required")?;
    if !valid_username(username) {
        return Err("environment_username_invalid".into());
    }
    let password = options
        .password
        .as_deref()
        .ok_or("environment_password_required")?;
    if !valid_password(password) {
        return Err("environment_password_invalid".into());
    }
    if host::distributions()?
        .iter()
        .any(|distro| distro.name.eq_ignore_ascii_case(name))
    {
        return Err("environment_name_exists".into());
    }
    let base_directory = absolute_path(install_dir, "environment_install_dir")?;
    let destination = if base_directory
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(name))
    {
        base_directory
    } else {
        base_directory.join(name)
    };
    reject_existing_path(&destination, "environment_install_dir")?;
    require_existing_parent(&destination, "environment_install_dir")?;
    import_online_distribution(name, distribution, &destination)?;
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
    if let Some(timezone) = options.timezone.as_deref() {
        if !valid_timezone(timezone) {
            return Err("environment_timezone_invalid".into());
        }
    }
    let distro = locate(key)?;
    host::guest_script_with_timeout(&distro, &setup_script(options), CONFIGURE_DEADLINE)
        .map_err(|error| format!("environment_setup_failed:{error}"))?;
    view(&distro.name)
}

pub(crate) fn backup(key: &str, destination: &str) -> Result<Value, String> {
    let distro = locate(key)?;
    let destination = absolute_path(destination, "environment_backup")?;
    reject_existing_path(&destination, "environment_backup")?;
    require_existing_parent(&destination, "environment_backup")?;
    assert_no_reparse(&destination, "environment_backup")?;
    let args = vec![
        "--export".into(),
        distro.name.clone(),
        destination.to_string_lossy().into_owned(),
    ];
    host::wsl_command(&args, None, EXPORT_DEADLINE)?;
    let output = fs::symlink_metadata(&destination);
    if !output
        .as_ref()
        .is_ok_and(|metadata| metadata.is_file() && !is_reparse(metadata))
    {
        return Err("environment_backup_output_missing".into());
    }
    Ok(json!({"name":distro.name,"path":destination}))
}

pub(crate) fn remove(key: &str) -> Result<Value, String> {
    let distro = locate(key)?;
    let args = vec!["--unregister".into(), distro.name.clone()];
    host::wsl_command(&args, None, IMPORT_DEADLINE)?;
    Ok(json!({"id":distro.id,"name":distro.name}))
}

#[cfg(test)]
mod tests {
    use super::{
        InstallOptions, absolute_path, inspect_script, setup_script, valid_distribution,
        valid_name, valid_password, valid_timezone, valid_username,
    };

    #[test]
    fn validates_wsl_names_without_shell_metacharacters() {
        assert!(valid_name("Ubuntu-Dev_01"));
        assert!(!valid_name(""));
        assert!(!valid_name("../tmp"));
        assert!(!valid_name("name;touch"));
        assert!(!valid_name("中文"));
    }

    #[test]
    fn validates_timezone_names_without_path_traversal() {
        assert!(valid_timezone("Asia/Shanghai"));
        assert!(valid_timezone("Etc/UTC"));
        assert!(!valid_timezone("../UTC"));
        assert!(!valid_timezone("/etc/passwd"));
    }

    #[test]
    fn validates_online_distribution_and_linux_user_inputs() {
        assert!(valid_distribution("Ubuntu-24.04"));
        assert!(!valid_distribution("Ubuntu;unregister"));
        assert!(valid_username("dev_user-1"));
        assert!(!valid_username("Dev User"));
        assert!(valid_password("p@ss'word"));
        assert!(!valid_password("line\nbreak"));
    }

    #[test]
    fn requires_absolute_paths() {
        assert!(absolute_path("relative.tar", "source").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_unc_and_alternate_data_stream_paths() {
        assert!(absolute_path(r"\\server\share\rootfs.tar", "source").is_err());
        assert!(absolute_path(r"C:\safe\file:stream", "source").is_err());
    }

    #[test]
    fn chinese_setup_script_configures_locale_and_fcitx() {
        let script = setup_script(InstallOptions {
            zsh: true,
            chrome: true,
            chinese: true,
            username: Some("dev".into()),
            password: Some("p@ss'word".into()),
            timezone: Some("Asia/Shanghai".into()),
        });
        assert!(script.contains("fcitx5-chinese-addons"));
        assert!(script.contains("GTK_IM_MODULE=fcitx"));
        assert!(script.contains("XMODIFIERS=@im=fcitx"));
        assert!(script.contains("zh_CN.UTF-8"));
        assert!(script.contains("google-chrome-stable"));
        assert!(script.contains("language-pack-zh-hans"));
        assert!(script.contains("fonts-noto-cjk"));
        assert!(script.contains("/usr/local/bin/chrome"));
        assert!(script.contains("--lang=zh-CN"));
        assert!(script.contains("--accept-lang=zh-CN,zh"));
        assert!(script.contains("alias chrome='/usr/local/bin/chrome'"));
        assert!(script.contains(">/dev/null 2>&1 </dev/null &"));
        assert!(script.contains("timezone=Asia/Shanghai"));
        assert!(script.contains("useradd --create-home --shell /bin/bash"));
        assert!(script.contains("default=$environment_user"));
    }

    #[test]
    fn inspect_script_reports_useful_runtime_context() {
        let script = inspect_script();
        assert!(script.contains("timezone"));
        assert!(script.contains("distribution"));
        assert!(script.contains("kernel"));
        assert!(script.contains("architecture"));
    }
}
