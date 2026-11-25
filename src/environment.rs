//! WSL distribution lifecycle helpers used by the desktop environment manager.
//!
//! The controller only ever handles registered distributions.  Import and export
//! are kept here so the desktop IPC layer can validate one request and delegate
//! all process execution to the host adapter without constructing shell commands.

pub(crate) mod timezone;

use crate::host::{self, Distro};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const IMPORT_DEADLINE: Duration = Duration::from_secs(10 * 60);
const CONFIGURE_DEADLINE: Duration = Duration::from_secs(20 * 60);
const EXPORT_DEADLINE: Duration = Duration::from_secs(30 * 60);
const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(30 * 60);
/// The read-only feature view runs inline while the daemon holds the controller
/// lock, so status and stop wait behind it. Enough for a cold distro start.
const INSPECT_DEADLINE: Duration = Duration::from_secs(60);

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

/// `wsl_conf_set <section> <key> <value>` sets one key in /etc/wsl.conf (or
/// `$wsl_conf`) and keeps every other section, key and comment. The first change
/// in a run saves the previous file as `<conf>.wsl-proxy-backup`.
const WSL_CONF_SET: &str = r#"wsl_conf_backed_up=0
wsl_conf_set() {
    conf=${wsl_conf:-/etc/wsl.conf}
    if [ -f "$conf" ] && [ "$wsl_conf_backed_up" = 0 ]; then
        cp -p "$conf" "$conf.wsl-proxy-backup"
        wsl_conf_backed_up=1
    fi
    [ -f "$conf" ] || : > "$conf"
    awk -v section="$1" -v key="$2" -v value="$3" '
        function finish() {
            if (in_section && !written) { print key "=" value; written = 1 }
        }
        /^[ \t]*\[/ {
            finish()
            header = $0
            sub(/^[ \t]*\[[ \t]*/, "", header)
            sub(/[ \t]*\].*$/, "", header)
            in_section = (tolower(header) == tolower(section))
            if (in_section) { found = 1 }
            print
            next
        }
        in_section && index($0, "=") > 0 {
            name = $0
            sub(/=.*$/, "", name)
            gsub(/^[ \t]+|[ \t]+$/, "", name)
            if (tolower(name) == tolower(key)) {
                if (!written) { print key "=" value; written = 1 }
                next
            }
        }
        { print }
        END {
            finish()
            if (!found) { printf "\n[%s]\n%s=%s\n", section, key, value }
        }
    ' "$conf" > "$conf.wsl-proxy-tmp"
    cat "$conf.wsl-proxy-tmp" > "$conf"
    rm -f "$conf.wsl-proxy-tmp"
}
"#;

fn setup_script(options: InstallOptions) -> String {
    // Only `create` supplies a username. Every run enables systemd so an edited
    // distribution can become a takeover target; a newly created environment
    // also always gets the base packages and a default user. Editing never
    // changes an existing [user] default.
    let new_environment = if options.username.is_some() { "1" } else { "0" };
    let wsl_conf_set = WSL_CONF_SET;
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
new_environment={new_environment}
install_zsh={install_zsh}
install_chrome={install_chrome}
install_chinese={install_chinese}
environment_user={username}
environment_password={password}
timezone={timezone}

{wsl_conf_set}

if [ -n "$timezone" ]; then
    if [ -r "/usr/share/zoneinfo/$timezone" ]; then
        ln -sf "/usr/share/zoneinfo/$timezone" /etc/localtime
        printf '%s\n' "$timezone" > /etc/timezone
    else
        echo 'environment_timezone_not_found' >&2
        exit 21
    fi
fi

install_components=0
if [ "$install_zsh" = 1 ] || [ "$install_chrome" = 1 ] || [ "$install_chinese" = 1 ]; then
    install_components=1
fi
if [ "$install_components" = 1 ] && ! command -v apt-get >/dev/null 2>&1; then
    echo 'environment_setup_requires_apt' >&2
    exit 20
fi
# A new environment always gets systemd and iptables (the takeover needs both),
# even when no optional component was selected.
run_apt=$install_components
if [ "$new_environment" = 1 ] && command -v apt-get >/dev/null 2>&1; then
    run_apt=1
fi
if [ "$run_apt" = 1 ]; then
    apt-get update
    packages=""
    if [ "$install_zsh" = 1 ] && apt-cache show zsh >/dev/null 2>&1; then
        packages="$packages zsh"
    fi
    if [ "$install_chinese" = 1 ]; then
        # The GTK frontends are recommends of fcitx5, so --no-install-recommends
        # drops them; without im-fcitx5.so, GTK apps such as Chrome ignore
        # GTK_IM_MODULE=fcitx.
        for package in locales language-pack-zh-hans fcitx5 fcitx5-chinese-addons \
            fcitx5-frontend-gtk3 fcitx5-frontend-gtk4 im-config; do
            if apt-cache show "$package" >/dev/null 2>&1; then
                packages="$packages $package"
            fi
        done
    fi
    for package in systemd systemd-sysv iptables; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            packages="$packages $package"
        fi
    done
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
# Windows starts GUI programs without a login shell, so the variables from
# /etc/profile.d are not present; export them here as well.
export LANG=zh_CN.UTF-8
export LANGUAGE=zh_CN:zh
export LC_ALL=zh_CN.UTF-8
if command -v fcitx5 >/dev/null 2>&1 && [ -n "${{DISPLAY:-}}${{WAYLAND_DISPLAY:-}}" ]; then
    export GTK_IM_MODULE=fcitx
    export QT_IM_MODULE=fcitx
    export XMODIFIERS=@im=fcitx
    # WSLg refuses the Wayland input-method protocol, and fcitx5 exits right
    # away unless its Wayland frontend is disabled.  The GTK module keeps
    # working through X11 (XWayland) and the session bus.
    if ! command -v pgrep >/dev/null 2>&1 || ! pgrep -x fcitx5 >/dev/null 2>&1; then
        fcitx5 -d --disable=wayland >/dev/null 2>&1 || true
        sleep 1
    fi
fi
browser=""
if command -v google-chrome-stable >/dev/null 2>&1; then
    browser=google-chrome-stable
elif command -v google-chrome >/dev/null 2>&1; then
    browser=google-chrome
else
    exit 127
fi
launch_args="--lang=zh-CN --accept-lang=zh-CN,zh --disable-quic --disable-features=AsyncDns"
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
    if ! command -v pgrep >/dev/null 2>&1 || ! pgrep -x fcitx5 >/dev/null 2>&1; then
        # WSLg refuses the Wayland input-method protocol, and fcitx5 exits
        # right away unless that frontend is disabled.
        fcitx5 -d --disable=wayland >/dev/null 2>&1 || true
    fi
fi
PROFILE
        cat > /etc/skel/.config/autostart/fcitx5.desktop <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Fcitx 5
Exec=fcitx5 -d --disable=wayland
X-GNOME-Autostart-enabled=true
DESKTOP
        if [ -d /root ]; then
            install -d -m 0755 /root/.config/autostart
            cp /etc/skel/.config/autostart/fcitx5.desktop /root/.config/autostart/fcitx5.desktop
        fi
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
fi

# Only the keys this tool owns are written; every other wsl.conf setting stays.
# The takeover needs systemd, so it is enabled on create and on every edit.
wsl_conf_set boot systemd true
if [ -n "$environment_user" ]; then
    wsl_conf_set user default "$environment_user"
fi
if [ -n "$timezone" ]; then
    wsl_conf_set time useWindowsTimezone false
fi
"#
    )
}

/// Read-only facts for the detail view. Every value is printed as a JSON string
/// or a literal `true`/`false`, so a missing tool yields `""` or `false` and
/// never breaks the single JSON line. The fixed PATH also keeps `command -v`
/// from walking the Windows directories WSL appends.
fn inspect_script() -> &'static str {
    r#"#!/bin/sh
set +e
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
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
# `wsl_conf_get <section> <key>` prints the first value of that key in
# /etc/wsl.conf (or `$wsl_conf`), matched without regard to letter case.
wsl_conf_get() {
    conf=${wsl_conf:-/etc/wsl.conf}
    [ -r "$conf" ] || return 0
    awk -v section="$1" -v key="$2" '
        /^[ \t]*\[/ {
            header = $0
            sub(/^[ \t]*\[[ \t]*/, "", header)
            sub(/[ \t]*\].*$/, "", header)
            in_section = (tolower(header) == tolower(section))
            next
        }
        in_section && !seen && index($0, "=") > 0 {
            name = $0
            sub(/=.*$/, "", name)
            gsub(/^[ \t]+|[ \t]+$/, "", name)
            if (tolower(name) == tolower(key)) {
                value = $0
                sub(/^[^=]*=/, "", value)
                sub(/[ \t]+[#;].*$/, "", value)
                gsub(/^[ \t]+|[ \t\r]+$/, "", value)
                print value
                seen = 1
            }
        }
    ' "$conf" 2>/dev/null
}
digits() {
    case "$1" in
        ''|*[!0-9]*) ;;
        *) printf '%s' "$1" ;;
    esac
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
# Pieces the current setup script installs. An environment made by an older
# version can have fcitx5 without them, and the IME then does not work in Chrome.
zh_locale=false
if locale -a 2>/dev/null | grep -Eiq '^zh_CN\.utf-?8$'; then zh_locale=true; fi
fcitx5_gtk=false
for module in /usr/lib/*/gtk-3.0/*/immodules/im-fcitx5.so /usr/lib/gtk-3.0/*/immodules/im-fcitx5.so /usr/lib64/gtk-3.0/*/immodules/im-fcitx5.so; do
    if [ -e "$module" ]; then fcitx5_gtk=true; break; fi
done
input_profile=missing
if [ -f /etc/profile.d/wsl-proxy-chinese-input.sh ]; then
    input_profile=outdated
    if grep -q -e '--disable=wayland' /etc/profile.d/wsl-proxy-chinese-input.sh 2>/dev/null; then input_profile=current; fi
fi
chrome_launcher=missing
if [ -f /usr/local/bin/chrome ]; then
    chrome_launcher=outdated
    if grep -q 'GTK_IM_MODULE' /usr/local/bin/chrome 2>/dev/null; then chrome_launcher=current; fi
fi
# Takeover basics, reported as facts; preflight decides whether takeover works.
systemd_configured=false
case "$(wsl_conf_get boot systemd | tr 'A-Z' 'a-z')" in true) systemd_configured=true ;; esac
pid1=$(head -n 1 /proc/1/comm 2>/dev/null)
default_user=$(wsl_conf_get user default)
wslg=false
if [ -d /mnt/wslg ] && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then wslg=true; fi
display_number=${DISPLAY:-}
display_number=${display_number#*:}
display_number=$(digits "${display_number%%.*}")
x11_socket=false
if [ -n "$display_number" ] && [ -S "/tmp/.X11-unix/X$display_number" ]; then x11_socket=true; fi
# Only the root file system: df without a path would stat every drvfs mount.
# The disk grows on demand, so the total is a ceiling, not space taken on Windows.
disk=$(df -Pk / 2>/dev/null | awk 'NR == 2 { print $2 " " $3 }')
disk_total_kb=$(digits "${disk%% *}")
disk_used_kb=$(digits "${disk##* }")
printf '{"zsh":%s,"chrome":%s,"chinese":%s,"input_method":%s,"locale":"%s","timezone":"%s","distribution":"%s","kernel":"%s","architecture":"%s",' \
    "$(has zsh)" "$chrome" "$(has fcitx5)" "$input_method" \
    "$(json_string "$locale_name")" "$(json_string "$timezone_name")" \
    "$(json_string "$distribution_name")" "$(json_string "$kernel_name")" \
    "$(json_string "$architecture")"
printf '"zh_locale":%s,"fcitx5_gtk":%s,"input_profile":"%s","chrome_launcher":"%s",' \
    "$zh_locale" "$fcitx5_gtk" "$input_profile" "$chrome_launcher"
printf '"systemd_configured":%s,"pid1":"%s","iptables_legacy":%s,"ip6tables_legacy":%s,' \
    "$systemd_configured" "$(json_string "$pid1")" "$(has iptables-legacy)" "$(has ip6tables-legacy)"
printf '"default_user":"%s","wslg":%s,"x11_socket":%s,"disk_total_kb":"%s","disk_used_kb":"%s"}\n' \
    "$(json_string "$default_user")" "$wslg" "$x11_socket" "$disk_total_kb" "$disk_used_kb"
"#
}

fn feature_view(distro: &Distro) -> Result<Value, String> {
    let output = host::guest_script_with_timeout(distro, inspect_script(), INSPECT_DEADLINE)?;
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

/// Undo a failed `create`. The download and setup take many minutes, so another
/// tool may have registered the same name meanwhile. Unregister only an entry
/// whose ID did not exist before this request and whose storage is this
/// request's destination; anything else is left alone and reported. Only an
/// empty directory is removed.
fn rollback_create(name: &str, destination: &Path, before: &[String], failure: String) -> String {
    let unregistered = match registered_distribution(name) {
        Ok(Some(distro)) if created_by_request(&distro, before, destination) => host::wsl_command(
            &["--unregister".into(), distro.name.clone()],
            None,
            IMPORT_DEADLINE,
        )
        .map(|_| ()),
        Ok(Some(distro)) => Err(format!(
            "environment_rollback_refused:{} was not created by this request",
            distro.name
        )),
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    let _ = fs::remove_dir(destination);
    match unregistered {
        Ok(()) => format!("{failure};environment_import_rolled_back"),
        Err(cleanup_error) => format!("{failure};environment_cleanup_failed:{cleanup_error}"),
    }
}

/// `create` refused an existing destination, so storage at or under it can
/// only come from this request (WSL may keep the disk in a subdirectory).
fn created_by_request(distro: &Distro, before: &[String], destination: &Path) -> bool {
    !before.iter().any(|id| id.eq_ignore_ascii_case(&distro.id))
        && within_windows_path(&distro.base_path, &destination.to_string_lossy())
}

/// Registry paths may carry the `\\?\` prefix, forward slashes or a trailing
/// separator; letter case is not significant on Windows.
fn within_windows_path(path: &str, directory: &str) -> bool {
    let normal = |path: &str| {
        let path = path
            .strip_prefix(r"\\?\")
            .unwrap_or(path)
            .replace('/', "\\");
        path.trim_end_matches('\\').to_lowercase()
    };
    let (path, directory) = (normal(path), normal(directory));
    !path.is_empty()
        && !directory.is_empty()
        && (path == directory
            || path
                .strip_prefix(&directory)
                .is_some_and(|rest| rest.starts_with('\\')))
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

fn write_progress(name: &str, phase: &str, percent: u8, stage: &str, detail: &str) {
    let Ok(directory) = host::data_dir() else {
        return;
    };
    if fs::create_dir_all(&directory).is_err() {
        return;
    }
    let path = directory.join(format!("environment-progress-{name}.json"));
    let temporary = directory.join(format!("environment-progress-{name}.tmp"));
    let value = json!({
        "phase": phase,
        "percent": percent,
        "stage": stage,
        "detail": detail
    });
    if fs::write(&temporary, value.to_string()).is_ok() {
        let _ = fs::remove_file(&path);
        let _ = fs::rename(temporary, path);
    }
}

fn clear_progress(name: &str) {
    if let Ok(directory) = host::data_dir() {
        let _ = fs::remove_file(directory.join(format!("environment-progress-{name}.json")));
        let _ = fs::remove_file(directory.join(format!("environment-progress-{name}.tmp")));
    }
}

/// `--name` and `--location` exist only in newer WSL releases. An older
/// wsl.exe rejects the argument and echoes it, so that case gets its own code
/// telling the user to update WSL instead of a generic install failure.
fn install_failure(error: String) -> String {
    if error.contains("--location") {
        format!("environment_wsl_update_required:{error}")
    } else {
        format!("environment_distribution_install_failed:{error}")
    }
}

fn install_online_distribution(
    name: &str,
    distribution: &str,
    destination: &Path,
) -> Result<(), String> {
    let install_args = vec![
        "--install".into(),
        "--web-download".into(),
        "--distribution".into(),
        distribution.into(),
        "--location".into(),
        destination.to_string_lossy().into_owned(),
        "--name".into(),
        name.into(),
        "--no-launch".into(),
        "--version".into(),
        "2".into(),
    ];
    host::wsl_command(&install_args, None, DOWNLOAD_DEADLINE).map_err(install_failure)?;
    let installed = registered_distribution(name)?
        .ok_or_else(|| format!("environment_not_registered:{name}"))?;
    if installed.version != 2 {
        return Err(format!("environment_not_wsl2:{name}"));
    }
    Ok(())
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
    let registered = host::distributions()?;
    if registered
        .iter()
        .any(|distro| distro.name.eq_ignore_ascii_case(name))
    {
        return Err("environment_name_exists".into());
    }
    let before: Vec<String> = registered.into_iter().map(|distro| distro.id).collect();
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
    write_progress(
        name,
        "download",
        18,
        "下载发行版",
        "正在通过 wsl.exe 从微软官方源下载发行版",
    );
    let result = (|| {
        if let Err(error) = install_online_distribution(name, distribution, &destination) {
            return Err(rollback_create(name, &destination, &before, error));
        }
        write_progress(
            name,
            "initialize",
            52,
            "初始化用户和组件",
            "环境目录已创建，正在创建用户并安装组件",
        );
        let distro = match locate(name) {
            Ok(distro) => distro,
            Err(error) => {
                let failure = format!("environment_setup_failed:{error}");
                return Err(rollback_create(name, &destination, &before, failure));
            }
        };
        if let Err(error) =
            host::guest_script_with_timeout(&distro, &setup_script(options), CONFIGURE_DEADLINE)
        {
            let failure = format!("environment_setup_failed:{error}");
            return Err(rollback_create(name, &destination, &before, failure));
        }
        // Applies the new [boot] systemd and [user] default; nothing else runs
        // in a distribution created moments ago.
        let _ = host::wsl_command(
            &["--terminate".into(), distro.name.clone()],
            None,
            IMPORT_DEADLINE,
        );
        write_progress(
            name,
            "inspect",
            92,
            "检查环境",
            "正在读取发行版能力并确认创建结果",
        );
        view(name)
    })();
    clear_progress(name);
    result
}

pub(crate) fn edit(key: &str, options: InstallOptions) -> Result<Value, String> {
    if let Some(timezone) = options.timezone.as_deref()
        && !valid_timezone(timezone)
    {
        return Err("environment_timezone_invalid".into());
    }
    let distro = locate(key)?;
    write_progress(
        &distro.name,
        "initialize",
        52,
        "安装组件",
        "正在执行环境初始化脚本",
    );
    let result = (|| {
        host::guest_script_with_timeout(&distro, &setup_script(options), CONFIGURE_DEADLINE)
            .map_err(|error| format!("environment_setup_failed:{error}"))?;
        // Restart so [boot] systemd and [time] take effect. This stops every
        // process in the distribution; the desktop warns before submitting.
        let _ = host::wsl_command(
            &["--terminate".into(), distro.name.clone()],
            None,
            IMPORT_DEADLINE,
        );
        write_progress(
            &distro.name,
            "inspect",
            92,
            "检查环境",
            "正在读取组件能力并刷新环境详情",
        );
        view(&distro.name)
    })();
    clear_progress(&distro.name);
    result
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
        InstallOptions, absolute_path, created_by_request, inspect_script, setup_script,
        valid_distribution, valid_name, valid_password, valid_timezone, valid_username,
        within_windows_path,
    };
    use crate::host::Distro;
    use std::path::Path;

    #[test]
    fn rollback_only_claims_a_new_registration_stored_at_this_destination() {
        let distro = |id: &str, base_path: &str| Distro {
            id: id.into(),
            name: "Dev".into(),
            base_path: base_path.into(),
            version: 2,
        };
        let destination = Path::new(r"D:\WSL\Dev");
        let before = vec!["{11111111-1111-1111-1111-111111111111}".to_string()];
        let fresh = "{22222222-2222-2222-2222-222222222222}";
        assert!(created_by_request(
            &distro(fresh, r"\\?\d:\wsl\dev\"),
            &before,
            destination
        ));
        assert!(created_by_request(
            &distro(fresh, "D:/WSL/Dev"),
            &before,
            destination
        ));
        // Registered before this request, or stored somewhere else: never ours.
        assert!(!created_by_request(
            &distro("{11111111-1111-1111-1111-111111111111}", r"D:\WSL\Dev"),
            &before,
            destination
        ));
        assert!(!created_by_request(
            &distro(fresh, r"E:\Other\Dev"),
            &before,
            destination
        ));
        assert!(!created_by_request(
            &distro(fresh, ""),
            &before,
            destination
        ));
        assert!(created_by_request(
            &distro(fresh, r"D:\WSL\Dev\{22222222-2222-2222-2222-222222222222}"),
            &before,
            destination
        ));
        assert!(!within_windows_path(r"D:\WSL\Dev2", r"D:\WSL\Dev"));
        assert!(!within_windows_path(r"D:\WSL", r"D:\WSL\Dev"));
    }

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
        assert!(script.contains("fcitx5-frontend-gtk3"));
        assert!(script.contains("fcitx5-frontend-gtk4"));
        assert!(script.contains("fcitx5 -d --disable=wayland"));
        assert!(script.contains("GTK_IM_MODULE=fcitx"));
        assert_eq!(script.matches("export GTK_IM_MODULE=fcitx").count(), 2);
        assert!(script.contains("XMODIFIERS=@im=fcitx"));
        assert!(script.contains("zh_CN.UTF-8"));
        assert!(script.contains("google-chrome-stable"));
        assert!(script.contains("language-pack-zh-hans"));
        assert!(script.contains("fonts-noto-cjk"));
        assert!(script.contains("/usr/local/bin/chrome"));
        assert!(script.contains("--lang=zh-CN"));
        assert!(script.contains("--accept-lang=zh-CN,zh"));
        assert!(script.contains("--disable-quic"));
        assert!(script.contains("--disable-features=AsyncDns"));
        assert!(script.contains("alias chrome='/usr/local/bin/chrome'"));
        assert!(script.contains(">/dev/null 2>&1 </dev/null &"));
        assert!(script.contains("timezone=Asia/Shanghai"));
        assert!(script.contains("useradd --create-home --shell /bin/bash"));
        assert!(script.contains("new_environment=1"));
        assert!(script.contains("wsl_conf_set boot systemd true"));
        assert!(script.contains("wsl_conf_set user default \"$environment_user\""));
        assert!(script.contains("wsl_conf_set time useWindowsTimezone false"));
        assert!(script.contains("for package in systemd systemd-sysv iptables"));
        assert!(!script.contains("> /etc/wsl.conf"));
    }

    /// The detail view calls a file `current` only when it carries the marker the
    /// current setup writes, so the two scripts must agree on paths and markers.
    #[test]
    fn inspect_looks_for_what_the_current_setup_writes() {
        let setup = setup_script(InstallOptions {
            chrome: true,
            chinese: true,
            ..InstallOptions::default()
        });
        let inspect = inspect_script();
        let body = |start: &str, end: &str| {
            setup
                .split(start)
                .nth(1)
                .expect(start)
                .split(end)
                .next()
                .expect(end)
                .to_owned()
        };
        let profile = body(
            "cat > /etc/profile.d/wsl-proxy-chinese-input.sh <<'PROFILE'\n",
            "\nPROFILE\n",
        );
        let launcher = body("cat > /usr/local/bin/chrome <<'CHROME'\n", "\nCHROME\n");

        assert!(profile.contains("--disable=wayland"));
        assert!(
            inspect.contains(
                "grep -q -e '--disable=wayland' /etc/profile.d/wsl-proxy-chinese-input.sh"
            )
        );
        assert!(launcher.contains("GTK_IM_MODULE"));
        assert!(inspect.contains("grep -q 'GTK_IM_MODULE' /usr/local/bin/chrome"));
        assert!(setup.contains("fcitx5-frontend-gtk3"));
        assert!(inspect.contains("/gtk-3.0/*/immodules/im-fcitx5.so"));
        assert!(setup.contains("locale-gen zh_CN.UTF-8"));
        assert!(inspect.contains(r"'^zh_CN\.utf-?8$'"));
        assert!(setup.contains("wsl_conf_set boot systemd true"));
        assert!(inspect.contains("wsl_conf_get boot systemd"));
    }

    #[test]
    fn chrome_launcher_supplies_the_ime_environment_outside_a_login_shell() {
        let script = setup_script(InstallOptions {
            chrome: true,
            chinese: true,
            ..InstallOptions::default()
        });
        let launcher = script
            .split("cat > /usr/local/bin/chrome <<'CHROME'")
            .nth(1)
            .expect("chrome launcher")
            .split("\nCHROME\n")
            .next()
            .expect("launcher body");
        assert!(launcher.contains("export GTK_IM_MODULE=fcitx"));
        assert!(launcher.contains("export XMODIFIERS=@im=fcitx"));
        assert!(launcher.contains("pgrep -x fcitx5"));
        assert!(launcher.contains("fcitx5 -d --disable=wayland"));
    }

    #[test]
    fn old_wsl_rejecting_install_location_asks_for_an_update() {
        assert!(
            super::install_failure(
                "wsl_exit_failed: 1: Invalid command line argument: --location".into()
            )
            .starts_with("environment_wsl_update_required:")
        );
        assert!(
            super::install_failure("wsl_exit_failed: 1: network unreachable".into())
                .starts_with("environment_distribution_install_failed:")
        );
    }

    #[test]
    fn editing_never_marks_an_existing_distribution_as_new() {
        let script = setup_script(InstallOptions {
            timezone: Some("Asia/Shanghai".into()),
            ..InstallOptions::default()
        });
        assert!(script.contains("new_environment=0"));
        assert!(script.contains("environment_user=''"));
        // systemd is enabled on every edit, outside any create-only branch.
        assert!(script.contains("\nwsl_conf_set boot systemd true\n"));
    }

    #[cfg(unix)]
    #[test]
    fn setup_scripts_parse_as_posix_shell() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        for options in [
            InstallOptions {
                zsh: true,
                chrome: true,
                chinese: true,
                username: Some("dev".into()),
                password: Some("p@ss'word".into()),
                timezone: None,
            },
            InstallOptions {
                timezone: Some("Asia/Shanghai".into()),
                ..InstallOptions::default()
            },
        ] {
            let mut child = Command::new("sh")
                .arg("-n")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(setup_script(options).as_bytes())
                .unwrap();
            assert!(child.wait().unwrap().success());
        }
    }

    #[cfg(unix)]
    #[test]
    fn wsl_conf_set_keeps_unrelated_settings() {
        use std::fs;
        use std::process::Command;
        let directory = std::env::temp_dir().join(format!(
            "wpl-wsl-conf-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let conf = directory.join("wsl.conf");
        let original = "# keep me\n[boot]\ncommand = service ssh start\n\n[user]\ndefault = operator\n\n[network]\ngenerateResolvConf=false\n";
        fs::write(&conf, original).unwrap();
        let run = |calls: &str| {
            let script = format!(
                "set -eu\nwsl_conf='{}'\n{}\n{}\n",
                conf.display(),
                super::WSL_CONF_SET,
                calls
            );
            let status = Command::new("sh").arg("-c").arg(script).status().unwrap();
            assert!(status.success());
            fs::read_to_string(&conf).unwrap()
        };

        // Editing a timezone adds [time] and changes nothing else.
        let after = run("wsl_conf_set time useWindowsTimezone false");
        assert!(after.starts_with(original));
        assert!(after.ends_with("[time]\nuseWindowsTimezone=false\n"));
        let backup = conf.with_file_name("wsl.conf.wsl-proxy-backup");
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);

        // Re-setting replaces in place, also when the key had spaces around '='.
        let after = run(
            "wsl_conf_set boot systemd true\nwsl_conf_set user default builder\nwsl_conf_set time useWindowsTimezone false",
        );
        assert_eq!(
            after,
            "# keep me\n[boot]\ncommand = service ssh start\n\nsystemd=true\n[user]\ndefault=builder\n\n[network]\ngenerateResolvConf=false\n\n[time]\nuseWindowsTimezone=false\n"
        );
        assert_eq!(after.matches("useWindowsTimezone").count(), 1);
        assert!(!directory.join("wsl.conf.wsl-proxy-tmp").exists());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn inspect_script_reports_useful_runtime_context() {
        let script = inspect_script();
        assert!(script.contains("timezone"));
        assert!(script.contains("distribution"));
        assert!(script.contains("kernel"));
        assert!(script.contains("architecture"));
    }

    /// Runs the real inspect script with `sh` and a stand-in wsl.conf. Most of
    /// the probed tools and files are absent on a build host, which is exactly
    /// the case that must still produce one parseable line. Like the wsl.conf
    /// test above it needs a POSIX `sh`, so it only runs on Unix hosts.
    #[cfg(unix)]
    fn run_inspect(conf: &str) -> serde_json::Value {
        use std::fs;
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let directory = std::env::temp_dir().join(format!(
            "wpl-inspect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("wsl.conf");
        fs::write(&path, conf).unwrap();
        let mut child = Command::new("sh")
            .arg("-s")
            .env("wsl_conf", &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(inspect_script().as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let _ = fs::remove_dir_all(directory);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let line = stdout
            .lines()
            .find(|line| line.trim_start().starts_with('{'))
            .expect("one JSON line");
        serde_json::from_str(line).expect("valid JSON")
    }

    #[cfg(unix)]
    #[test]
    fn inspect_script_prints_every_fact_as_valid_json() {
        let facts = run_inspect("");
        for key in [
            "zsh",
            "chrome",
            "chinese",
            "input_method",
            "zh_locale",
            "fcitx5_gtk",
            "systemd_configured",
            "iptables_legacy",
            "ip6tables_legacy",
            "wslg",
            "x11_socket",
        ] {
            assert!(facts[key].is_boolean(), "{key} = {}", facts[key]);
        }
        for key in [
            "locale",
            "timezone",
            "distribution",
            "kernel",
            "architecture",
            "pid1",
            "default_user",
            "disk_total_kb",
            "disk_used_kb",
        ] {
            assert!(facts[key].is_string(), "{key} = {}", facts[key]);
        }
        for key in ["disk_total_kb", "disk_used_kb"] {
            let value = facts[key].as_str().unwrap();
            assert!(
                value.bytes().all(|byte| byte.is_ascii_digit()),
                "{key} = {value}"
            );
        }
        for key in ["input_profile", "chrome_launcher"] {
            assert!(
                matches!(
                    facts[key].as_str(),
                    Some("current" | "outdated" | "missing")
                ),
                "{key} = {}",
                facts[key]
            );
        }
        assert_eq!(facts["systemd_configured"], false);
        assert_eq!(facts["default_user"], "");
    }

    #[cfg(unix)]
    #[test]
    fn inspect_script_reads_wsl_conf_like_the_setup_writes_it() {
        let facts = run_inspect(
            "# default=commented\n[Boot]\n  SystemD = True  # set by hand\n[user]\ndefault = builder\ndefault = second\n[network]\ndefault=other\n",
        );
        assert_eq!(facts["systemd_configured"], true);
        assert_eq!(facts["default_user"], "builder");

        let facts = run_inspect("[boot]\nsystemd=false\n[user]\n");
        assert_eq!(facts["systemd_configured"], false);
        assert_eq!(facts["default_user"], "");
    }
}
