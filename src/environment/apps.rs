//! Desktop applications installed in a distribution, and starting one of them.
//!
//! Both run as the distribution's default user, never root: listing reads that
//! user's own entries too, and an app started from the desktop belongs to that
//! user like one started from its shell. The desktop only ever names an entry
//! by its desktop-file ID; the command line is read from that file inside the
//! distribution, so no command text travels over the desktop channel.

use super::{INSPECT_DEADLINE, locate};
use crate::host;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::Duration;

/// How long a launch is watched for a failure right at the start (entry gone,
/// program missing). A program still running by then counts as started.
const LAUNCH_SETTLE: Duration = Duration::from_millis(1500);

/// Where desktop entries live, highest precedence first: an ID found in an
/// earlier directory hides the same ID in later ones, as in the XDG menu spec.
const APPLICATION_DIRS: &str = r#""$HOME/.local/share/applications" \
    "$HOME/.local/share/flatpak/exports/share/applications" \
    /var/lib/flatpak/exports/share/applications \
    /var/lib/snapd/desktop/applications \
    /usr/local/share/applications \
    /usr/share/applications"#;

/// The setup script's Chrome launcher. Chrome's own entries (it installs
/// `google-chrome.desktop` and `com.google.Chrome.desktop`) run the browser
/// directly and would skip the launcher's en-US language, input method
/// variables and startup flags, so a browser command is sent through it.
const CHROME_LAUNCHER: &str = "/usr/local/bin/chrome";

/// Desktop-file IDs as found on disk, limited to characters that need no
/// quoting anywhere. Entries with other names (spaces, for example) are not
/// listed and cannot be launched.
pub(crate) fn valid_app_id(id: &str) -> bool {
    let Some(stem) = id.strip_suffix(".desktop") else {
        return false;
    };
    !stem.is_empty()
        && id.len() <= 255
        && stem.as_bytes()[0].is_ascii_alphanumeric()
        && stem.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b'+')
        })
}

/// Where an `Icon=` name is looked up, in order: the hicolor theme every app
/// installs into (largest raster sizes first, then scalable), then pixmaps.
const ICON_THEME_DIRS: &str = r#""$HOME/.local/share/icons/hicolor" \
        "$HOME/.local/share/flatpak/exports/share/icons/hicolor" \
        /var/lib/flatpak/exports/share/icons/hicolor \
        /usr/local/share/icons/hicolor \
        /usr/share/icons/hicolor"#;

/// Prints one `ID<TAB>name<TAB>icon` line per entry worth showing in a
/// launcher: `Type=Application` with an `Exec`, not hidden, not a terminal
/// program (no console window exists to show it), not limited to one desktop
/// environment (WSLg runs no desktop environment) and with its `TryExec`
/// program present. `icon` is the real path of a PNG or SVG file for the
/// entry's `Icon=`, or `-` when none is found.
fn list_script() -> String {
    format!(
        r#"#!/bin/sh
set +e
PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
export PATH
set --
for dir in {APPLICATION_DIRS}; do
    [ -d "$dir" ] || continue
    for file in "$dir"/*.desktop; do
        [ -f "$file" ] && set -- "$@" "$file"
    done
done
[ "$#" -gt 0 ] || exit 0
tab=$(printf '\t')
# Prints the real path of the icon file for an `Icon=` value, or nothing.
resolve_icon() {{
    icon=$1
    case "$icon" in
        ''|-) return ;;
        /*)
            case "$icon" in *.png|*.svg|*.PNG|*.SVG) ;; *) return ;; esac
            [ -f "$icon" ] && readlink -f "$icon"
            return
            ;;
    esac
    icon=${{icon%.png}}
    icon=${{icon%.svg}}
    icon=${{icon%.xpm}}
    for size in 256x256 128x128 512x512 96x96 64x64 48x48 scalable; do
        for theme in {ICON_THEME_DIRS}; do
            for ext in png svg; do
                candidate="$theme/$size/apps/$icon.$ext"
                if [ -f "$candidate" ]; then
                    readlink -f "$candidate"
                    return
                fi
            done
        done
    done
    for ext in png svg; do
        if [ -f "/usr/share/pixmaps/$icon.$ext" ]; then
            readlink -f "/usr/share/pixmaps/$icon.$ext"
            return
        fi
    done
}}
awk '
function reset() {{
    file = FILENAME; group = ""; type = ""; command = ""; tryexec = ""
    name = ""; name_zh_cn = ""; name_zh = ""
    nodisplay = ""; hidden = ""; terminal = ""; onlyshowin = ""; icon = ""
}}
function flush(    id, label) {{
    if (file == "") return
    id = file
    sub(/^.*\//, "", id)
    if (id in seen) return
    seen[id] = 1
    if (type != "Application" || command == "") return
    if (nodisplay == "true" || hidden == "true" || terminal == "true" || onlyshowin != "") return
    label = name_zh_cn != "" ? name_zh_cn : (name_zh != "" ? name_zh : name)
    gsub(/[\t\r]/, " ", label)
    if (label == "") label = id
    gsub(/[\t\r]/, " ", tryexec)
    gsub(/[\t\r]/, " ", icon)
    # Empty fields become "-": read collapses runs of tabs.
    print id "\t" label "\t" (tryexec == "" ? "-" : tryexec) "\t" (icon == "" ? "-" : icon)
}}
FNR == 1 {{ flush(); reset() }}
/^[ \t]*#/ {{ next }}
/^[ \t]*\[/ {{
    group = $0
    sub(/^[ \t]*\[/, "", group)
    sub(/\][ \t\r]*$/, "", group)
    next
}}
group != "Desktop Entry" {{ next }}
index($0, "=") > 0 {{
    key = $0
    sub(/=.*$/, "", key)
    gsub(/^[ \t]+|[ \t]+$/, "", key)
    value = $0
    sub(/^[^=]*=/, "", value)
    gsub(/^[ \t]+|[ \t\r]+$/, "", value)
    if (key == "Type") type = value
    else if (key == "Exec") command = value
    else if (key == "TryExec") tryexec = value
    else if (key == "Name") name = value
    else if (key == "Name[zh_CN]") name_zh_cn = value
    else if (key == "Name[zh]") name_zh = value
    else if (key == "NoDisplay") nodisplay = tolower(value)
    else if (key == "Hidden") hidden = tolower(value)
    else if (key == "Terminal") terminal = tolower(value)
    else if (key == "OnlyShowIn") onlyshowin = value
    else if (key == "Icon") icon = value
}}
END {{ flush() }}
' "$@" 2>/dev/null | while IFS="$tab" read -r id label tryexec icon; do
    if [ "$tryexec" != - ]; then
        case "$tryexec" in
            /*) [ -x "$tryexec" ] || continue ;;
            *) command -v "$tryexec" >/dev/null 2>&1 || continue ;;
        esac
    fi
    path=$(resolve_icon "$icon" | tr -d '\t\r\n')
    printf '%s\t%s\t%s\n' "$id" "$label" "${{path:--}}"
done
"#
    )
}

/// Runs in a login shell, so `/etc/profile.d` (the input method variables)
/// applies as in a terminal. Exit codes: 66 entry not found, 65 entry without
/// a usable `Exec`, 127 program not installed. The body is a function so the
/// shell has read the whole script from standard input before `exec`.
fn launch_script() -> String {
    format!(
        r#"set -u
main() {{
    id=$1
    file=""
    for dir in {APPLICATION_DIRS}; do
        if [ -f "$dir/$id" ]; then
            file=$dir/$id
            break
        fi
    done
    [ -n "$file" ] || exit 66
    cd "$HOME" 2>/dev/null || cd /
    command_line=$(awk '
        /^[ \t]*\[/ {{
            group = $0
            sub(/^[ \t]*\[/, "", group)
            sub(/\][ \t\r]*$/, "", group)
            next
        }}
        group == "Desktop Entry" && /^[ \t]*Exec[ \t]*=/ {{
            sub(/^[^=]*=[ \t]*/, "")
            sub(/[ \t\r]+$/, "")
            print
            exit
        }}
    ' "$file" 2>/dev/null)
    [ -n "$command_line" ] || exit 65
    # Field codes stand for files or URLs to open; none are passed here.
    command_line=$(printf '%s' "$command_line" | sed 's/%[fFuUdDnNickvm]//g; s/%%/%/g')
    eval "set -- $command_line" 2>/dev/null || exit 65
    [ "$#" -gt 0 ] || exit 65
    case "$1" in
        google-chrome|google-chrome-stable|/usr/bin/google-chrome|/usr/bin/google-chrome-stable|/opt/google/chrome/google-chrome)
            if [ -x {CHROME_LAUNCHER} ]; then
                shift
                set -- {CHROME_LAUNCHER} "$@"
            fi
            ;;
    esac
    command -v "$1" >/dev/null 2>&1 || exit 127
    exec "$@" </dev/null >/dev/null 2>&1
}}
main "$@"
"#
    )
}

/// Turns the list script's lines into entries sorted by name. Lines that do
/// not carry a valid ID are dropped; a repeated ID keeps its first line. The
/// icon is kept only as an absolute path to a PNG or SVG file; the desktop
/// reads it through `\\wsl.localhost`.
fn parse_apps(output: &str) -> Vec<Value> {
    let mut seen = HashSet::new();
    let mut apps: Vec<(String, String, Option<String>)> = output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let id = fields.next()?.trim();
            let name = fields.next()?.trim();
            if !valid_app_id(id) || !seen.insert(id.to_owned()) {
                return None;
            }
            let name = if name.is_empty() {
                id.trim_end_matches(".desktop")
            } else {
                name
            };
            let icon = fields
                .next()
                .map(str::trim)
                .filter(|path| valid_icon_path(path));
            Some((id.to_owned(), name.to_owned(), icon.map(str::to_owned)))
        })
        .collect();
    apps.sort_by(|(left_id, left, _), (right_id, right, _)| {
        left.to_lowercase()
            .cmp(&right.to_lowercase())
            .then_with(|| left_id.cmp(right_id))
    });
    apps.into_iter()
        .map(|(id, name, icon)| json!({"id": id, "name": name, "icon": icon}))
        .collect()
}

fn valid_icon_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    path.starts_with('/')
        && path.len() <= 1024
        && (lower.ends_with(".png") || lower.ends_with(".svg"))
        && !path.chars().any(char::is_control)
        && !path.split('/').any(|part| part == "..")
}

fn launch_failure(error: String) -> String {
    match error.strip_prefix("guest_exit:") {
        Some("66") => "environment_app_not_found".into(),
        Some("65") => "environment_app_entry_invalid".into(),
        Some("127") => "environment_app_command_missing".into(),
        Some(code) => format!("environment_app_exited:{code}"),
        None => format!("environment_app_launch_failed:{error}"),
    }
}

pub(crate) fn list(key: &str) -> Result<Value, String> {
    let distro = locate(key)?;
    let output = host::user_script_with_timeout(&distro, &list_script(), INSPECT_DEADLINE)
        .map_err(|error| format!("environment_apps_failed:{error}"))?;
    Ok(json!({"name": distro.name, "apps": parse_apps(&output)}))
}

/// Starts one listed app. Starting it starts the distribution if it is not
/// running. Returns once the app is running or has failed at once.
pub(crate) fn launch(key: &str, app: &str) -> Result<Value, String> {
    if !valid_app_id(app) {
        return Err("environment_app_invalid".into());
    }
    let distro = locate(key)?;
    host::launch_user_script(&distro, &launch_script(), &[app.to_owned()], LAUNCH_SETTLE)
        .map_err(launch_failure)?;
    Ok(json!({"name": distro.name, "app": app}))
}

#[cfg(test)]
mod tests {
    use super::{launch_failure, launch_script, parse_apps, valid_app_id};
    use serde_json::json;

    #[test]
    fn app_ids_are_plain_desktop_file_names() {
        assert!(valid_app_id("google-chrome.desktop"));
        assert!(valid_app_id("org.gnome.TextEditor.desktop"));
        assert!(valid_app_id("firefox_firefox.desktop"));
        assert!(!valid_app_id(".desktop"));
        assert!(!valid_app_id("gedit"));
        assert!(!valid_app_id("-x.desktop"));
        assert!(!valid_app_id("../evil.desktop"));
        assert!(!valid_app_id("a b.desktop"));
        assert!(!valid_app_id("a;rm.desktop"));
        assert!(!valid_app_id("a$(x).desktop"));
    }

    #[test]
    fn listed_apps_are_sorted_by_name_and_deduplicated() {
        let output = "org.gnome.TextEditor.desktop\t文本编辑器\t/usr/share/icons/hicolor/scalable/apps/editor.svg\n\
                      google-chrome.desktop\tGoogle Chrome\t/opt/google/chrome/product_logo_256.png\n\
                      google-chrome.desktop\tShadowed copy\t-\n\
                      bad name.desktop\tSkipped\t-\n\
                      no-tab-line\n\
                      relative.desktop\tRelative\ticons/x.png\n\
                      xpm.desktop\tXpm\t/usr/share/pixmaps/x.xpm\n\
                      blank.desktop\t \t-\n";
        assert_eq!(
            parse_apps(output),
            [
                json!({"id": "blank.desktop", "name": "blank", "icon": null}),
                json!({
                    "id": "google-chrome.desktop",
                    "name": "Google Chrome",
                    "icon": "/opt/google/chrome/product_logo_256.png"
                }),
                json!({"id": "relative.desktop", "name": "Relative", "icon": null}),
                json!({"id": "xpm.desktop", "name": "Xpm", "icon": null}),
                json!({
                    "id": "org.gnome.TextEditor.desktop",
                    "name": "文本编辑器",
                    "icon": "/usr/share/icons/hicolor/scalable/apps/editor.svg"
                }),
            ]
        );
    }

    #[test]
    fn launch_exit_codes_become_specific_errors() {
        assert_eq!(
            launch_failure("guest_exit:66".into()),
            "environment_app_not_found"
        );
        assert_eq!(
            launch_failure("guest_exit:65".into()),
            "environment_app_entry_invalid"
        );
        assert_eq!(
            launch_failure("guest_exit:127".into()),
            "environment_app_command_missing"
        );
        assert_eq!(
            launch_failure("guest_exit:1".into()),
            "environment_app_exited:1"
        );
        assert_eq!(
            launch_failure("wsl_start_failed: denied".into()),
            "environment_app_launch_failed:wsl_start_failed: denied"
        );
    }

    #[test]
    fn chrome_goes_through_the_tool_launcher() {
        let script = launch_script();
        assert!(script.contains("/usr/bin/google-chrome-stable|"));
        assert!(script.contains("set -- /usr/local/bin/chrome \"$@\""));
        assert!(script.trim_end().ends_with("main \"$@\""));
    }

    /// Runs both scripts against a fake `$HOME` and system directory with the
    /// local `/bin/sh` and `awk`. Skipped where they are missing (Windows).
    #[cfg(unix)]
    #[test]
    fn scripts_list_and_resolve_entries_in_a_sandbox() {
        use super::list_script;
        use std::fs;
        use std::process::Command;
        let root = std::env::temp_dir().join(format!("wsl-proxy-apps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home = root.join("home");
        let user_apps = home.join(".local/share/applications");
        fs::create_dir_all(&user_apps).unwrap();
        let entry = |name: &str, body: &str| {
            fs::write(user_apps.join(name), format!("[Desktop Entry]\n{body}\n")).unwrap();
        };
        entry(
            "editor.desktop",
            "Type=Application\nName=Editor\nName[zh_CN]=编辑器\nExec=sh -c 'exit 0' %U\nIcon=wsl-proxy-test-editor",
        );
        let icon_dir = home.join(".local/share/icons/hicolor/128x128/apps");
        fs::create_dir_all(&icon_dir).unwrap();
        fs::write(icon_dir.join("wsl-proxy-test-editor.png"), b"png").unwrap();
        let absolute_icon = home.join("logo.svg");
        fs::write(&absolute_icon, b"svg").unwrap();
        entry(
            "absolute.desktop",
            &format!(
                "Type=Application\nName=Absolute\nExec=sh\nIcon={}",
                absolute_icon.display()
            ),
        );
        entry(
            "hidden.desktop",
            "Type=Application\nName=Hidden\nExec=sh\nNoDisplay=true",
        );
        entry(
            "console.desktop",
            "Type=Application\nName=Console\nExec=sh\nTerminal=true",
        );
        entry(
            "gnome-only.desktop",
            "Type=Application\nName=Panel\nExec=sh\nOnlyShowIn=GNOME;",
        );
        entry(
            "gone.desktop",
            "Type=Application\nName=Gone\nExec=sh\nTryExec=definitely-not-installed-x",
        );
        entry(
            "link.desktop",
            "Type=Link\nName=Link\nURL=https://example.invalid",
        );
        entry(
            "actions.desktop",
            "Type=Application\nName=Actions\nExec=sh -c 'exit 0'\n\n[Desktop Action new]\nName=Other\nExec=false",
        );
        entry(
            "missing.desktop",
            "Type=Application\nName=Missing\nExec=definitely-not-installed-x --flag",
        );

        let listed = Command::new("/bin/sh")
            .arg("-c")
            .arg(list_script())
            .env("HOME", &home)
            .output()
            .unwrap();
        let listed = String::from_utf8(listed.stdout).unwrap();
        let ids: Vec<_> = parse_apps(&listed)
            .into_iter()
            .map(|app| app["id"].as_str().unwrap().to_owned())
            .filter(|id| !id.starts_with("org.") || id.contains("editor"))
            .collect();
        for expected in ["actions.desktop", "editor.desktop", "missing.desktop"] {
            assert!(
                ids.iter().any(|id| id == expected),
                "{expected} not in {ids:?}"
            );
        }
        for skipped in [
            "hidden.desktop",
            "console.desktop",
            "gnome-only.desktop",
            "gone.desktop",
            "link.desktop",
        ] {
            assert!(!ids.iter().any(|id| id == skipped), "{skipped} listed");
        }
        let icon_of = |id: &str| {
            parse_apps(&listed)
                .into_iter()
                .find(|app| app["id"] == id)
                .map(|app| app["icon"].clone())
                .unwrap()
        };
        let canonical = |path: std::path::PathBuf| fs::canonicalize(path).unwrap();
        assert_eq!(
            icon_of("editor.desktop"),
            json!(canonical(icon_dir.join("wsl-proxy-test-editor.png")))
        );
        assert_eq!(
            icon_of("absolute.desktop"),
            json!(canonical(absolute_icon.clone()))
        );
        assert_eq!(icon_of("actions.desktop"), json!(null));
        assert!(listed.contains("editor.desktop\t编辑器\t"));

        let launch = |id: &str| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg(launch_script())
                .arg("sh")
                .arg(id)
                .env("HOME", &home)
                .status()
                .unwrap()
                .code()
        };
        assert_eq!(launch("editor.desktop"), Some(0));
        assert_eq!(launch("actions.desktop"), Some(0));
        assert_eq!(launch("missing.desktop"), Some(127));
        assert_eq!(launch("nowhere-to-be-found.desktop"), Some(66));
        entry("empty.desktop", "Type=Application\nName=Empty");
        assert_eq!(launch("empty.desktop"), Some(65));
        let _ = fs::remove_dir_all(&root);
    }
}
