// 升级前的判断、结果说明和安装器助手脚本的测试。
// 不用 `use super::*`：那会把 gpui 的 `test` 宏一起引进来，顶掉标准的 `#[test]`。
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;
use wsl_proxyctl::update::{self, UpdateError, Version};

use super::{
    Handoff, OUTPUT_LINES, Outcome, RESULT_NAME, describe, encode_command, helper_script,
    megabytes, outcome_text, overlaps, policy_allows, powershell, same_path, spawn_helper,
    updates_dir, upgrade_blocker,
};

fn outcome(ok: bool, stage: &str) -> Outcome {
    Outcome {
        ok,
        stage: stage.into(),
        version: "0.1.12".into(),
        from: "0.1.11".into(),
        install_dir: r"C:\Users\Tester\AppData\Local\Programs\WslProxy".into(),
        package: r"C:\Users\Tester\AppData\Local\WSLProxyLab\updates\0.1.12\package".into(),
        output: "line 1\n\nline 2".into(),
    }
}

#[test]
fn upgrades_wait_for_a_confirmed_idle_backend_and_no_running_operation() {
    assert_eq!(upgrade_blocker(true, "idle", false, false), None);
    assert!(
        upgrade_blocker(false, "idle", false, false)
            .unwrap()
            .contains("后台状态未确认")
    );
    assert!(
        upgrade_blocker(true, "managed", true, false)
            .unwrap()
            .contains("停止接管")
    );
    assert!(
        upgrade_blocker(true, "idle", true, false)
            .unwrap()
            .contains("停止接管")
    );
    assert!(
        upgrade_blocker(true, "recovery_required", false, false)
            .unwrap()
            .contains("恢复")
    );
    assert!(
        upgrade_blocker(true, "idle", false, true)
            .unwrap()
            .contains("操作正在进行")
    );
}

#[test]
fn only_policies_that_run_local_unsigned_scripts_allow_one_click() {
    for allowed in ["RemoteSigned", "Unrestricted", "Bypass", "remotesigned\r\n"] {
        assert!(policy_allows(allowed), "{allowed:?}");
    }
    for refused in ["Restricted", "AllSigned", "Undefined", "Default", ""] {
        assert!(!policy_allows(refused), "{refused:?}");
    }
}

#[test]
fn the_result_file_round_trips_only_with_its_schema() {
    let text = "\u{feff}{\"schema_version\":1,\"ok\":false,\"stage\":\"refused\",\"version\":\"0.1.12\",\"from\":\"0.1.11\",\"install_dir\":\"C:\\\\Users\\\\Tester\\\\AppData\\\\Local\\\\Programs\\\\WslProxy\",\"package\":\"C:\\\\Users\\\\Tester\\\\AppData\\\\Local\\\\WSLProxyLab\\\\updates\\\\0.1.12\\\\package\",\"output\":\"line 1\\n\\nline 2\",\"finished_at\":\"2026-11-25T18:00:00Z\"}";
    assert_eq!(Outcome::parse(text), Some(outcome(false, "refused")));
    assert_eq!(Outcome::parse("{\"schema_version\":2,\"ok\":true}"), None);
    assert_eq!(Outcome::parse("not json"), None);
}

#[test]
fn a_refused_upgrade_explains_and_offers_the_manual_command_only_when_the_package_is_there() {
    let (title, lines) = outcome_text(&outcome(false, "refused"), "0.1.11");
    assert_eq!(title, "升级没有完成");
    assert!(lines[0].0.starts_with("安装器拒绝了这次升级"));
    assert!(lines[0].0.contains("v0.1.11"));
    // The package directory does not exist here, so no command to rerun it.
    assert!(!lines.iter().any(|(text, _)| text.contains("install.ps1")));
    assert_eq!(lines.last().unwrap(), &("line 1\nline 2".to_owned(), true));
    let (_, lines) = outcome_text(&outcome(false, "failed"), "0.1.11");
    assert!(lines[0].0.starts_with("升级在运行安装器之前就停下了"));
}

#[test]
fn an_interrupted_upgrade_gives_the_recover_command() {
    let (title, lines) = outcome_text(&outcome(false, "interrupted"), "0.1.11");
    assert!(title.contains("中断"));
    assert_eq!(
        lines[1],
        (
            r"& 'C:\Users\Tester\AppData\Local\WSLProxyLab\updates\0.1.12\package\install.ps1' -InstallDir 'C:\Users\Tester\AppData\Local\Programs\WslProxy' -Recover".to_owned(),
            true
        )
    );
}

#[test]
fn a_reported_install_of_another_version_is_not_shown_as_success() {
    let (title, lines) = outcome_text(&outcome(true, "installed"), "0.1.11");
    assert_eq!(title, "升级结果和当前版本不一致");
    assert!(lines[0].0.contains("v0.1.12") && lines[0].0.contains("v0.1.11"));
}

#[test]
fn only_the_last_lines_of_the_installer_output_are_shown() {
    let mut long = outcome(false, "refused");
    long.output = (1..=30)
        .map(|n| format!("line {n}"))
        .collect::<Vec<_>>()
        .join("\n");
    let (_, lines) = outcome_text(&long, "0.1.11");
    let shown = &lines.last().unwrap().0;
    assert_eq!(shown.lines().count(), OUTPUT_LINES);
    assert!(shown.starts_with("line 19\n") && shown.ends_with("line 30"));
}

#[test]
fn paths_compare_without_case_or_trailing_separators() {
    assert!(same_path(
        Path::new(r"C:\Apps\WslProxy\"),
        Path::new(r"c:\apps\wslproxy")
    ));
    assert!(!same_path(
        Path::new(r"C:\Apps\WslProxy2"),
        Path::new(r"C:\Apps\WslProxy")
    ));
    assert!(overlaps(
        Path::new(r"C:\Apps\WslProxy\updates"),
        Path::new(r"C:\apps\wslproxy")
    ));
    assert!(overlaps(
        Path::new(r"C:\Apps"),
        Path::new(r"C:\Apps\WslProxy")
    ));
    assert!(!overlaps(
        Path::new(r"C:\Apps\WslProxy2"),
        Path::new(r"C:\Apps\WslProxy")
    ));
}

#[test]
fn sizes_are_shown_in_megabytes() {
    assert_eq!(megabytes(43_189_826), "41.2 MB");
    assert_eq!(megabytes(0), "0.0 MB");
}

#[test]
fn update_errors_read_as_chinese_with_the_detail_kept() {
    assert!(describe(&UpdateError::RateLimited).contains("60 次"));
    assert!(describe(&UpdateError::Checksum).contains("SHA-256"));
    assert!(
        describe(&UpdateError::Network("direct: timed out".into())).contains("direct: timed out")
    );
}

#[test]
fn encoded_commands_are_base64_of_utf16_little_endian() {
    assert_eq!(encode_command(""), "");
    assert_eq!(encode_command("a"), "YQA=");
    assert_eq!(encode_command("ab"), "YQBiAA==");
    assert_eq!(encode_command("abc"), "YQBiAGMA");
    assert_eq!(encode_command("升"), "R1M=");
}

fn handoff_script(install_dir: &Path) -> String {
    let staging = Path::new(r"C:\Users\Lab'User\AppData\Local\WSLProxyLab\updates\0.1.12");
    helper_script(&Handoff {
        zip: &staging.join("wsl-proxy-0.1.12-windows-x64.zip"),
        sha256: "2cd2342bd9524e2649b8fc48abaea4e1e3e389dacdf40f12fb5d66a5fe184eed",
        package: &staging.join("package"),
        staging,
        install_dir,
        result: Path::new(r"C:\Users\Lab'User\AppData\Local\WSLProxyLab\updates\result.json"),
        powershell: Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        desktop_pid: 4242,
        version: Version::parse("0.1.12").unwrap(),
        from: Version::parse("0.1.11").unwrap(),
    })
}

#[test]
fn the_helper_quotes_paths_and_names_every_input() {
    let script = handoff_script(Path::new(
        r"C:\Users\Lab'User\AppData\Local\Programs\WslProxy",
    ));
    assert!(script.contains(r"$target = 'C:\Users\Lab''User\AppData\Local\Programs\WslProxy'"));
    assert!(script.contains(r"$zip = 'C:\Users\Lab''User\AppData\Local\WSLProxyLab\updates\0.1.12\wsl-proxy-0.1.12-windows-x64.zip'"));
    assert!(
        script
            .contains("$sha = '2cd2342bd9524e2649b8fc48abaea4e1e3e389dacdf40f12fb5d66a5fe184eed'")
    );
    assert!(script.contains("$desktopPid = 4242"));
    assert!(script.contains("$version = '0.1.12'"));
    assert!(script.contains("$from = '0.1.11'"));
    // The installer is never run with its execution policy bypassed.
    assert!(!script.to_ascii_lowercase().contains("executionpolicy"));
    assert!(script.contains("-File (Join-Path $package 'install.ps1') -InstallDir $target"));
}

/// Windows PowerShell itself parses the helper the way it would receive it.
#[test]
fn windows_powershell_parses_the_helper_without_errors() {
    let script = handoff_script(Path::new(
        r"C:\Users\Lab'User\AppData\Local\Programs\WslProxy",
    ));
    // Prints the decoded length (UTF-16 units), then the number of parse errors
    // and their messages.
    let check = format!(
        "$s = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}')); $e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($s, [ref]$t, [ref]$e); $s.Length; $e.Count; $e | ForEach-Object {{ $_.Message }}",
        encode_command(&script)
    );
    let output = Command::new(powershell().unwrap())
        .args(["-NoProfile", "-NonInteractive", "-Command", &check])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{text}");
    let length = script.encode_utf16().count().to_string();
    assert_eq!(
        text.split_whitespace().collect::<Vec<_>>(),
        [length.as_str(), "0"],
        "{text}"
    );
}

#[test]
fn the_helper_fits_on_a_command_line() {
    let script = handoff_script(Path::new(
        r"C:\Users\Lab'User\AppData\Local\Programs\WslProxy",
    ));
    // CreateProcess allows 32,767 characters for the whole command line.
    assert!(encode_command(&script).len() < 24_000);
}

/// 用本机的 QA 安装目录走一遍真实的交接：等桌面进程退出、核对、解压、运行安装器、
/// 写结果、重新打开桌面。结果写在真正的 `updates\result.json`，重新打开的桌面会显示它。
/// 手动运行（安装目录要先用旧版本的 install.ps1 装好）：
/// `set WSL_PROXY_QA_ZIP=<新版本 ZIP> && set WSL_PROXY_QA_INSTALL_DIR=<安装目录> &&
/// cargo test -p wsl-proxy-desktop qa_hand_off -- --ignored --nocapture`
#[test]
#[ignore = "installs into a QA directory and reopens its desktop"]
fn qa_hand_off() {
    let zip = PathBuf::from(std::env::var("WSL_PROXY_QA_ZIP").unwrap());
    let install_dir = PathBuf::from(std::env::var("WSL_PROXY_QA_INSTALL_DIR").unwrap());
    let name = zip.file_name().unwrap().to_string_lossy().into_owned();
    let version = name
        .strip_prefix("wsl-proxy-")
        .and_then(|rest| rest.strip_suffix("-windows-x64.zip"))
        .and_then(Version::parse)
        .unwrap();
    let installed: Value =
        serde_json::from_str(&fs::read_to_string(install_dir.join("release.json")).unwrap())
            .unwrap();
    let from = Version::parse(installed["version"].as_str().unwrap()).unwrap();
    let updates = updates_dir().unwrap();
    let staging = updates.join(version.to_string());
    fs::create_dir_all(&staging).unwrap();
    let staged = staging.join(&name);
    fs::copy(&zip, &staged).unwrap();
    let sha256 = update::file_sha256(&staged).unwrap();
    // A process that has already exited stands in for the closing desktop.
    let mut gone = Command::new("cmd").args(["/c", "exit"]).spawn().unwrap();
    let desktop_pid = gone.id();
    gone.wait().unwrap();
    let result = updates.join(RESULT_NAME);
    let _ = fs::remove_file(&result);
    let powershell = powershell().unwrap();
    let script = helper_script(&Handoff {
        zip: &staged,
        sha256: &sha256,
        package: &staging.join("package"),
        staging: &staging,
        install_dir: &install_dir,
        result: &result,
        powershell: &powershell,
        desktop_pid,
        version,
        from,
    });
    spawn_helper(&powershell, &script, &updates).unwrap();
    let started = Instant::now();
    let text = loop {
        // The reopened desktop deletes the file once it has read it, so read it
        // as soon as it appears.
        if let Ok(text) = fs::read_to_string(&result)
            && !text.is_empty()
        {
            break text;
        }
        assert!(
            started.elapsed() < Duration::from_secs(300),
            "no result after 5 minutes"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    println!("{text}");
    let outcome = Outcome::parse(&text).unwrap();
    assert!(outcome.ok, "{outcome:?}");
    assert_eq!(outcome.stage, "installed");
    assert_eq!(outcome.version, version.to_string());
}
