//! 启动前检查本进程的 Windows 完整性级别。
//!
//! EXE 所在目录带有「低完整性」强制标签时，Windows 以 Low 级别启动它：
//! 后台写不了 LocalAppData 里的锁文件，托盘图标也发不到资源管理器。
//! 这种情况下控制台什么都做不了，所以先说明原因再退出，不占用单实例锁，
//! 也不留下没有托盘、关掉后找不回来的隐藏窗口。

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenIntegrityLevel,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MB_ICONWARNING, MB_OK, MB_SETFOREGROUND, MessageBoxW,
};

/// `SECURITY_MANDATORY_MEDIUM_RID`：普通用户进程的默认级别。
const MEDIUM_RID: u32 = 0x2000;

/// 本进程低于普通用户级别时返回 `true`。读不到级别时返回 `false`，按正常流程继续。
pub(crate) fn below_medium() -> bool {
    current_rid().is_some_and(is_below_medium)
}

/// 弹出说明框，用户确认后返回。
pub(crate) fn warn() {
    let directory = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.display().to_string()))
        .unwrap_or_else(|| "（无法读取）".into());
    alert("WSL Proxy 无法在当前位置运行", &message(&directory));
}

/// 在还没有窗口可用时说明问题：弹出系统提示框，用户确认后返回。
pub(crate) fn alert(caption: &str, text: &str) {
    let text = wide(text);
    let caption = wide(caption);
    unsafe {
        MessageBoxW(
            null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND,
        );
    }
}

fn is_below_medium(rid: u32) -> bool {
    rid < MEDIUM_RID
}

fn message(directory: &str) -> String {
    format!(
        "WSL Proxy 当前以 Windows「低完整性」级别运行，无法启动后台、读取数据，也无法显示托盘图标，点击“确定”后退出。\n\n\
         最常见的原因：程序所在的文件夹带有「低完整性」标签（一些开发工具的沙箱会给工作目录加这个标签），从里面启动的程序都会被 Windows 降低权限。启动时出现「无法验证发布者」的安全警告也是这个原因。\n\n\
         程序所在位置：\n{directory}\n\n\
         解决办法：把 wsl-proxy-desktop.exe 和 wsl-proxyctl.exe 一起复制到其他文件夹后再运行；或者移除该文件夹的低完整性标签。不需要以管理员身份运行。"
    )
}

fn current_rid() -> Option<u32> {
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    let mut raw = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return None;
    }
    let token = Token(raw);
    let mut needed = 0;
    unsafe { GetTokenInformation(token.0, TokenIntegrityLevel, null_mut(), 0, &mut needed) };
    if needed < size_of::<TOKEN_MANDATORY_LABEL>() as u32 || needed > 1024 {
        return None;
    }
    // TOKEN_MANDATORY_LABEL 里有指针，用 usize 数组保证对齐。
    let mut storage = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenIntegrityLevel,
            storage.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return None;
    }
    let label = unsafe { &*storage.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    let sid = label.Label.Sid;
    if sid.is_null() {
        return None;
    }
    let count = unsafe { *GetSidSubAuthorityCount(sid) };
    if count == 0 {
        return None;
    }
    Some(unsafe { *GetSidSubAuthority(sid, u32::from(count) - 1) })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_levels_below_medium_are_rejected() {
        assert!(is_below_medium(0x0000)); // Untrusted
        assert!(is_below_medium(0x1000)); // Low
        assert!(!is_below_medium(0x2000)); // Medium
        assert!(!is_below_medium(0x2100)); // Medium Plus
        assert!(!is_below_medium(0x3000)); // High
    }

    #[test]
    fn message_names_the_folder_and_the_fix() {
        let text = message(r"D:\work\app");
        assert!(text.contains(r"D:\work\app"));
        assert!(text.contains("wsl-proxy-desktop.exe 和 wsl-proxyctl.exe"));
        assert!(text.contains("低完整性"));
    }

    #[test]
    fn this_test_process_reports_a_level() {
        assert!(current_rid().is_some());
    }
}
