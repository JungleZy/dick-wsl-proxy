#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
mod app;

#[cfg(target_os = "windows")]
fn main() {
    app::run();
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("WSL 代理控制台是 Windows 原生应用；请在 Windows 构建并运行 wsl-proxy-desktop.exe。");
    std::process::exit(1);
}
