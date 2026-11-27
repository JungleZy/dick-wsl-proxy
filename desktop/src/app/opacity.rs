//! 全局不透明度：状态岛和应用窗口的底色共用一个值，设置页里调，存进注册表的偏好键，
//! 下次启动沿用。
//!
//! 只影响底色；文字、图标和按钮始终是实色，调得再低也看得清内容。

use std::sync::atomic::{AtomicU32, Ordering};

use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

use super::theme::PREFERENCES_KEY;

/// 设置页滑块的范围（百分比）。低于一半时底色太淡，文字压在桌面上看不清。
pub(crate) const MIN: u32 = 50;
pub(crate) const MAX: u32 = 100;
const DEFAULT: u32 = 88;
const VALUE_NAME: &str = "DesktopOpacity";

/// 0 表示还没 [`load`] 过。
static PERCENT: AtomicU32 = AtomicU32::new(0);

/// 读出保存的值，没保存过或读不出来用默认值。启动时调用一次。
pub(crate) fn load() -> u32 {
    let percent = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(PREFERENCES_KEY)
        .and_then(|key| key.get_value::<u32, _>(VALUE_NAME))
        .map_or(DEFAULT, |value| value.clamp(MIN, MAX));
    PERCENT.store(percent, Ordering::Relaxed);
    percent
}

/// 当前百分比；还没 [`load`] 过时是默认值。
pub(crate) fn percent() -> u32 {
    match PERCENT.load(Ordering::Relaxed) {
        0 => DEFAULT,
        percent => percent,
    }
}

/// 画底色用的 alpha（0～1）。
pub(crate) fn alpha() -> f32 {
    percent() as f32 / 100.
}

/// 立即生效，不保存：拖动滑块的过程中调用。
pub(crate) fn apply(percent: u32) {
    PERCENT.store(percent.clamp(MIN, MAX), Ordering::Relaxed);
}

/// 保存当前值：松开滑块时调用。保存失败只影响下次启动，返回原因由调用方提示。
pub(crate) fn save() -> Result<(), String> {
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(PREFERENCES_KEY)
        .map_err(|error| format!("opacity_preference_open_failed:{error}"))?;
    key.set_value(VALUE_NAME, &percent())
        .map_err(|error| format!("opacity_preference_write_failed:{error}"))
}
