//! Current-user startup registration for the desktop console.

use std::io;

use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "WSLProxyLab";

pub(crate) fn enabled() -> Result<bool, String> {
    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    let run = current_user
        .open_subkey(RUN_KEY)
        .map_err(|error| format!("autostart_open_failed:{error}"))?;
    match run.get_value::<String, _>(VALUE_NAME) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("autostart_read_failed:{error}")),
    }
}

pub(crate) fn set_enabled(value: bool) -> Result<(), String> {
    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = current_user
        .create_subkey(RUN_KEY)
        .map_err(|error| format!("autostart_open_failed:{error}"))?;
    if value {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let command = format!("\"{}\"", executable.display());
        run.set_value(VALUE_NAME, &command)
            .map_err(|error| format!("autostart_write_failed:{error}"))?;
    } else {
        match run.delete_value(VALUE_NAME) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("autostart_remove_failed:{error}")),
        }
    }
    Ok(())
}
