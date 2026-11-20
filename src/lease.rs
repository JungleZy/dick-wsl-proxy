//! A non-forwarding Windows process keeps exclusive sockets reserved if the controller dies.
//! It receives Winsock duplication tickets on an anonymous pipe, never accepts a connection,
//! and releases them only after an explicit, journal-backed stop has removed the guest rules.
#[cfg(windows)]
mod windows {
    use crate::plan::Plan;
    use socket2::Socket;
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawSocket, FromRawSocket};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::ptr;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Networking::WinSock::*;
    use windows_sys::Win32::System::Threading::*;

    struct Event(HANDLE);
    impl Drop for Event {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn name(plan: &Plan, suffix: &str) -> Vec<u16> {
        format!(
            "Global\\wpl-{}-{:08x}-{suffix}\0",
            plan.target.id, plan.cookie
        )
        .encode_utf16()
        .collect()
    }
    impl Event {
        fn create(n: &[u16]) -> Result<Self, String> {
            let h = unsafe { CreateEventW(ptr::null(), 1, 0, n.as_ptr()) };
            let err = unsafe { GetLastError() };
            if h.is_null() {
                return Err(format!("lease_create_event:{err}"));
            }
            let event = Self(h);
            if err == ERROR_ALREADY_EXISTS {
                return Err("lease_name_collision".into());
            }
            Ok(event)
        }
        fn open(n: &[u16], access: u32) -> Result<Option<Self>, String> {
            let h = unsafe { OpenEventW(access, 0, n.as_ptr()) };
            if !h.is_null() {
                return Ok(Some(Self(h)));
            }
            let err = unsafe { GetLastError() };
            if err == ERROR_FILE_NOT_FOUND {
                Ok(None)
            } else {
                Err(format!("lease_open_event:{err}"))
            }
        }
        fn signal(&self) -> Result<(), String> {
            if unsafe { SetEvent(self.0) } == 0 {
                Err("lease_signal_failed".into())
            } else {
                Ok(())
            }
        }
        fn wait(&self, millis: u32) -> Result<(), String> {
            if unsafe { WaitForSingleObject(self.0, millis) } == WAIT_OBJECT_0 {
                Ok(())
            } else {
                Err("lease_wait_failed_or_timeout".into())
            }
        }
    }
    // WSAPROTOCOL_INFOW is a C wire structure with no pointers. Both processes use the same EXE.
    fn ticket() -> WSAPROTOCOL_INFOW {
        unsafe { std::mem::zeroed() }
    }
    fn bytes(info: &mut WSAPROTOCOL_INFOW) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                (info as *mut WSAPROTOCOL_INFOW).cast(),
                size_of::<WSAPROTOCOL_INFOW>(),
            )
        }
    }
    pub fn reserve(plan: &Plan, tcp: &Socket, udp: &Socket) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut child = Command::new(exe)
            .arg("lease-worker")
            .arg(plan.cookie.to_string())
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let result = (|| {
            let mut input = child.stdin.take().ok_or("lease_stdin_missing")?;
            for sock in [tcp, udp] {
                let mut info = ticket();
                if unsafe { WSADuplicateSocketW(sock.as_raw_socket() as _, child.id(), &mut info) }
                    != 0
                {
                    return Err(format!("lease_duplicate:{}", unsafe { WSAGetLastError() }));
                }
                input
                    .write_all(bytes(&mut info))
                    .map_err(|e| e.to_string())?;
            }
            drop(input);
            let mut ack = child.stdout.take().ok_or("lease_stdout_missing")?;
            let (tx, rx) = mpsc::sync_channel(1);
            std::thread::Builder::new()
                .spawn(move || {
                    let mut b = [0u8];
                    let _ = tx.send(ack.read_exact(&mut b).is_ok() && b == [1]);
                })
                .map_err(|e| e.to_string())?;
            if rx.recv_timeout(Duration::from_secs(10)) != Ok(true) {
                return Err("lease_worker_not_ready".into());
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
    pub fn worker(plan: &Plan) -> Result<(), String> {
        let stop = Event::create(&name(plan, "stop"))?;
        let done = Event::create(&name(plan, "done"))?;
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
            return Err("lease_winsock_start".into());
        }
        let mut sockets = Vec::with_capacity(2);
        for _ in 0..2 {
            let mut info = ticket();
            std::io::stdin()
                .lock()
                .read_exact(bytes(&mut info))
                .map_err(|e| e.to_string())?;
            let h = unsafe {
                WSASocketW(
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    FROM_PROTOCOL_INFO,
                    &info,
                    0,
                    WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
                )
            };
            if h == INVALID_SOCKET {
                return Err(format!("lease_import:{}", unsafe { WSAGetLastError() }));
            }
            let s = unsafe { Socket::from_raw_socket(h as _) };
            if s.local_addr().map_err(|e| e.to_string())?.as_socket_ipv4() != Some(plan.ingress) {
                return Err("lease_wrong_endpoint".into());
            }
            sockets.push(s);
        }
        let mut out = std::io::stdout().lock();
        out.write_all(&[1])
            .and_then(|_| out.flush())
            .map_err(|e| e.to_string())?;
        drop(out);
        stop.wait(INFINITE)?;
        drop(sockets);
        unsafe { WSACleanup() };
        drop(stop); // No new recovery observer can see a stale custodian after `done`.
        done.signal()
    }
    pub fn alive(plan: &Plan) -> Result<bool, String> {
        Ok(Event::open(&name(plan, "stop"), EVENT_MODIFY_STATE)?.is_some())
    }
    pub fn release(plan: &Plan) -> Result<(), String> {
        let Some(stop) = Event::open(&name(plan, "stop"), EVENT_MODIFY_STATE)? else {
            return Ok(());
        };
        let done = Event::open(&name(plan, "done"), SYNCHRONIZATION_SYNCHRONIZE)?
            .ok_or("lease_missing_done_event")?;
        stop.signal()?;
        done.wait(10000)
    }
}
#[cfg(windows)]
pub use windows::{alive, release, reserve, worker};
#[cfg(not(windows))]
mod unsupported {
    use crate::plan::Plan;
    use socket2::Socket;
    pub fn reserve(_: &Plan, _: &Socket, _: &Socket) -> Result<(), String> {
        Err("Windows required".into())
    }
    pub fn worker(_: &Plan) -> Result<(), String> {
        Err("Windows required".into())
    }
    pub fn alive(_: &Plan) -> Result<bool, String> {
        Err("Windows required".into())
    }
    pub fn release(_: &Plan) -> Result<(), String> {
        Err("Windows required".into())
    }
}
#[cfg(not(windows))]
pub use unsupported::{alive, release, reserve, worker};
