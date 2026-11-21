// Windows named-pipe transport.
use super::framing;
mod inner {
    use super::framing;
    use serde_json::Value;
    use std::ffi::{OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_SEM_TIMEOUT, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_ID_INFO,
        FILE_SHARE_READ, FileIdInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateEventW, CreateProcessW, GetCurrentProcess, GetExitCodeProcess,
        GetProcessId, INFINITE, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, ResetEvent,
        STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    const START_TIMEOUT: Duration = Duration::from_secs(15);
    const START_COMPETITOR_GRACE: Duration = Duration::from_secs(2);
    const DAEMON_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
    const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
    const RESPONSE_TIMEOUT: Duration = Duration::from_secs(240);

    struct Handle(HANDLE);

    impl Handle {
        fn checked(raw: HANDLE) -> io::Result<Self> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(raw))
            }
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            // All overlapped operations are completed/cancelled before this point.
            unsafe { CloseHandle(self.0) };
        }
    }

    fn terminate_spawned(process: HANDLE) -> io::Result<()> {
        let terminate_error = if unsafe { TerminateProcess(process, 1) } == 0 {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        let wait = unsafe {
            WaitForSingleObject(
                process,
                DAEMON_CLEANUP_TIMEOUT.as_millis().min(u32::MAX as u128) as u32,
            )
        };
        if wait == WAIT_OBJECT_0 {
            return Ok(());
        }
        if wait == WAIT_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ipc_spawn_cleanup_timeout",
            ));
        }
        Err(terminate_error.unwrap_or_else(io::Error::last_os_error))
    }

    fn process_id(process: HANDLE) -> io::Result<u32> {
        let pid = unsafe { GetProcessId(process) };
        if pid == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(pid)
        }
    }

    fn exited_code(process: HANDLE) -> io::Result<Option<u32>> {
        let wait = unsafe { WaitForSingleObject(process, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(code))
    }

    enum SpawnError {
        Io(io::Error),
        Cleanup {
            original: io::Error,
            cleanup: io::Error,
        },
    }

    impl From<io::Error> for SpawnError {
        fn from(error: io::Error) -> Self {
            Self::Io(error)
        }
    }

    impl SpawnError {
        fn report(self, context: &str) -> String {
            match self {
                Self::Io(error) => report(context, error),
                Self::Cleanup { original, cleanup } => format!(
                    "{}; {}",
                    report(context, original),
                    report("ipc_spawn_cleanup", cleanup)
                ),
            }
        }
    }
    fn cleanup_spawn_error(process: HANDLE, original: io::Error) -> SpawnError {
        match terminate_spawned(process) {
            Ok(()) => SpawnError::Io(original),
            Err(cleanup) => SpawnError::Cleanup { original, cleanup },
        }
    }

    struct LocalAllocation(*mut std::ffi::c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }

    fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
        let mut value: Vec<u16> = value.encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ipc_invalid_path",
            ));
        }
        value.push(0);
        Ok(value)
    }

    fn report(context: &str, error: io::Error) -> String {
        match error.raw_os_error() {
            Some(code) => format!("{context}: Windows error {code}"),
            None => format!("{context}: {:?}", error.kind()),
        }
    }

    fn token_sid(process: HANDLE) -> io::Result<String> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = Handle::checked(token)?;
        let mut needed = 0;
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
        if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc_invalid_token",
            ));
        }
        // TOKEN_USER contains a pointer; a byte vector need not have its alignment.
        let words = (needed as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0usize; words];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        let mut text = null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _allocation = LocalAllocation(text.cast());
        // A Windows SID has at most 15 subauthorities, well below this bound.
        let mut length = 0;
        while length < 256 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc_invalid_sid",
            ));
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ipc_invalid_sid"))
    }

    fn current_sid() -> io::Result<String> {
        token_sid(unsafe { GetCurrentProcess() })
    }

    fn pipe_name(sid: &str) -> io::Result<Vec<u16>> {
        wide(OsStr::new(&format!(r"\\.\pipe\wsl-proxyctl-m4-{sid}")))
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FileIdentity(u64, [u8; 16]);

    fn file_identity(file: &File) -> io::Result<FileIdentity> {
        let mut info = FILE_ID_INFO::default();
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(FileIdentity(
            info.VolumeSerialNumber,
            info.FileId.Identifier,
        ))
    }

    struct Executable {
        path: PathBuf,
        // Deny replacement/writes while launching or authenticating the daemon.
        _file: File,
        identity: FileIdentity,
    }

    impl Executable {
        fn open(path: &Path) -> io::Result<Self> {
            let path = path.canonicalize()?;
            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ipc_invalid_executable",
                ));
            }
            let identity = file_identity(&file)?;
            Ok(Self {
                path,
                _file: file,
                identity,
            })
        }

        fn sibling() -> io::Result<Self> {
            let current = std::env::current_exe()?;
            let directory = current.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ipc_missing_executable_directory",
                )
            })?;
            Self::open(&directory.join("wsl-proxyctl.exe"))
        }

        fn verify_process(&self, process: HANDLE, sid: &str) -> io::Result<()> {
            verify_owner(process, sid)?;
            let mut path = vec![0; 32768];
            let mut length = path.len() as u32;
            if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            path.truncate(length as usize);
            let image = Self::open(Path::new(&OsString::from_wide(&path)))?;
            // Compare native file identity, not case folding, path spelling, or PID.
            if image.identity != self.identity {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ipc_untrusted_server_image",
                ));
            }
            Ok(())
        }

        fn spawn(&self, sid: &str) -> Result<Handle, SpawnError> {
            let application = wide(self.path.as_os_str())?;
            if application.contains(&(b'"' as u16)) {
                return Err(SpawnError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ipc_invalid_executable",
                )));
            }
            let mut command = vec![b'"' as u16];
            command.extend_from_slice(&application[..application.len() - 1]);
            command.extend("\" daemon".encode_utf16());
            command.push(0);
            let directory = wide(
                self.path
                    .parent()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "ipc_invalid_executable")
                    })?
                    .as_os_str(),
            )?;
            let startup = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: null_mut(),
                hStdOutput: null_mut(),
                hStdError: null_mut(),
                ..Default::default()
            };
            let mut info = PROCESS_INFORMATION::default();
            if unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    null(),
                    null(),
                    0,
                    CREATE_NO_WINDOW,
                    null(),
                    directory.as_ptr(),
                    &startup,
                    &mut info,
                )
            } == 0
            {
                return Err(SpawnError::Io(io::Error::last_os_error()));
            }
            let process = match Handle::checked(info.hProcess) {
                Ok(process) => process,
                Err(error) => {
                    if !info.hThread.is_null() && info.hThread != INVALID_HANDLE_VALUE {
                        unsafe { CloseHandle(info.hThread) };
                    }
                    return Err(SpawnError::Io(error));
                }
            };
            let _thread = match Handle::checked(info.hThread) {
                Ok(thread) => thread,
                Err(error) => {
                    return Err(cleanup_spawn_error(process.0, error));
                }
            };
            if let Err(error) = self.verify_process(process.0, sid) {
                return Err(cleanup_spawn_error(process.0, error));
            }
            Ok(process)
        }
    }

    fn cleanup_started_daemon(context: &str, error: io::Error, child: Handle) -> String {
        let failure = report(context, error);
        match terminate_spawned(child.0) {
            Ok(()) => failure,
            Err(cleanup) => format!("{failure}; {}", report("ipc_spawn_cleanup", cleanup)),
        }
    }

    fn cleanup_untrusted_server(
        context: &str,
        error: io::Error,
        pipe: &Pipe,
        child: Handle,
    ) -> String {
        let child_pid = process_id(child.0).ok();
        let server_pid = pipe_process_id(pipe.handle.0, true).ok();
        // Authentication can fail after the daemon has already accepted real
        // requests. Never terminate the child when it is the named-pipe server,
        // or when the peer PID cannot be established safely.
        if server_pid.is_none() || server_pid == child_pid {
            return report(context, error);
        }
        cleanup_started_daemon(context, error, child)
    }

    fn verify_owner(process: HANDLE, sid: &str) -> io::Result<()> {
        if token_sid(process)? != sid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ipc_untrusted_peer_sid",
            ));
        }
        Ok(())
    }

    fn pipe_process_id(pipe: HANDLE, server: bool) -> io::Result<u32> {
        let mut pid = 0;
        let success = unsafe {
            if server {
                GetNamedPipeServerProcessId(pipe, &mut pid)
            } else {
                GetNamedPipeClientProcessId(pipe, &mut pid)
            }
        };
        if success == 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc_invalid_peer_pid",
            ));
        }
        Ok(pid)
    }

    fn peer_process(pipe: HANDLE, server: bool) -> io::Result<Handle> {
        let pid = pipe_process_id(pipe, server)?;
        Handle::checked(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
    }

    fn milliseconds(deadline: Instant) -> io::Result<u32> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "ipc_timeout"));
        }
        Ok(remaining
            .as_millis()
            .saturating_add(1)
            .min((INFINITE - 1) as u128) as u32)
    }

    struct Pipe {
        handle: Handle,
        event: Handle,
        deadline: Instant,
    }

    impl Pipe {
        fn from_handle(handle: Handle) -> io::Result<Self> {
            let event = Handle::checked(unsafe { CreateEventW(null(), 1, 0, null()) })?;
            Ok(Self {
                handle,
                event,
                deadline: Instant::now() + FRAME_TIMEOUT,
            })
        }

        fn server(name: &[u16], sid: &str) -> io::Result<Self> {
            let sddl = wide(OsStr::new(&format!("D:P(A;;GA;;;{sid})")))?;
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let _descriptor = LocalAllocation(descriptor);
            let security = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            // Keep this single first-instance handle for the entire server life;
            // DisconnectNamedPipe reuses it without a namespace takeover gap.
            let handle = Handle::checked(unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    64 * 1024,
                    64 * 1024,
                    1000,
                    &security,
                )
            })?;
            Self::from_handle(handle)
        }

        fn reset(&mut self, duration: Duration) {
            self.deadline = Instant::now() + duration;
        }

        fn overlapped(&self) -> io::Result<OVERLAPPED> {
            if unsafe { ResetEvent(self.event.0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(OVERLAPPED {
                hEvent: self.event.0,
                ..Default::default()
            })
        }

        fn complete(&self, operation: &mut OVERLAPPED, timeout: u32) -> io::Result<usize> {
            let wait = unsafe { WaitForSingleObject(self.event.0, timeout) };
            if wait != WAIT_OBJECT_0 {
                let error = if wait == WAIT_TIMEOUT {
                    io::Error::new(io::ErrorKind::TimedOut, "ipc_timeout")
                } else {
                    io::Error::last_os_error()
                };
                // Cancellation must finish before stack OVERLAPPED/buffers die.
                // Named-pipe overlapped reads/writes support CancelIoEx.
                unsafe {
                    CancelIoEx(self.handle.0, operation);
                    let mut ignored = 0;
                    GetOverlappedResult(self.handle.0, operation, &mut ignored, 1);
                }
                return Err(error);
            }
            let mut transferred = 0;
            if unsafe { GetOverlappedResult(self.handle.0, operation, &mut transferred, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(transferred as usize)
        }

        fn connect(&self) -> io::Result<()> {
            let mut operation = self.overlapped()?;
            if unsafe { ConnectNamedPipe(self.handle.0, &mut operation) } != 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|code| code as u32) {
                Some(ERROR_PIPE_CONNECTED) => Ok(()),
                Some(ERROR_IO_PENDING) => self.complete(&mut operation, INFINITE).map(|_| ()),
                _ => Err(error),
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            let timeout = milliseconds(self.deadline)?;
            let mut operation = self.overlapped()?;
            let mut transferred = 0;
            if unsafe {
                ReadFile(
                    self.handle.0,
                    bytes.as_mut_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut transferred,
                    &mut operation,
                )
            } != 0
            {
                return Ok(transferred as usize);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
                self.complete(&mut operation, timeout)
            } else {
                Err(error)
            }
        }
    }

    impl Write for Pipe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            let timeout = milliseconds(self.deadline)?;
            let mut operation = self.overlapped()?;
            let mut transferred = 0;
            if unsafe {
                WriteFile(
                    self.handle.0,
                    bytes.as_ptr(),
                    bytes.len().min(u32::MAX as usize) as u32,
                    &mut transferred,
                    &mut operation,
                )
            } != 0
            {
                return Ok(transferred as usize);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
                self.complete(&mut operation, timeout)
            } else {
                Err(error)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn open_pipe(name: &[u16], deadline: Instant) -> io::Result<Pipe> {
        loop {
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                return Pipe::from_handle(Handle::checked(handle)?);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
                return Err(error);
            }
            let timeout = milliseconds(deadline)?;
            if unsafe { WaitNamedPipeW(name.as_ptr(), timeout) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }

    fn authenticate(pipe: &Pipe, executable: &Executable, sid: &str) -> io::Result<()> {
        let process = peer_process(pipe.handle.0, true)?;
        executable.verify_process(process.0, sid)
    }

    fn request_at(
        name: &[u16],
        executable: &Executable,
        sid: &str,
        req: &Value,
    ) -> Result<Value, String> {
        let encoded = framing::encode(req).map_err(|error| report("ipc_invalid_request", error))?;
        let mut pipe = open_pipe(name, Instant::now() + CONNECT_TIMEOUT)
            .map_err(|error| report("ipc_unavailable", error))?;
        authenticate(&pipe, executable, sid)
            .map_err(|error| report("ipc_untrusted_server", error))?;
        pipe.reset(FRAME_TIMEOUT);
        framing::write_frame(&mut pipe, &encoded)
            .map_err(|error| report("ipc_request_uncertain; query state before retrying", error))?;
        pipe.reset(RESPONSE_TIMEOUT);
        let response = framing::read_frame(&mut pipe).map_err(|error| {
            report("ipc_response_uncertain; query state before retrying", error)
        })?;
        pipe.reset(FRAME_TIMEOUT);
        // A lost ACK must not turn a received mutation result into a retryable
        // request failure. The server simply stays alive if it misses the ACK.
        let _ = pipe.write_all(&[framing::ACK]);
        Ok(response)
    }

    pub(crate) fn request(req: &Value) -> Result<Value, String> {
        let sid = current_sid().map_err(|error| report("ipc_identity_unavailable", error))?;
        let executable =
            Executable::sibling().map_err(|error| report("ipc_sibling_unavailable", error))?;
        let name = pipe_name(&sid).map_err(|error| report("ipc_invalid_name", error))?;
        request_at(&name, &executable, &sid, req)
    }

    pub(crate) fn ensure_daemon() -> Result<(), String> {
        let sid = current_sid().map_err(|error| report("ipc_identity_unavailable", error))?;
        let executable =
            Executable::sibling().map_err(|error| report("ipc_sibling_unavailable", error))?;
        let name = pipe_name(&sid).map_err(|error| report("ipc_invalid_name", error))?;
        match open_pipe(&name, Instant::now() + CONNECT_TIMEOUT) {
            Ok(pipe) => {
                return authenticate(&pipe, &executable, &sid)
                    .map_err(|error| report("ipc_untrusted_server", error));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {}
            Err(error) => return Err(report("ipc_unavailable", error)),
        }
        // CreateProcessW uses an explicit, locked sibling image, no shell,
        // no inherited handles, and null standard handles under CREATE_NO_WINDOW.
        let child = executable
            .spawn(&sid)
            .map_err(|error| error.report("ipc_daemon_start_failed"))?;
        let deadline = Instant::now() + START_TIMEOUT;
        let mut child_exit: Option<(Instant, u32)> = None;
        loop {
            match open_pipe(&name, deadline) {
                Ok(pipe) => match authenticate(&pipe, &executable, &sid) {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        return Err(cleanup_untrusted_server(
                            "ipc_untrusted_server",
                            error,
                            &pipe,
                            child,
                        ));
                    }
                },
                Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    if child_exit.is_none() {
                        match exited_code(child.0) {
                            Ok(Some(code)) => child_exit = Some((Instant::now(), code)),
                            Ok(None) => {}
                            Err(exit_error) => {
                                return Err(report("ipc_daemon_exit_probe_failed", exit_error));
                            }
                        }
                    }
                    if let Some((exited, code)) = child_exit {
                        if exited.elapsed() >= START_COMPETITOR_GRACE {
                            return Err(format!("ipc_daemon_exited_before_pipe: exit_code={code}"));
                        }
                    }
                    if Instant::now() < deadline {
                        // A concurrent launcher may win first-instance ownership. Keep waiting
                        // briefly for its pipe even if this child has already exited.
                        unsafe { WaitForSingleObject(child.0, 50) };
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    // Close the probe/terminate race: a child can create its pipe just after
                    // the timed-out probe. Prefer a late authenticated pipe over killing it.
                    match open_pipe(&name, Instant::now() + Duration::from_millis(100)) {
                        Ok(pipe) => match authenticate(&pipe, &executable, &sid) {
                            Ok(()) => return Ok(()),
                            Err(error) => {
                                return Err(cleanup_untrusted_server(
                                    "ipc_untrusted_server",
                                    error,
                                    &pipe,
                                    child,
                                ));
                            }
                        },
                        Err(final_error)
                            if final_error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) =>
                        {
                            if let Some(code) = exited_code(child.0).ok().flatten() {
                                return Err(format!(
                                    "ipc_daemon_exited_before_pipe: exit_code={code}"
                                ));
                            }
                            return Err(cleanup_started_daemon(
                                "ipc_daemon_start_timeout",
                                error,
                                child,
                            ));
                        }
                        Err(final_error)
                            if final_error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32)
                                || final_error.kind() == io::ErrorKind::TimedOut =>
                        {
                            return Err(report("ipc_daemon_start_timeout", final_error));
                        }
                        Err(final_error) => {
                            if exited_code(child.0).ok().flatten().is_some() {
                                return Err(report("ipc_daemon_connect_failed", final_error));
                            }
                            return Err(cleanup_started_daemon(
                                "ipc_daemon_connect_failed",
                                final_error,
                                child,
                            ));
                        }
                    }
                }
                Err(error)
                    if error.raw_os_error() == Some(ERROR_SEM_TIMEOUT as i32)
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    // The named pipe exists but is busy. Do not kill the child: it may be
                    // the healthy daemon serving another request or a concurrent winner.
                    return Err(report("ipc_daemon_start_timeout", error));
                }
                Err(error) => {
                    if exited_code(child.0).ok().flatten().is_some() {
                        return Err(report("ipc_daemon_connect_failed", error));
                    }
                    return Err(cleanup_started_daemon(
                        "ipc_daemon_connect_failed",
                        error,
                        child,
                    ));
                }
            }
        }
    }

    fn serve_pipe(
        mut pipe: Pipe,
        sid: &str,
        mut handler: impl FnMut(Value) -> (Value, bool),
    ) -> Result<(), String> {
        loop {
            match pipe.connect() {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                    unsafe { DisconnectNamedPipe(pipe.handle.0) };
                    continue;
                }
                Err(error) => return Err(report("ipc_accept_failed", error)),
            }
            let terminate = (|| -> io::Result<bool> {
                let peer = peer_process(pipe.handle.0, false)?;
                verify_owner(peer.0, sid)?;
                pipe.reset(FRAME_TIMEOUT);
                let req = framing::read_frame(&mut pipe)?;
                let (response, terminate) = handler(req);
                pipe.reset(FRAME_TIMEOUT);
                framing::respond(&mut pipe, &response)?;
                Ok(terminate)
            })()
            .unwrap_or(false);
            // Malformed frames, timeouts and broken pipes are connection-local.
            // The handler is never replayed, nor is its payload logged.
            unsafe { DisconnectNamedPipe(pipe.handle.0) };
            if terminate {
                return Ok(());
            }
        }
    }

    pub(crate) fn serve(handler: impl FnMut(Value) -> (Value, bool)) -> Result<(), String> {
        let sid = current_sid().map_err(|error| report("ipc_identity_unavailable", error))?;
        let name = pipe_name(&sid).map_err(|error| report("ipc_invalid_name", error))?;
        let pipe = Pipe::server(&name, &sid)
            .map_err(|error| report("ipc_pipe_ownership_failed", error))?;
        serve_pipe(pipe, &sid, handler)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, atomic::AtomicUsize};

        fn fixture() -> (Vec<u16>, String, Executable, Pipe) {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sid = current_sid().unwrap();
            let name = wide(OsStr::new(&format!(
                r"\\.\pipe\wsl-proxyctl-ipc-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )))
            .unwrap();
            let executable = Executable::open(&std::env::current_exe().unwrap()).unwrap();
            let pipe = Pipe::server(&name, &sid).unwrap();
            (name, sid, executable, pipe)
        }

        // Create the server on its owning thread: raw Win32 handles deliberately
        // are not declared Send/Sync just to satisfy a test fixture.
        fn start_server(
            name: Vec<u16>,
            sid: String,
            ready: std::sync::mpsc::Sender<()>,
            calls: Arc<AtomicUsize>,
        ) -> std::thread::JoinHandle<()> {
            std::thread::spawn(move || {
                let pipe = Pipe::server(&name, &sid).unwrap();
                ready.send(()).unwrap();
                serve_pipe(pipe, &sid, |req| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    (req.clone(), req["quit"] == true)
                })
                .unwrap();
            })
        }

        #[test]
        fn first_instance_ownership_is_exclusive() {
            let (name, sid, _, _pipe) = fixture();
            assert!(Pipe::server(&name, &sid).is_err());
        }

        #[test]
        fn disconnects_do_not_replay_mutations_or_accept_shutdown_without_ack() {
            let (name, sid, executable, pipe) = fixture();
            drop(pipe);
            let calls = Arc::new(AtomicUsize::new(0));
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let server = start_server(name.clone(), sid.clone(), ready_tx, calls.clone());
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            // Before a frame: no mutation.
            drop(open_pipe(&name, Instant::now() + CONNECT_TIMEOUT).unwrap());
            // After a complete shutdown frame, but without receiving/ACKing it:
            // the mutation may run once, but must not stop the server.
            let mut client = open_pipe(&name, Instant::now() + CONNECT_TIMEOUT).unwrap();
            framing::write_frame(
                &mut client,
                &framing::encode(&serde_json::json!({"quit": true})).unwrap(),
            )
            .unwrap();
            let _response = framing::read_frame(&mut client).unwrap();
            drop(client);
            let response =
                request_at(&name, &executable, &sid, &serde_json::json!({"quit": true})).unwrap();
            assert_eq!(response["quit"], true);
            server.join().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }

        #[test]
        fn stalled_header_is_bounded_and_next_client_succeeds() {
            let (name, sid, executable, pipe) = fixture();
            drop(pipe);
            let calls = Arc::new(AtomicUsize::new(0));
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let server = start_server(name.clone(), sid.clone(), ready_tx, calls.clone());
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut stalled = open_pipe(&name, Instant::now() + CONNECT_TIMEOUT).unwrap();
            stalled.write_all(&[1]).unwrap();
            let begin = Instant::now();
            let response =
                request_at(&name, &executable, &sid, &serde_json::json!({"quit": true})).unwrap();
            assert_eq!(response["quit"], true);
            assert!(begin.elapsed() < CONNECT_TIMEOUT + FRAME_TIMEOUT);
            server.join().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn disconnect_before_response_write_does_not_stop_or_replay() {
            let (name, sid, executable, pipe) = fixture();
            drop(pipe);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let (invoked_tx, invoked_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let thread_name = name.clone();
            let thread_sid = sid.clone();
            let server = std::thread::spawn(move || {
                let pipe = Pipe::server(&thread_name, &thread_sid).unwrap();
                ready_tx.send(()).unwrap();
                let mut calls = 0;
                serve_pipe(pipe, &thread_sid, |req| {
                    calls += 1;
                    if req["drop"] == true {
                        invoked_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    (req, true)
                })
                .unwrap();
                calls
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut client = open_pipe(&name, Instant::now() + CONNECT_TIMEOUT).unwrap();
            framing::write_frame(
                &mut client,
                &framing::encode(&serde_json::json!({"drop": true})).unwrap(),
            )
            .unwrap();
            invoked_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(client);
            release_tx.send(()).unwrap();
            assert_eq!(
                request_at(&name, &executable, &sid, &serde_json::json!({"quit": true})).unwrap()["quit"],
                true
            );
            assert_eq!(server.join().unwrap(), 2);
        }

        #[test]
        fn server_image_mismatch_is_rejected_before_request_bytes() {
            let (name, sid, _, pipe) = fixture();
            drop(pipe);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let thread_name = name.clone();
            let thread_sid = sid.clone();
            let server = std::thread::spawn(move || {
                let mut pipe = Pipe::server(&thread_name, &thread_sid).unwrap();
                ready_tx.send(()).unwrap();
                pipe.connect().unwrap();
                pipe.reset(FRAME_TIMEOUT);
                assert!(framing::read_frame(&mut pipe).is_err());
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let system = std::env::var_os("SystemRoot").unwrap();
            let wrong =
                Executable::open(&PathBuf::from(system).join("System32\\notepad.exe")).unwrap();
            let error = request_at(
                &name,
                &wrong,
                &sid,
                &serde_json::json!({"env_path": "private"}),
            )
            .unwrap_err();
            assert!(error.starts_with("ipc_untrusted_server:"));
            server.join().unwrap();
        }
    }
}

pub(super) use inner::{ensure_daemon, request, serve};
