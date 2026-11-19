use crate::m1::Plan;
use std::net::SocketAddrV4;

#[cfg(any(windows, test))]
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use std::io::BufRead;

#[cfg(any(windows, test))]
const RESPONSE_LIMIT: usize = 4096;
#[cfg(any(windows, test))]
const REQUEST_LIMIT: usize = 2048;
#[cfg(any(windows, test))]
const GUEST_TIMING_LIMIT_US: u64 = 12_000_000;
pub(crate) const MAX_LOOKUPS: usize = 16;
#[cfg(windows)]
const BOOTSTRAP_LIMIT: usize = 128 * 1024;

// Only this fixed program is an argument to wsl.exe. The embedded kernel source
// and all plan/query values travel as JSON over stdin, never through a shell.
#[cfg(windows)]
const BOOTSTRAP: &str = r#"import json, os, select, signal, sys, time
buffer = bytearray()
def receive(limit):
    deadline = time.monotonic() + 60
    while True:
        end = buffer.find(b'\n')
        if end >= 0:
            if end + 1 > limit:
                raise ValueError('request_limit')
            line = bytes(buffer[:end])
            del buffer[:end + 1]
            return json.loads(line)
        if len(buffer) >= limit:
            raise ValueError('request_limit')
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
            return None
        chunk = os.read(0, min(4096, limit - len(buffer)))
        if not chunk:
            if buffer:
                raise ValueError('incomplete_request')
            return None
        buffer.extend(chunk)
def emit(value):
    print(json.dumps(value, separators=(',', ':'), ensure_ascii=True), flush=True)
def reason(error):
    return ''.join(c if 32 <= ord(c) < 127 else '?' for c in str(error))[:512] or 'query_failed'
try:
    signal.alarm(65)
    initial = receive(131072)
    if initial is None:
        sys.exit(0)
    if not isinstance(initial, dict) or set(initial) != {'kernel', 'plan'} or not isinstance(initial['kernel'], str):
        raise ValueError('invalid_bootstrap')
    kernel = {'__name__': 'wsl_proxy_readonly_query'}
    exec(compile(initial['kernel'], '<embedded-kernel>', 'exec'), kernel)
    plan = kernel['validate']({'operation': 'precheck', 'plan': initial['plan'], 'protocol': None, 'peer': None})
    kernel['guard'](plan)
    prepared = kernel['prepare_lookup'](plan)
    del initial
    emit({'kind': 'ready'})
    sequence = 0
    while True:
        signal.alarm(65)
        request = receive(2048)
        if request is None:
            break
        signal.alarm(12)
        require = kernel['require']
        require(isinstance(request, dict) and set(request) == {'id', 'lookups'}, 'invalid_query')
        require(type(request['id']) is int and request['id'] == sequence + 1 and request['id'] <= 0xffffffffffffffff, 'invalid_query_sequence')
        lookups = request['lookups']
        require(isinstance(lookups, list) and 1 <= len(lookups) <= 16, 'invalid_query_count')
        keys = []
        for item in lookups:
            require(isinstance(item, dict) and set(item) == {'protocol','peer'} and item['protocol'] in ('tcp','udp'), 'invalid_query_item')
            require(kernel['endpoint'](item['peer'])[0] == plan['guest'], 'invalid_query_peer')
            keys.append((item['protocol'], item['peer']))
        sequence = request['id']
        try:
            read_start = time.monotonic_ns()
            ct = kernel['Conntrack']()
            try:
                payloads = ct.request(kernel['CT_GET'], kernel['ROOT'] | kernel['MATCH'])
            finally:
                ct.close()
            read_end = time.monotonic_ns()
            # Read includes fresh socket construction, netlink envelope checks,
            # and socket close; decode includes tuple validation and indexing.
            try:
                entries = [kernel['parse_entry'](payload) for payload in payloads]
            finally:
                del payloads
            try:
                origins = kernel['resolve_queries'](prepared, entries, keys)
            finally:
                del entries
            decode_end = time.monotonic_ns()
            kernel_read_us = (read_end - read_start) // 1000
            decode_lookup_us = (decode_end - read_end) // 1000
            require(0 <= kernel_read_us + decode_lookup_us <= 12000000, 'invalid_query_timing')
            emit({'kind': 'origins', 'id': sequence, 'origins': origins, 'kernel_read_us': kernel_read_us, 'decode_lookup_us': decode_lookup_us})
        except (kernel['Failure'], OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
            emit({'kind': 'lookup_error', 'id': sequence, 'error': reason(error)})
except Exception as error:
    emit({'kind': 'fatal', 'error': reason(error)})
    sys.exit(1)
"#;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct Lookup {
    pub protocol: &'static str,
    pub peer: SocketAddrV4,
}

/// Guest durations per physical batch, measured with a monotonic clock.
/// `kernel_read_us` includes fresh Conntrack socket construction, the netlink
/// request/envelope validation, and socket close (not just kernel execution).
/// `decode_lookup_us` covers tuple decoding/validation and snapshot indexing.
/// Neither includes JSON/stdio transit, host queueing, or helper startup.
#[derive(Debug)]
pub struct BatchOrigins {
    pub origins: Vec<Option<SocketAddrV4>>,
    pub kernel_read_us: u64,
    pub decode_lookup_us: u64,
}

#[cfg(any(windows, test))]
#[derive(Serialize)]
struct Query {
    id: u64,
    lookups: Vec<Lookup>,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Ready {},
    Origins {
        id: u64,
        origins: Vec<Option<SocketAddrV4>>,
        kernel_read_us: u64,
        decode_lookup_us: u64,
    },
    LookupError {
        id: u64,
        error: String,
    },
    Fatal {
        error: String,
    },
}

#[cfg(any(windows, test))]
fn read_response(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> Result<Response, String> {
    buffer.clear();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| format!("query_transport_read_failed: {error}"))?;
        if available.is_empty() {
            return Err("query_transport_incomplete_response".into());
        }
        let available = &available[..available.len().min(RESPONSE_LIMIT + 1 - buffer.len())];
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        buffer.extend_from_slice(&available[..count]);
        reader.consume(count);
        if buffer.len() > RESPONSE_LIMIT {
            return Err("query_transport_response_limit".into());
        }
        if buffer.last() == Some(&b'\n') {
            break;
        }
    }
    let response: Response = serde_json::from_slice(buffer)
        .map_err(|error| format!("query_transport_invalid_response: {error}"))?;
    if let Response::LookupError { error, .. } | Response::Fatal { error } = &response
        && (error.is_empty() || error.len() > 512 || error.chars().any(char::is_control))
    {
        return Err("query_transport_invalid_error".into());
    }
    if let Response::Origins {
        kernel_read_us,
        decode_lookup_us,
        ..
    } = &response
        && kernel_read_us
            .checked_add(*decode_lookup_us)
            .is_none_or(|total| total > GUEST_TIMING_LIMIT_US)
    {
        return Err("query_transport_invalid_timing".into());
    }
    Ok(response)
}

#[cfg(any(windows, test))]
fn origin_allowed(plan: &Plan, origin: SocketAddrV4) -> bool {
    if plan.system_dns.is_none() {
        return plan.origins.contains(&origin);
    }
    let [first, second, _, _] = origin.ip().octets();
    plan.origins.is_empty()
        && first != 0
        && first != 127
        && first < 224
        && !(first == 169 && second == 254)
        && origin.port() != 0
        && origin != plan.ingress
}

/// A bounded, ordered, read-only stdio batch, never a guest service or listener.
/// Idle helpers exit and are reaped; the next query starts a fresh guarded batch.
pub struct QueryBridge {
    #[cfg(windows)]
    plan: Plan,
    #[cfg(windows)]
    transport: Option<windows::Transport>,
    #[cfg(windows)]
    reopen_after: Option<std::time::Instant>,
}

impl QueryBridge {
    pub fn open(plan: &Plan) -> Result<Self, String> {
        #[cfg(windows)]
        {
            let transport = windows::Transport::open(plan)?;
            Ok(Self {
                plan: plan.clone(),
                transport: Some(transport),
                reopen_after: None,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = plan;
            Err("unsupported_platform: Windows host required".into())
        }
    }

    /// A failed lookup keeps the batch usable. A transport failure discards it;
    /// only a subsequent request may reopen it, never replaying a sent request.
    pub fn query_batch(&mut self, lookups: Vec<Lookup>) -> Result<BatchOrigins, String> {
        #[cfg(windows)]
        {
            if lookups.is_empty()
                || lookups.len() > MAX_LOOKUPS
                || lookups.iter().any(|key| {
                    !matches!(key.protocol, "tcp" | "udp")
                        || key.peer.ip() != &self.plan.guest
                        || key.peer.port() == 0
                })
            {
                return Err("query_lookup_invalid_batch".into());
            }
            if self.transport.as_ref().is_none_or(|batch| !batch.active()) {
                if self
                    .reopen_after
                    .is_some_and(|deadline| std::time::Instant::now() < deadline)
                {
                    return Err("query_transport_reopen_cooldown".into());
                }
                self.close()?;
                match windows::Transport::open(&self.plan) {
                    Ok(transport) => {
                        self.transport = Some(transport);
                        self.reopen_after = None;
                    }
                    Err(error) => {
                        self.reopen_after =
                            Some(std::time::Instant::now() + std::time::Duration::from_secs(30));
                        return Err(error);
                    }
                }
            }
            let result = self
                .transport
                .as_mut()
                .expect("a transport was opened above")
                .query(lookups, &self.plan);
            if result
                .as_ref()
                .is_err_and(|error| error.starts_with("query_transport_"))
            {
                self.reopen_after =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(30));
                if let Err(close_error) = self.close() {
                    return Err(format!("{}; {close_error}", result.unwrap_err()));
                }
            }
            result
        }
        #[cfg(not(windows))]
        {
            let _ = lookups;
            Err("unsupported_platform: Windows host required".into())
        }
    }

    /// Terminates and reaps only this bridge's native wsl.exe process.
    pub fn close(&mut self) -> Result<(), String> {
        #[cfg(windows)]
        if let Some(mut transport) = self.transport.take() {
            return transport.close();
        }
        Ok(())
    }
}

impl Drop for QueryBridge {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(windows)]
mod windows {
    use super::{
        BOOTSTRAP, BOOTSTRAP_LIMIT, BatchOrigins, Lookup, Plan, Query, REQUEST_LIMIT, Response,
        read_response,
    };
    use serde::Serialize;
    use std::io::{BufReader, Write};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, SyncSender};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    const START_DEADLINE: Duration = Duration::from_secs(30);
    const QUERY_DEADLINE: Duration = Duration::from_secs(12);
    const IDLE_DEADLINE: Duration = Duration::from_secs(45);
    const REUSE_WINDOW: Duration = Duration::from_secs(40);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CancelSynchronousIo(thread: *mut std::ffi::c_void) -> i32;
    }

    struct Process(Mutex<Child>);

    impl Process {
        fn terminate(&self) -> Result<(), String> {
            let mut child = self.0.lock().unwrap_or_else(|error| error.into_inner());
            if matches!(child.try_wait(), Ok(Some(_))) {
                return Ok(());
            }
            if let Err(error) = child.kill() {
                if child.try_wait().ok().flatten().is_some() {
                    return Ok(());
                }
                return Err(format!("query_transport_terminate_failed: {error}"));
            }
            child
                .wait()
                .map(|_| ())
                .map_err(|error| format!("query_transport_reap_failed: {error}"))
        }
    }

    struct Reaper(Arc<Process>);

    impl Drop for Reaper {
        fn drop(&mut self) {
            let _ = self.0.terminate();
        }
    }

    pub(super) struct Transport {
        requests: Option<SyncSender<Query>>,
        responses: Receiver<Result<Response, String>>,
        worker: Option<JoinHandle<()>>,
        process: Arc<Process>,
        stopped: Arc<AtomicBool>,
        last_used: Instant,
        sequence: u64,
    }

    impl Transport {
        pub(super) fn open(plan: &Plan) -> Result<Self, String> {
            plan.target
                .id
                .strip_prefix('{')
                .and_then(|id| id.strip_suffix('}'))
                .filter(|id| {
                    id.len() == 36
                        && id.bytes().enumerate().all(|(index, byte)| {
                            if matches!(index, 8 | 13 | 18 | 23) {
                                byte == b'-'
                            } else {
                                byte.is_ascii_hexdigit()
                            }
                        })
                })
                .ok_or("query_transport_invalid_distribution_id")?;
            #[derive(Serialize)]
            struct Initial<'a> {
                kernel: &'static str,
                plan: &'a Plan,
            }
            let mut initial = serde_json::to_vec(&Initial {
                kernel: include_str!("kernel.py"),
                plan,
            })
            .map_err(|error| format!("query_transport_bootstrap_encoding_failed: {error}"))?;
            initial.push(b'\n');
            if initial.len() > BOOTSTRAP_LIMIT {
                return Err("query_transport_bootstrap_limit".into());
            }
            let executable = crate::host::wsl_executable()
                .map_err(|error| format!("query_transport_wsl_executable_failed: {error}"))?;
            let directory = executable
                .parent()
                .ok_or("query_transport_invalid_wsl_path")?;
            let mut child = Command::new(&executable)
                .current_dir(directory)
                .args([
                    "--distribution-id",
                    &plan.target.id,
                    "--cd",
                    "/",
                    "--user",
                    "root",
                    "--exec",
                    "/usr/bin/python3",
                    "-I",
                    "-u",
                    "-c",
                    BOOTSTRAP,
                ])
                .env("WSL_UTF8", "1")
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("query_transport_start_failed: {error}"))?;
            let input = child.stdin.take().expect("piped stdin was requested");
            let output = child.stdout.take().expect("piped stdout was requested");
            let process = Arc::new(Process(Mutex::new(child)));
            let reaper = Reaper(Arc::clone(&process));
            let stopped = Arc::new(AtomicBool::new(false));
            let worker_stopped = Arc::clone(&stopped);
            let (requests, receiver) = mpsc::sync_channel(1);
            let (sender, responses) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("wsl-query-stdio".into())
                .spawn(move || {
                    let _reaper = reaper;
                    run(input, output, initial, receiver, sender, &worker_stopped);
                })
                .map_err(|error| format!("query_transport_thread_failed: {error}"))?;
            let transport = Self {
                requests: Some(requests),
                responses,
                worker: Some(worker),
                process,
                stopped,
                last_used: Instant::now(),
                sequence: 0,
            };
            let ready = transport.receive(START_DEADLINE);
            match ready {
                Ok(Response::Ready {}) => Ok(transport),
                Ok(Response::Fatal { error }) => {
                    Err(format!("query_transport_guard_failed: {error}"))
                }
                Ok(_) => Err("query_transport_expected_ready".into()),
                Err(error) => Err(error),
            }
        }

        pub(super) fn active(&self) -> bool {
            self.sequence < u64::MAX
                && self.last_used.elapsed() < REUSE_WINDOW
                && self
                    .worker
                    .as_ref()
                    .is_some_and(|worker| !worker.is_finished())
        }

        fn receive(&self, deadline: Duration) -> Result<Response, String> {
            self.responses
                .recv_timeout(deadline)
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => "query_transport_timeout".to_owned(),
                    mpsc::RecvTimeoutError::Disconnected => "query_transport_closed".to_owned(),
                })?
        }

        pub(super) fn query(
            &mut self,
            lookups: Vec<Lookup>,
            plan: &Plan,
        ) -> Result<BatchOrigins, String> {
            let count = lookups.len();
            self.sequence += 1;
            self.requests
                .as_ref()
                .ok_or("query_transport_closed")?
                .try_send(Query {
                    id: self.sequence,
                    lookups,
                })
                .map_err(|error| format!("query_transport_request_channel_failed: {error}"))?;
            let response = self.receive(QUERY_DEADLINE)?;
            self.last_used = Instant::now();
            match response {
                Response::Origins {
                    id,
                    origins,
                    kernel_read_us,
                    decode_lookup_us,
                } if id == self.sequence && origins.len() == count => {
                    if !origins
                        .iter()
                        .flatten()
                        .all(|origin| super::origin_allowed(plan, *origin))
                    {
                        return Err("query_transport_unrelated_origin".into());
                    }
                    Ok(BatchOrigins {
                        origins,
                        kernel_read_us,
                        decode_lookup_us,
                    })
                }
                Response::LookupError { id, error } if id == self.sequence => {
                    Err(format!("query_lookup_{error}"))
                }
                Response::Fatal { error } => Err(format!("query_transport_guest_failed: {error}")),
                _ => Err("query_transport_response_sequence_mismatch".into()),
            }
        }

        pub(super) fn close(&mut self) -> Result<(), String> {
            self.stopped.store(true, Ordering::Release);
            self.requests.take();
            if let Some(worker) = &self.worker {
                // Cancel pending synchronous stdio before waiting for process exit.
                unsafe { CancelSynchronousIo(worker.as_raw_handle()) };
            }
            let process_result = self.process.terminate();
            if let Some(worker) = self.worker.take() {
                // Killing wsl.exe does not by itself cancel a host thread's pipe
                // I/O. Repeated cancellation covers the race before Read/WriteFile.
                while !worker.is_finished() {
                    // This live JoinHandle owns precisely our stdio thread handle.
                    unsafe { CancelSynchronousIo(worker.as_raw_handle()) };
                    thread::sleep(Duration::from_millis(2));
                }
                if worker.join().is_err() {
                    return Err("query_transport_worker_panicked".into());
                }
            }
            process_result
        }
    }

    impl Drop for Transport {
        fn drop(&mut self) {
            let _ = self.close();
        }
    }

    fn run(
        mut input: ChildStdin,
        output: ChildStdout,
        mut request: Vec<u8>,
        requests: Receiver<Query>,
        responses: SyncSender<Result<Response, String>>,
        stopped: &AtomicBool,
    ) {
        let mut output = BufReader::new(output);
        let mut response = Vec::with_capacity(super::RESPONSE_LIMIT + 1);
        let ready = exchange(&mut input, &mut output, &request, &mut response, stopped);
        let initialized = matches!(ready, Ok(Response::Ready {}));
        if responses.send(ready).is_err() || !initialized {
            return;
        }
        while !stopped.load(Ordering::Acquire) {
            let query = match requests.recv_timeout(IDLE_DEADLINE) {
                Ok(query) => query,
                Err(_) => return,
            };
            request.clear();
            let result = serde_json::to_writer(&mut request, &query)
                .map_err(|error| format!("query_transport_request_encoding_failed: {error}"))
                .and_then(|()| {
                    request.push(b'\n');
                    if request.len() > REQUEST_LIMIT {
                        return Err("query_transport_request_limit".into());
                    }
                    exchange(&mut input, &mut output, &request, &mut response, stopped)
                });
            let usable = matches!(
                result,
                Ok(Response::Origins { .. } | Response::LookupError { .. })
            );
            if responses.send(result).is_err() || !usable {
                return;
            }
        }
    }

    fn exchange(
        input: &mut ChildStdin,
        output: &mut BufReader<ChildStdout>,
        request: &[u8],
        response: &mut Vec<u8>,
        stopped: &AtomicBool,
    ) -> Result<Response, String> {
        if stopped.load(Ordering::Acquire) {
            return Err("query_transport_closed".into());
        }
        let mut remaining = request;
        while !remaining.is_empty() {
            if stopped.load(Ordering::Acquire) {
                return Err("query_transport_closed".into());
            }
            let written = input
                .write(remaining)
                .map_err(|error| format!("query_transport_write_failed: {error}"))?;
            if written == 0 {
                return Err("query_transport_closed".into());
            }
            remaining = &remaining[written..];
        }
        if stopped.load(Ordering::Acquire) {
            return Err("query_transport_closed".into());
        }
        read_response(output, response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn original_destination_bounds_remain_explicit_in_both_modes() {
        let mut plan: Plan = serde_json::from_value(serde_json::json!({
            "target": {
                "id": "{01234567-89ab-cdef-0123-456789abcdef}",
                "name": "WSLProxyLab-Target",
                "base_path": "D:\\WSL\\ProxyLab\\Target",
                "version": 2
            },
            "cgroup_ns": "cgroup:[4026534269]",
            "cgroup_root": "25:386884",
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "guest": "172.28.83.138",
            "ingress": "172.28.80.1:43771",
            "origins": ["172.28.80.1:43772"],
            "cookie": 305419896
        }))
        .unwrap();
        assert!(origin_allowed(&plan, "172.28.80.1:43772".parse().unwrap()));
        assert!(!origin_allowed(&plan, "93.184.216.34:443".parse().unwrap()));
        plan.system_dns = Some("10.255.255.254".parse().unwrap());
        assert!(!origin_allowed(&plan, "93.184.216.34:443".parse().unwrap()));
        plan.origins.clear();
        assert!(origin_allowed(&plan, "93.184.216.34:443".parse().unwrap()));
        for endpoint in [
            "127.0.0.1:443",
            "0.0.0.0:443",
            "169.254.1.1:443",
            "224.0.0.1:443",
            "93.184.216.34:0",
            "172.28.80.1:43771",
        ] {
            assert!(
                !origin_allowed(&plan, endpoint.parse().unwrap()),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn response_is_one_ordered_bounded_frame() {
        let mut reader = Cursor::new(b"{\"kind\":\"ready\"}\n{\"kind\":\"origins\",\"id\":7,\"origins\":[null,\"172.20.0.1:8080\"],\"kernel_read_us\":123,\"decode_lookup_us\":45}\n");
        let mut buffer = Vec::new();
        assert_eq!(
            read_response(&mut reader, &mut buffer).unwrap(),
            Response::Ready {}
        );
        assert_eq!(
            read_response(&mut reader, &mut buffer).unwrap(),
            Response::Origins {
                id: 7,
                origins: vec![None, Some("172.20.0.1:8080".parse().unwrap())],
                kernel_read_us: 123,
                decode_lookup_us: 45,
            }
        );
        assert!(
            read_response(&mut reader, &mut buffer)
                .unwrap_err()
                .contains("incomplete_response")
        );
    }

    #[test]
    fn response_rejects_overflow_truncation_and_unknown_fields() {
        let mut buffer = Vec::new();
        let large = vec![b' '; RESPONSE_LIMIT + 20];
        let mut reader = Cursor::new(large);
        assert!(
            read_response(&mut reader, &mut buffer)
                .unwrap_err()
                .contains("response_limit")
        );
        assert_eq!(reader.position(), (RESPONSE_LIMIT + 1) as u64);
        for frame in [
            "{\"kind\":\"ready\"}",
            "{\"kind\":\"ready\",\"operation\":\"install\"}\n",
            "{\"kind\":\"origin\",\"id\":1}\n",
            "{\"kind\":\"origins\",\"id\":1}\n",
            "{\"kind\":\"fatal\",\"error\":\"bad\\nerror\"}\n",
        ] {
            assert!(
                read_response(&mut Cursor::new(frame), &mut buffer).is_err(),
                "{frame}"
            );
        }
    }

    #[test]
    fn response_rejects_malformed_or_unbounded_guest_timings() {
        let mut buffer = Vec::new();
        for metadata in [
            "",
            ",\"kernel_read_us\":1",
            ",\"kernel_read_us\":-1,\"decode_lookup_us\":0",
            ",\"kernel_read_us\":1.5,\"decode_lookup_us\":0",
            ",\"kernel_read_us\":\"1\",\"decode_lookup_us\":0",
            ",\"kernel_read_us\":null,\"decode_lookup_us\":0",
            ",\"kernel_read_us\":0,\"decode_lookup_us\":12000001",
            ",\"kernel_read_us\":12000000,\"decode_lookup_us\":1",
            ",\"kernel_read_us\":18446744073709551615,\"decode_lookup_us\":1",
            ",\"kernel_read_us\":18446744073709551616,\"decode_lookup_us\":0",
            ",\"kernel_read_us\":0,\"decode_lookup_us\":0,\"kernel_read_us\":1",
            ",\"kernel_read_us\":0,\"decode_lookup_us\":0,\"other_us\":1",
        ] {
            let frame = format!("{{\"kind\":\"origins\",\"id\":1,\"origins\":[null]{metadata}}}\n");
            assert!(
                read_response(&mut Cursor::new(frame), &mut buffer).is_err(),
                "{metadata}"
            );
        }
        for (kernel_read_us, decode_lookup_us) in [(0, 0), (12_000_000, 0), (0, 12_000_000)] {
            let frame = format!(
                "{{\"kind\":\"origins\",\"id\":1,\"origins\":[null],\"kernel_read_us\":{kernel_read_us},\"decode_lookup_us\":{decode_lookup_us}}}\n"
            );
            assert!(read_response(&mut Cursor::new(frame), &mut buffer).is_ok());
        }
    }

    #[test]
    fn lookup_failure_remains_distinct_from_transport_failure() {
        let mut buffer = Vec::new();
        let frame = b"{\"kind\":\"lookup_error\",\"id\":9,\"error\":\"mapping_missing_ambiguous_or_unowned\"}\n";
        assert_eq!(
            read_response(&mut Cursor::new(frame), &mut buffer).unwrap(),
            Response::LookupError {
                id: 9,
                error: "mapping_missing_ambiguous_or_unowned".into()
            }
        );
    }

    #[test]
    fn requests_have_only_fixed_readonly_fields_and_fit_the_bound() {
        for protocol in ["tcp", "udp"] {
            let bytes = serde_json::to_vec(&Query {
                id: u64::MAX,
                lookups: vec![
                    Lookup {
                        protocol,
                        peer: "255.255.255.255:65535".parse().unwrap()
                    };
                    MAX_LOOKUPS
                ],
            })
            .unwrap();
            assert!(bytes.len() < REQUEST_LIMIT);
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 2);
            assert!(value.get("operation").is_none());
            assert_eq!(value["lookups"][0]["protocol"], protocol);
        }
    }
}
