use super::{
    BUFFER_SIZE, CONNECT_TIMEOUT, Flow, POLL_INTERVAL, Plan, Route, Shared, TcpRegistration,
    destination, route, select_route, serve_dns_tcp,
};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

/// Longest single wait on a quiet connection. Deadlines and the stop flag are
/// rechecked at least this often; a stop also shuts the sockets down, which
/// ends the wait at once.
const QUIET_WAIT: Duration = Duration::from_secs(1);

pub(super) fn forward_tcp(
    plan: &Plan,
    client: TcpStream,
    registration: &TcpRegistration,
    runtime: Option<&crate::managed::Runtime>,
) -> Result<(), String> {
    let shared = &registration.shared;
    let flow = &registration.flow;
    let origin = destination(plan, "tcp", registration.peer, shared)?;
    flow.destination(origin);
    let selected = select_route(plan, runtime, "tcp", origin, flow, shared)?;
    if selected == Route::Dns {
        flow.stage("dns");
        return serve_dns_tcp(
            plan,
            runtime.expect("DNS route requires M2 runtime"),
            client,
            registration,
            origin,
        );
    }
    if shared.is_stopping() {
        return Ok(());
    }
    flow.stage("connect");
    let upstream = match selected {
        Route::Direct(target) => {
            TcpStream::connect_timeout(&SocketAddr::V4(target), CONNECT_TIMEOUT)
                .map_err(|e| format!("connect to authorized direct endpoint: {e}"))?
        }
        Route::Chain => runtime
            .expect("chain route requires M2 runtime")
            .policy
            .chain(origin)
            .map_err(|_| "two-hop TCP chain connect failed".to_string())?,
        Route::Dns => unreachable!("DNS handled internally"),
    };
    registration.attach_origin(&upstream)?;
    flow.stage("metadata");
    if client.peer_addr().ok() != Some(SocketAddr::V4(registration.peer))
        || destination(plan, "tcp", registration.peer, shared)? != origin
        || route(plan, runtime, "tcp", origin)? != selected
    {
        return Err("TCP mapping changed while connecting to origin".into());
    }
    flow.stage("relay");
    relay(client, upstream, shared, flow).map_err(|e| format!("relay: {e}"))
}

pub(super) fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

/// Out of sockets, handles or buffer space. That passes; it is no reason to
/// stop forwarding for every other connection.
pub(super) fn exhausted(error: &io::Error) -> bool {
    // WSAEMFILE and WSAENOBUFS on Windows; ENFILE, EMFILE and ENOBUFS elsewhere.
    #[cfg(windows)]
    const CODES: [i32; 2] = [10024, 10055];
    #[cfg(not(windows))]
    const CODES: [i32; 3] = [23, 24, 105];
    error.kind() == io::ErrorKind::OutOfMemory
        || error
            .raw_os_error()
            .is_some_and(|code| CODES.contains(&code))
}

struct Pipe {
    buffer: [u8; BUFFER_SIZE],
    start: usize,
    end: usize,
    eof: bool,
    shutdown: bool,
}

impl Pipe {
    /// This direction waits for data from its source.
    fn wants_read(&self) -> bool {
        self.start == self.end && !self.eof
    }

    /// This direction holds data its target has not accepted yet.
    fn wants_write(&self) -> bool {
        self.start < self.end
    }

    fn new() -> Self {
        Self {
            buffer: [0; BUFFER_SIZE],
            start: 0,
            end: 0,
            eof: false,
            shutdown: false,
        }
    }

    fn pump(
        &mut self,
        source: &mut TcpStream,
        target: &mut TcpStream,
        flow: &Flow,
        upload: bool,
    ) -> io::Result<bool> {
        let mut progressed = false;
        if self.start == self.end && !self.eof {
            match source.read(&mut self.buffer) {
                Ok(0) => self.eof = true,
                Ok(size) => {
                    self.start = 0;
                    self.end = size;
                    progressed = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.start < self.end {
            match target.write(&self.buffer[self.start..self.end]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(size) => {
                    self.start += size;
                    if upload {
                        flow.tx(size);
                    } else {
                        flow.rx(size);
                    }
                    progressed = true;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
        }
        if self.eof && self.start == self.end && !self.shutdown {
            target.shutdown(Shutdown::Write)?;
            self.shutdown = true;
            progressed = true;
        }
        Ok(progressed)
    }
}

pub(super) fn relay(
    mut client: TcpStream,
    mut upstream: TcpStream,
    shared: &Shared,
    flow: &Flow,
) -> io::Result<()> {
    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;
    client.set_nonblocking(true)?;
    upstream.set_nonblocking(true)?;
    let mut request = Pipe::new();
    let mut response = Pipe::new();
    let mut touched = Instant::now();
    let mut half_closed = None;
    while !shared.is_stopping() {
        let mut progressed = request.pump(&mut client, &mut upstream, flow, true)?;
        if shared.is_stopping() {
            break;
        }
        progressed |= response.pump(&mut upstream, &mut client, flow, false)?;
        if request.shutdown && response.shutdown {
            return Ok(());
        }
        let now = Instant::now();
        if progressed {
            touched = now;
        }
        if request.eof || response.eof {
            let since = if progressed {
                // A half-closed stream may continue carrying a long response.
                // Bound only the quiet period after EOF, not total response time.
                half_closed = Some(now);
                now
            } else {
                *half_closed.get_or_insert(now)
            };
            if now.duration_since(since) >= shared.limits.half_close {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP half-close deadline",
                ));
            }
        }
        if now.duration_since(touched) >= shared.limits.tcp_idle {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP idle deadline"));
        }
        if !progressed {
            // Sleep until a socket is ready instead of polling: a long-lived
            // idle connection then costs no CPU.
            let mut wait = QUIET_WAIT.min(
                shared
                    .limits
                    .tcp_idle
                    .saturating_sub(now.duration_since(touched)),
            );
            if let Some(since) = half_closed {
                wait = wait.min(
                    shared
                        .limits
                        .half_close
                        .saturating_sub(now.duration_since(since)),
                );
            }
            wait_quiet(&client, &upstream, &request, &response, wait);
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    Ok(())
}

/// Waits until one side can be read or written as `request` and `response`
/// need, a socket fails or hangs up, or `timeout` passes.
#[cfg(windows)]
fn wait_quiet(
    client: &TcpStream,
    upstream: &TcpStream,
    request: &Pipe,
    response: &Pipe,
    timeout: Duration,
) {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        POLLHUP, POLLRDNORM, POLLWRNORM, SOCKET_ERROR, WSAPOLLFD, WSAPoll,
    };
    let interest = |read: bool, write: bool| {
        (if read { POLLRDNORM } else { 0 }) | (if write { POLLWRNORM } else { 0 })
    };
    let mut descriptors = [WSAPOLLFD::default(); 2];
    let mut count = 0;
    for (socket, events) in [
        (
            client.as_raw_socket(),
            interest(request.wants_read(), response.wants_write()),
        ),
        (
            upstream.as_raw_socket(),
            interest(response.wants_read(), request.wants_write()),
        ),
    ] {
        if events != 0 {
            descriptors[count].fd = socket as _;
            descriptors[count].events = events;
            count += 1;
        }
    }
    if count == 0 {
        thread::sleep(POLL_INTERVAL);
        return;
    }
    let millis = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
    // SAFETY: `descriptors` is a live local array and `count` never exceeds its
    // length; both sockets belong to this thread for the whole call.
    let ready = unsafe { WSAPoll(descriptors.as_mut_ptr(), count as u32, millis) };
    // Readiness, an error or a hang-up all end the wait; the next pump finds out
    // which. WSAPoll reports POLLHUP whatever was asked for, so after a peer's
    // half-close it returns at once on every call: a wait that saw nothing but
    // hang-ups sleeps instead of spinning while the other direction drains.
    let only_hangup = ready > 0
        && descriptors[..count]
            .iter()
            .all(|descriptor| descriptor.revents & !POLLHUP == 0);
    if ready == SOCKET_ERROR || only_hangup {
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(not(windows))]
fn wait_quiet(_: &TcpStream, _: &TcpStream, _: &Pipe, _: &Pipe, _: Duration) {
    thread::sleep(POLL_INTERVAL);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_out_of_sockets_is_not_a_listener_failure() {
        #[cfg(windows)]
        let (codes, broken) = ([10024, 10055], 10038); // WSAENOTSOCK stays fatal.
        #[cfg(not(windows))]
        let (codes, broken) = ([24, 105], 9); // EBADF stays fatal.
        for code in codes {
            assert!(exhausted(&io::Error::from_raw_os_error(code)));
        }
        assert!(!exhausted(&io::Error::from_raw_os_error(broken)));
        assert!(!exhausted(&io::Error::from(io::ErrorKind::ConnectionReset)));
    }

    #[test]
    fn connection_reset_is_transient() {
        let error = io::Error::from(io::ErrorKind::ConnectionReset);
        assert!(transient(&error));
    }
}
