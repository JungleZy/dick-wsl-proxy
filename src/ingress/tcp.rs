use super::{
    BUFFER_SIZE, CONNECT_TIMEOUT, Flow, HALF_CLOSE_TIMEOUT, POLL_INTERVAL, Plan, Route, Shared,
    TCP_IDLE_TIMEOUT, TcpRegistration, destination, route, select_route, serve_dns_tcp,
};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::thread;
use std::time::Instant;

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

struct Pipe {
    buffer: [u8; BUFFER_SIZE],
    start: usize,
    end: usize,
    eof: bool,
    shutdown: bool,
}

impl Pipe {
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
            let since = half_closed.get_or_insert(now);
            if now.duration_since(*since) >= HALF_CLOSE_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "TCP half-close deadline",
                ));
            }
        }
        if now.duration_since(touched) >= TCP_IDLE_TIMEOUT {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP idle deadline"));
        }
        if !progressed {
            thread::sleep(POLL_INTERVAL);
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_reset_is_transient() {
        let error = io::Error::from(io::ErrorKind::ConnectionReset);
        assert!(transient(&error));
    }
}
