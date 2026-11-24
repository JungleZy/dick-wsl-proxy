//! First hop -> authenticated residential SOCKS5 -> destination, with a small
//! pool of tunnels already authenticated at the residential proxy. A pooled
//! tunnel only needs its CONNECT, which saves the first-hop CONNECT and the
//! residential method and authentication round trips of a fresh chain.
use super::{
    AuthPacket, SETUP_TIMEOUT, WipedBytes, connect, connect_addr, connect_reply, connect_request,
    expect, receive, remaining, send,
};
use crate::credential::Residential;
use std::io;
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Authenticated tunnels kept ready while chains are being opened.
pub(super) const POOL_TARGET: usize = if cfg!(test) { 0 } else { 2 };
/// A pooled tunnel is closed after this long unused; proxies drop quiet
/// sessions on their own schedule, and an idle one should not be held.
const POOL_IDLE: Duration = Duration::from_secs(20);
/// Tunnels are only kept ready this long after the last chain was opened.
const DEMAND_WINDOW: Duration = Duration::from_secs(60);

/// How a residential handshake failed: refused or broken for real, or in a
/// way that only shows the proxy could not take pipelined requests.
pub(super) enum Setup {
    Failed(String),
    Incompatible(String),
}

impl Setup {
    fn into_message(self) -> String {
        match self {
            Self::Failed(message) | Self::Incompatible(message) => message,
        }
    }
}

struct Pooled {
    id: u64,
    stream: TcpStream,
    since: Instant,
}

pub(super) struct Dialer {
    first_hop: SocketAddrV4,
    residential: Residential,
    /// Whether residential handshakes still send authentication and CONNECT
    /// in one write. Cleared for the rest of this takeover the first time the
    /// proxy cannot follow that.
    pub(super) pipeline: AtomicBool,
    target: usize,
    pool: Mutex<Vec<Pooled>>,
    next_id: AtomicUsize,
    in_flight: AtomicUsize,
    last_demand: Mutex<Option<Instant>>,
    closed: AtomicBool,
}

impl Dialer {
    pub(super) fn new(first_hop: SocketAddrV4, residential: Residential, target: usize) -> Self {
        Self {
            first_hop,
            residential,
            pipeline: AtomicBool::new(true),
            target,
            pool: Mutex::new(Vec::new()),
            next_id: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            last_demand: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Drops every pooled tunnel; tunnels still being built are dropped when
    /// they finish. Called when the policy is dropped.
    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.pool.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// A chain to `dest`: on a pooled tunnel when one is alive, otherwise a
    /// fresh one. The single deadline covers every handshake.
    pub(super) fn chain(self: &Arc<Self>, dest: SocketAddr) -> Result<TcpStream, String> {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        *self.last_demand.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        let pooled = self.take();
        self.refill();
        if let Some(mut stream) = pooled {
            match pooled_connect(&mut stream, dest, deadline) {
                Ok(()) => return finish(stream),
                Err(Setup::Failed(message)) => return Err(message),
                // The tunnel went stale while pooled: build a fresh chain.
                Err(Setup::Incompatible(_)) => {}
            }
        }
        self.fresh(dest, deadline).and_then(finish)
    }

    fn fresh(&self, dest: SocketAddr, deadline: Instant) -> Result<TcpStream, String> {
        let pipelined = self.pipeline.load(Ordering::Relaxed);
        let mut stream = self.open_residential(deadline)?;
        match self.residential_connect(&mut stream, dest, deadline, pipelined) {
            Ok(()) => Ok(stream),
            Err(Setup::Incompatible(_)) if pipelined => {
                self.pipeline.store(false, Ordering::Relaxed);
                let mut stream = self.open_residential(deadline)?;
                self.residential_connect(&mut stream, dest, deadline, false)
                    .map_err(Setup::into_message)?;
                Ok(stream)
            }
            Err(error) => Err(error.into_message()),
        }
    }

    /// The newest pooled tunnel that is still open and not past its idle limit.
    fn take(&self) -> Option<TcpStream> {
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(entry) = pool.pop() {
            if entry.since.elapsed() < POOL_IDLE && alive(&entry.stream) {
                return Some(entry.stream);
            }
        }
        None
    }

    /// Starts background dials until pooled plus in-flight tunnels reach the
    /// target, while chains are still being asked for.
    fn refill(self: &Arc<Self>) {
        if self.target == 0 || self.closed.load(Ordering::Acquire) || !self.in_demand() {
            return;
        }
        let pooled = self.pool.lock().unwrap_or_else(|e| e.into_inner()).len();
        loop {
            let in_flight = self.in_flight.load(Ordering::Acquire);
            if pooled + in_flight >= self.target {
                return;
            }
            if self
                .in_flight
                .compare_exchange(
                    in_flight,
                    in_flight + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                continue;
            }
            let dialer = Arc::clone(self);
            let spawned = thread::Builder::new()
                .name("chain-pool".into())
                .spawn(move || dialer.prepare());
            if spawned.is_err() {
                self.in_flight.fetch_sub(1, Ordering::AcqRel);
                return;
            }
        }
    }

    fn in_demand(&self) -> bool {
        self.last_demand
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|at| at.elapsed() < DEMAND_WINDOW)
    }

    /// Background: builds one authenticated tunnel, pools it, and closes it
    /// again if it is still unused when its idle limit passes.
    fn prepare(self: Arc<Self>) {
        let deadline = Instant::now() + SETUP_TIMEOUT;
        let built = self.open_residential(deadline).and_then(|mut stream| {
            authenticate(&mut stream, &self.residential, deadline)
                .map_err(Setup::into_message)
                .map(|()| stream)
        });
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
        let pooled = match built {
            Ok(stream) if !self.closed.load(Ordering::Acquire) => {
                let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
                if pool.len() < self.target {
                    pool.push(Pooled {
                        id,
                        stream,
                        since: Instant::now(),
                    });
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
        if !pooled {
            return;
        }
        thread::sleep(POOL_IDLE);
        let expired = {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            let before = pool.len();
            pool.retain(|entry| entry.id != id);
            pool.len() != before
        };
        if expired {
            self.refill();
        }
    }

    /// A first-hop tunnel to the residential proxy. No residential bytes,
    /// least of all credentials, are sent before this outer CONNECT succeeds.
    fn open_residential(&self, deadline: Instant) -> Result<TcpStream, String> {
        let mut stream =
            TcpStream::connect_timeout(&SocketAddr::V4(self.first_hop), remaining(deadline)?)
                .map_err(|_| "cannot connect to first-hop SOCKS5 endpoint")?;
        stream
            .set_nodelay(true)
            .map_err(|_| "cannot configure chain socket")?;
        send(&mut stream, &[5, 1, 0], deadline)?;
        expect(
            &mut stream,
            &[5, 0],
            deadline,
            "first-hop SOCKS5 method rejected",
        )?;
        connect(&mut stream, self.residential.endpoint(), deadline)?;
        Ok(stream)
    }

    /// Residential method selection, username/password authentication and
    /// CONNECT. Pipelined, authentication and CONNECT go out in one write
    /// once the proxy has selected authentication, saving one residential
    /// round trip.
    fn residential_connect(
        &self,
        stream: &mut TcpStream,
        dest: SocketAddr,
        deadline: Instant,
        pipelined: bool,
    ) -> Result<(), Setup> {
        if !pipelined {
            authenticate(stream, &self.residential, deadline)?;
            return connect_addr(stream, dest, deadline).map_err(Setup::Failed);
        }
        select_authentication(stream, deadline)?;
        let mut packet = AuthPacket([0; 513]);
        let auth = self.residential.auth_packet(&mut packet.0);
        let request = connect_request(dest);
        let mut batch = WipedBytes(Vec::with_capacity(auth + request.len()));
        batch.0.extend_from_slice(&packet.0[..auth]);
        batch.0.extend_from_slice(&request);
        send(stream, &batch.0, deadline).map_err(Setup::Failed)?;
        // A connection that breaks before the authentication reply means the
        // proxy could not take CONNECT behind the credentials, not that either
        // was refused.
        let mut status = [0; 2];
        receive(stream, &mut status, deadline).map_err(Setup::Incompatible)?;
        if status != [1, 0] {
            return Err(Setup::Failed(
                "residential SOCKS5 authentication rejected".into(),
            ));
        }
        connect_reply(stream, deadline).map_err(Setup::Failed)
    }
}

/// Credentials go out only after the proxy has selected username/password
/// authentication.
fn select_authentication(stream: &mut TcpStream, deadline: Instant) -> Result<(), Setup> {
    send(stream, &[5, 1, 2], deadline).map_err(Setup::Failed)?;
    expect(
        stream,
        &[5, 2],
        deadline,
        "residential SOCKS5 authentication method rejected",
    )
    .map_err(Setup::Failed)
}

fn authenticate(
    stream: &mut TcpStream,
    residential: &Residential,
    deadline: Instant,
) -> Result<(), Setup> {
    select_authentication(stream, deadline)?;
    let mut packet = AuthPacket([0; 513]);
    let auth = residential.auth_packet(&mut packet.0);
    send(stream, &packet.0[..auth], deadline).map_err(Setup::Failed)?;
    expect(
        stream,
        &[1, 0],
        deadline,
        "residential SOCKS5 authentication rejected",
    )
    .map_err(Setup::Failed)
}

/// CONNECT on a pooled, already authenticated tunnel. A tunnel that closes
/// before any reply went stale while pooled; a reply that refuses is final.
fn pooled_connect(
    stream: &mut TcpStream,
    dest: SocketAddr,
    deadline: Instant,
) -> Result<(), Setup> {
    if send(stream, &connect_request(dest), deadline).is_err() {
        return Err(Setup::Incompatible("pooled tunnel closed".into()));
    }
    let mut first = [0; 1];
    receive(stream, &mut first, deadline).map_err(Setup::Incompatible)?;
    if first[0] != 5 {
        return Err(Setup::Failed("SOCKS5 CONNECT rejected or malformed".into()));
    }
    connect_reply_rest(stream, deadline).map_err(Setup::Failed)
}

/// The rest of a CONNECT reply whose version byte was already read.
fn connect_reply_rest(stream: &mut TcpStream, deadline: Instant) -> Result<(), String> {
    let mut header = [0; 3];
    receive(stream, &mut header, deadline)?;
    if header[0] != 0 || header[1] != 0 {
        return Err("SOCKS5 CONNECT rejected or malformed".into());
    }
    let length = match header[2] {
        1 => 6,
        4 => 18,
        3 => {
            let mut length = [0];
            receive(stream, &mut length, deadline)?;
            if length[0] == 0 {
                return Err("SOCKS5 CONNECT returned an invalid bound address".into());
            }
            usize::from(length[0]) + 2
        }
        _ => return Err("SOCKS5 CONNECT returned an unsupported address type".into()),
    };
    let mut bound = [0; 257];
    receive(stream, &mut bound[..length], deadline)
}

/// An idle tunnel that has neither closed nor sent anything since it was
/// authenticated.
fn alive(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0];
    let quiet =
        matches!(stream.peek(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock);
    quiet && stream.set_nonblocking(false).is_ok()
}

fn finish(stream: TcpStream) -> Result<TcpStream, String> {
    stream
        .set_read_timeout(None)
        .map_err(|_| "cannot configure chain socket")?;
    stream
        .set_write_timeout(None)
        .map_err(|_| "cannot configure chain socket")?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Shutdown, TcpListener};

    fn local(listener: &TcpListener) -> SocketAddrV4 {
        match listener.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            SocketAddr::V6(_) => unreachable!(),
        }
    }

    fn read_exact<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
        let mut bytes = [0; N];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }

    fn relay(mut left: TcpStream, mut right: TcpStream) {
        let mut reader = left.try_clone().unwrap();
        let mut writer = right.try_clone().unwrap();
        let forward = thread::spawn(move || {
            let _ = std::io::copy(&mut reader, &mut writer);
            let _ = writer.shutdown(Shutdown::Write);
        });
        let _ = std::io::copy(&mut right, &mut left);
        let _ = left.shutdown(Shutdown::Write);
        let _ = forward.join();
    }

    /// A first hop that tunnels every connection to `residential`, and a
    /// residential proxy that records whether each CONNECT arrived together
    /// with the credentials ("fresh") or later on an idle tunnel ("pooled").
    fn proxies() -> (SocketAddrV4, Arc<Mutex<Vec<&'static str>>>) {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let residential = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let first_endpoint = local(&first);
        let residential_endpoint = local(&residential);
        thread::spawn(move || {
            for stream in first.incoming() {
                let mut stream = stream.unwrap();
                thread::spawn(move || {
                    assert_eq!(read_exact::<3>(&mut stream), [5, 1, 0]);
                    stream.write_all(&[5, 0]).unwrap();
                    read_exact::<10>(&mut stream);
                    let target = TcpStream::connect(residential_endpoint).unwrap();
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    relay(stream, target);
                });
            }
        });
        let log = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&log);
        thread::spawn(move || {
            for stream in residential.incoming() {
                let mut stream = stream.unwrap();
                let record = Arc::clone(&record);
                thread::spawn(move || {
                    assert_eq!(read_exact::<3>(&mut stream), [5, 1, 2]);
                    stream.write_all(&[5, 2]).unwrap();
                    read_exact::<31>(&mut stream);
                    stream.set_nonblocking(true).unwrap();
                    thread::sleep(Duration::from_millis(50));
                    let mut peek = [0];
                    let together = stream.peek(&mut peek).is_ok_and(|n| n > 0);
                    stream.set_nonblocking(false).unwrap();
                    stream.write_all(&[1, 0]).unwrap();
                    let mut request = [0; 10];
                    if stream.read_exact(&mut request).is_err() {
                        return; // A pooled tunnel closed unused.
                    }
                    record
                        .lock()
                        .unwrap()
                        .push(if together { "fresh" } else { "pooled" });
                    stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
                    let mut rest = Vec::new();
                    let _ = stream.read_to_end(&mut rest);
                });
            }
        });
        (first_endpoint, log)
    }

    fn dialer(first_hop: SocketAddrV4) -> Arc<Dialer> {
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        Arc::new(Dialer::new(first_hop, residential, 2))
    }

    fn wait_for_pool(dialer: &Dialer, size: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while dialer.pool.lock().unwrap().len() < size {
            assert!(Instant::now() < deadline, "pool never filled");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn a_later_chain_only_sends_connect_on_a_pooled_tunnel() {
        let (first_hop, log) = proxies();
        // The fixture points the credential at port 1; route the first hop's
        // CONNECT to the fake residential proxy whatever it names.
        let dialer = dialer(first_hop);
        let destination = SocketAddr::V4("192.0.2.1:443".parse().unwrap());
        drop(dialer.chain(destination).unwrap());
        wait_for_pool(&dialer, 2);
        drop(dialer.chain(destination).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while log.lock().unwrap().len() < 2 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(*log.lock().unwrap(), ["fresh", "pooled"]);
        dialer.close();
        assert!(dialer.pool.lock().unwrap().is_empty());
    }

    #[test]
    fn closed_or_expired_tunnels_are_never_handed_out() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer(local(&listener));
        let pair = || {
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            (client, server)
        };
        let (closed, server) = pair();
        drop(server);
        thread::sleep(Duration::from_millis(50));
        let (talking, mut server_talking) = pair();
        server_talking.write_all(b"x").unwrap();
        thread::sleep(Duration::from_millis(50));
        let (old, _server_old) = pair();
        let (good, _server_good) = pair();
        let good_port = good.local_addr().unwrap().port();
        {
            let mut pool = dialer.pool.lock().unwrap();
            let now = Instant::now();
            pool.push(Pooled {
                id: 1,
                stream: good,
                since: now,
            });
            pool.push(Pooled {
                id: 2,
                stream: old,
                since: now - POOL_IDLE,
            });
            pool.push(Pooled {
                id: 3,
                stream: talking,
                since: now,
            });
            pool.push(Pooled {
                id: 4,
                stream: closed,
                since: now,
            });
        }
        let taken = dialer.take().unwrap();
        assert_eq!(taken.local_addr().unwrap().port(), good_port);
        assert!(dialer.take().is_none());
    }

    #[test]
    fn a_closed_dialer_neither_refills_nor_keeps_tunnels() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let dialer = dialer(local(&listener));
        *dialer.last_demand.lock().unwrap() = Some(Instant::now());
        dialer.close();
        dialer.refill();
        assert_eq!(dialer.in_flight.load(Ordering::Acquire), 0);
        // No demand at all: nothing is kept ready either.
        let idle = dialer_with_target(local(&listener), 2);
        idle.refill();
        assert_eq!(idle.in_flight.load(Ordering::Acquire), 0);
    }

    fn dialer_with_target(first_hop: SocketAddrV4, target: usize) -> Arc<Dialer> {
        let residential = crate::credential::fixture(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1));
        Arc::new(Dialer::new(first_hop, residential, target))
    }
}
