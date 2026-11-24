//! Tells whether the saved residential SOCKS5 answers straight from Windows,
//! through the first hop, or neither. Takeover traffic always uses the chain;
//! this probe only reports what each path can do.

use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::{AuthPacket, Policy, connect, expect, remaining, send};

/// Each path gets its own deadline, handshakes included. Both run at once, so
/// the request holds the controller for at most this long.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// Where a path stopped. Codes only: never an address, username or password.
type Outcome = Result<(), &'static str>;

impl Policy {
    /// Authenticates to the residential SOCKS5 and asks it to CONNECT to the
    /// DNS upstream, once straight from Windows and once inside the first hop.
    /// The direct path sends the credentials without the first hop, so the
    /// desktop asks the user before requesting this.
    pub(crate) fn probe_residential(&self) -> Value {
        let (direct, chained) = thread::scope(|scope| {
            let direct = scope.spawn(|| self.probe_direct());
            let chained = scope.spawn(|| self.probe_chained());
            (
                direct.join().unwrap_or(Err("probe_failed")),
                chained.join().unwrap_or(Err("probe_failed")),
            )
        });
        json!({
            "verdict": verdict(direct, chained),
            "direct": path_view(direct),
            "chained": path_view(chained),
        })
    }

    fn probe_direct(&self) -> Outcome {
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let mut stream =
            open(self.residential.endpoint(), deadline).ok_or("residential_unreachable")?;
        self.residential_handshake(&mut stream, deadline)
    }

    fn probe_chained(&self) -> Outcome {
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let mut stream = open(self.first_hop, deadline).ok_or("first_hop_unreachable")?;
        send(&mut stream, &[5, 1, 0], deadline)
            .and_then(|()| expect(&mut stream, &[5, 0], deadline, "rejected"))
            .map_err(|_| "first_hop_rejected")?;
        connect(&mut stream, self.residential.endpoint(), deadline)
            .map_err(|_| "first_hop_connect_rejected")?;
        self.residential_handshake(&mut stream, deadline)
    }

    /// Method selection, username/password authentication, then CONNECT to a
    /// literal address so the residential side needs no name resolution.
    fn residential_handshake(&self, stream: &mut TcpStream, deadline: Instant) -> Outcome {
        send(stream, &[5, 1, 2], deadline)
            .and_then(|()| expect(stream, &[5, 2], deadline, "rejected"))
            .map_err(|_| "residential_method_rejected")?;
        {
            let mut packet = AuthPacket([0; 513]);
            let len = self.residential.auth_packet(&mut packet.0);
            send(stream, &packet.0[..len], deadline).map_err(|_| "residential_auth_rejected")?;
        }
        expect(stream, &[1, 0], deadline, "rejected").map_err(|_| "residential_auth_rejected")?;
        connect(stream, self.dns_upstream, deadline).map_err(|_| "residential_connect_rejected")
    }
}

fn open(endpoint: SocketAddrV4, deadline: Instant) -> Option<TcpStream> {
    let stream =
        TcpStream::connect_timeout(&SocketAddr::V4(endpoint), remaining(deadline).ok()?).ok()?;
    stream.set_nodelay(true).ok()?;
    Some(stream)
}

fn path_view(outcome: Outcome) -> Value {
    match outcome {
        Ok(()) => json!({"ok": true}),
        Err(stage) => json!({"ok": false, "stage": stage}),
    }
}

/// `both`, `direct_only` and `needs_first_hop` say which paths worked. With
/// neither working, a rejected login on either path is reported as such,
/// since providers also refuse logins from source IPs they do not allow.
fn verdict(direct: Outcome, chained: Outcome) -> &'static str {
    match (direct, chained) {
        (Ok(()), Ok(())) => "both",
        (Ok(()), Err(_)) => "direct_only",
        (Err(_), Ok(())) => "needs_first_hop",
        (Err(a), Err(b))
            if a == "residential_auth_rejected" || b == "residential_auth_rejected" =>
        {
            "credential_rejected"
        }
        _ => "unreachable",
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};

    use super::*;
    use crate::credential;
    use crate::policy::{Config, Validated};

    fn endpoint(listener: &TcpListener) -> SocketAddrV4 {
        match listener.local_addr().unwrap() {
            SocketAddr::V4(address) => address,
            _ => unreachable!(),
        }
    }

    /// A port nothing listens on: bound once, then released.
    fn closed_port() -> SocketAddrV4 {
        endpoint(&TcpListener::bind("127.0.0.1:0").unwrap())
    }

    fn policy(first_hop: SocketAddrV4, residential: SocketAddrV4) -> Policy {
        let config: Config = serde_json::from_value(json!({
            "first_hop": first_hop.to_string(),
            "credential": "fixture",
            "dns_upstream": "8.8.8.8:443",
            "dns_tls_name": "dns.google",
            "direct_ips": [],
            "direct_domains": [],
            "direct_suffixes": [],
            "allow_loopback_residential": true
        }))
        .unwrap();
        Policy::assemble(
            Validated::new(config).unwrap(),
            credential::fixture(residential),
        )
        .unwrap()
    }

    fn timed(stream: TcpStream) -> TcpStream {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
    }

    fn read_exact<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
        let mut bytes = [0; N];
        stream.read_exact(&mut bytes).unwrap();
        bytes
    }

    /// Serves one residential session and returns the username it received.
    fn residential_session(stream: TcpStream, accept_login: bool) -> String {
        let mut stream = timed(stream);
        assert_eq!(read_exact::<3>(&mut stream), [5, 1, 2]);
        stream.write_all(&[5, 2]).unwrap();
        let [version, user_len] = read_exact::<2>(&mut stream);
        assert_eq!(version, 1);
        let mut user = vec![0; usize::from(user_len)];
        stream.read_exact(&mut user).unwrap();
        let [pass_len] = read_exact::<1>(&mut stream);
        let mut pass = vec![0; usize::from(pass_len)];
        stream.read_exact(&mut pass).unwrap();
        if !accept_login {
            stream.write_all(&[1, 1]).unwrap();
            return String::from_utf8(user).unwrap();
        }
        stream.write_all(&[1, 0]).unwrap();
        let request = read_exact::<10>(&mut stream);
        assert_eq!(&request[..4], &[5, 1, 0, 1]);
        assert_eq!(&request[4..8], &[8, 8, 8, 8]);
        assert_eq!(&request[8..], &443u16.to_be_bytes());
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
        String::from_utf8(user).unwrap()
    }

    /// A no-auth first hop that tunnels one CONNECT to `upstream`, whatever
    /// address the request names, and checks it named `requested`.
    fn first_hop_session(
        stream: TcpStream,
        requested: SocketAddrV4,
        upstream: SocketAddrV4,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut client = timed(stream);
            assert_eq!(read_exact::<3>(&mut client), [5, 1, 0]);
            client.write_all(&[5, 0]).unwrap();
            let request = read_exact::<10>(&mut client);
            assert_eq!(&request[4..8], &requested.ip().octets());
            assert_eq!(&request[8..], &requested.port().to_be_bytes());
            let server = TcpStream::connect(upstream).unwrap();
            client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();
            let (mut client_read, mut server_write) =
                (client.try_clone().unwrap(), server.try_clone().unwrap());
            let forward = thread::spawn(move || {
                let _ = std::io::copy(&mut client_read, &mut server_write);
                let _ = server_write.shutdown(Shutdown::Write);
            });
            let (mut server_read, mut client_write) = (server, client);
            let _ = std::io::copy(&mut server_read, &mut client_write);
            let _ = client_write.shutdown(Shutdown::Write);
            forward.join().unwrap();
        })
    }

    #[test]
    fn a_residential_reachable_both_ways_authenticates_on_each_path() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let residential = TcpListener::bind("127.0.0.1:0").unwrap();
        let residential_endpoint = endpoint(&residential);
        let policy = policy(endpoint(&first), residential_endpoint);
        let hop = thread::spawn(move || {
            let (stream, _) = first.accept().unwrap();
            first_hop_session(stream, residential_endpoint, residential_endpoint)
                .join()
                .unwrap();
        });
        let server = thread::spawn(move || {
            (0..2)
                .map(|_| residential_session(residential.accept().unwrap().0, true))
                .collect::<Vec<_>>()
        });
        let report = policy.probe_residential();
        hop.join().unwrap();
        // The direct path sends the login too: the user agreed to that before probing.
        assert_eq!(server.join().unwrap(), ["fixture-user", "fixture-user"]);
        assert_eq!(report["verdict"], "both");
        assert_eq!(report["direct"], json!({"ok": true}));
        assert_eq!(report["chained"], json!({"ok": true}));
    }

    #[test]
    fn a_residential_hidden_behind_the_first_hop_needs_it() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let hidden = TcpListener::bind("127.0.0.1:0").unwrap();
        let hidden_endpoint = endpoint(&hidden);
        let advertised = closed_port();
        let policy = policy(endpoint(&first), advertised);
        let hop = thread::spawn(move || {
            let (stream, _) = first.accept().unwrap();
            first_hop_session(stream, advertised, hidden_endpoint)
                .join()
                .unwrap();
        });
        let server = thread::spawn(move || residential_session(hidden.accept().unwrap().0, true));
        let report = policy.probe_residential();
        hop.join().unwrap();
        server.join().unwrap();
        assert_eq!(report["verdict"], "needs_first_hop");
        assert_eq!(
            report["direct"],
            json!({"ok": false, "stage": "residential_unreachable"})
        );
        assert_eq!(report["chained"], json!({"ok": true}));
    }

    #[test]
    fn a_missing_first_hop_leaves_only_the_direct_path() {
        let residential = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy(closed_port(), endpoint(&residential));
        let server =
            thread::spawn(move || residential_session(residential.accept().unwrap().0, true));
        let report = policy.probe_residential();
        server.join().unwrap();
        assert_eq!(report["verdict"], "direct_only");
        assert_eq!(
            report["chained"],
            json!({"ok": false, "stage": "first_hop_unreachable"})
        );
    }

    #[test]
    fn a_refused_login_is_reported_as_a_credential_problem() {
        let residential = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy(closed_port(), endpoint(&residential));
        let server =
            thread::spawn(move || residential_session(residential.accept().unwrap().0, false));
        let report = policy.probe_residential();
        server.join().unwrap();
        assert_eq!(report["verdict"], "credential_rejected");
        assert_eq!(
            report["direct"],
            json!({"ok": false, "stage": "residential_auth_rejected"})
        );
    }

    #[test]
    fn nothing_listening_is_unreachable_with_both_stages_named() {
        let report = policy(closed_port(), closed_port()).probe_residential();
        assert_eq!(report["verdict"], "unreachable");
        assert_eq!(report["direct"]["stage"], "residential_unreachable");
        assert_eq!(report["chained"]["stage"], "first_hop_unreachable");
    }

    #[test]
    fn a_first_hop_that_refuses_the_tunnel_stops_before_any_login() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let policy = policy(endpoint(&first), closed_port());
        let hop = thread::spawn(move || {
            let mut client = timed(first.accept().unwrap().0);
            assert_eq!(read_exact::<3>(&mut client), [5, 1, 0]);
            client.write_all(&[5, 0]).unwrap();
            read_exact::<10>(&mut client);
            client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            // Nothing else may arrive: no residential login after a refused tunnel.
            // The probe closes with part of the reply unread, which Windows turns
            // into a reset; bytes read before it still land in `rest`.
            let mut rest = Vec::new();
            let _ = client.read_to_end(&mut rest);
            rest
        });
        let report = policy.probe_residential();
        assert!(hop.join().unwrap().is_empty());
        assert_eq!(
            report["chained"],
            json!({"ok": false, "stage": "first_hop_connect_rejected"})
        );
    }
}
