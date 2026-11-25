//! Before a managed takeover installs any rule, the target's timezone is set to
//! where the residential exit is, and only that distribution is restarted, so
//! every process in it starts again with that timezone. A failed step refuses
//! the takeover; the timezone is never restored when the takeover stops.

use crate::host::{self, Distro};
use crate::managed::Runtime;
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

/// Answers with the caller's public IP facts, including an IANA timezone.
const LOOKUP_HOST: &str = "my.ippure.com";
const LOOKUP_PATH: &str = "/v1/info";
/// From the TLS handshake to the last byte of the answer.
const LOOKUP_DEADLINE: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 64 * 1024;
const APPLY_DEADLINE: Duration = Duration::from_secs(30);
const TERMINATE_DEADLINE: Duration = Duration::from_secs(30);
/// The whole wait for the restarted target, including systemd's own limit.
const BOOT_DEADLINE: Duration = Duration::from_secs(75);

/// Looks the residential exit's timezone up through the two hops, writes it
/// into the target together with `[time] useWindowsTimezone=false` (otherwise
/// WSL puts the Windows timezone back at the next start), then restarts only
/// the target and waits for its boot to settle. Returns the timezone set.
pub(crate) fn sync_and_restart(runtime: &Runtime, target: &Distro) -> Result<String, String> {
    let timezone = exit_timezone(runtime)?;
    host::guest_script_with_timeout(target, &apply_script(&timezone)?, APPLY_DEADLINE)
        .map_err(|error| format!("timezone_apply_failed: {}", host::failure_tail(&error)))
        .and_then(|output| match output.trim() {
            "ok" => Ok(()),
            _ => Err("timezone_apply_failed: unexpected guest output".to_string()),
        })?;
    host::wsl_command(
        &["--terminate".into(), target.name.clone()],
        None,
        TERMINATE_DEADLINE,
    )
    .map_err(|error| format!("target_restart_failed: {}", host::failure_tail(&error)))?;
    // Starting it again here, not in the next probe, keeps a slow boot out of
    // the takeover's own short guest deadlines.
    host::guest_script_with_timeout(target, BOOT_WAIT, BOOT_DEADLINE)
        .map_err(|error| format!("target_restart_failed: {}", host::failure_tail(&error)))?;
    Ok(timezone)
}

/// Waits for systemd to finish booting, if the target runs it. A degraded or
/// slow boot is not an error here; the takeover's preflight judges the guest.
const BOOT_WAIT: &str = "if command -v systemctl >/dev/null 2>&1; then
    timeout 60 systemctl is-system-running --wait >/dev/null 2>&1 || true
fi
echo ok
";

fn exit_timezone(runtime: &Runtime) -> Result<String, String> {
    // Asked directly, the service would report the Windows address instead.
    if runtime.policy.allows_domain(LOOKUP_HOST) {
        return Err("timezone_lookup_domain_is_direct".into());
    }
    let address = runtime
        .dns
        .resolve_ipv4(LOOKUP_HOST)
        .map_err(|error| format!("timezone_lookup_failed: resolve: {error}"))?
        .into_iter()
        .map(|ip| SocketAddrV4::new(ip, 443))
        .find(|endpoint| {
            !runtime.policy.allows_ip(*endpoint.ip())
                && !runtime.policy.is_reserved_endpoint(*endpoint)
        })
        .ok_or("timezone_lookup_failed: no chainable address")?;
    let stream = runtime
        .policy
        .chain(address)
        .map_err(|error| format!("timezone_lookup_failed: chain: {error}"))?;
    let deadline = Instant::now() + LOOKUP_DEADLINE;
    stream
        .set_read_timeout(Some(LOOKUP_DEADLINE))
        .and_then(|()| stream.set_write_timeout(Some(LOOKUP_DEADLINE)))
        .map_err(|error| format!("timezone_lookup_failed: socket: {error}"))?;
    let mut builder = native_tls::TlsConnector::builder();
    builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
    let connector = builder
        .build()
        .map_err(|error| format!("timezone_lookup_failed: tls: {error}"))?;
    let mut tls = connector
        .connect(LOOKUP_HOST, stream)
        .map_err(|error| format!("timezone_lookup_failed: tls: {error}"))?;
    // The same request the guest exit probe sends: no client name goes out.
    write!(
        tls,
        "GET {LOOKUP_PATH} HTTP/1.1\r\nHost: {LOOKUP_HOST}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
    )
    .and_then(|()| tls.flush())
    .map_err(|error| format!("timezone_lookup_failed: send: {error}"))?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or("timezone_lookup_failed: timed out")?;
        tls.get_ref()
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("timezone_lookup_failed: socket: {error}"))?;
        match tls.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&buffer[..read]);
                if response.len() > MAX_RESPONSE {
                    return Err("timezone_lookup_failed: response too large".into());
                }
            }
            // Some servers close without a TLS close_notify; a body that is
            // already complete is still usable, anything less is not.
            Err(_) if complete(&response) => break,
            Err(error) => return Err(format!("timezone_lookup_failed: read: {error}")),
        }
    }
    parse_info(&response)
}

/// Whether `response` already holds a whole body by its Content-Length.
fn complete(response: &[u8]) -> bool {
    split_response(response)
        .ok()
        .and_then(|(headers, body)| content_length(&headers).map(|length| body.len() >= length))
        .unwrap_or(false)
}

fn split_response(response: &[u8]) -> Result<(String, &[u8]), String> {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("timezone_lookup_failed: incomplete response")?;
    let headers = std::str::from_utf8(&response[..end])
        .map_err(|_| "timezone_lookup_failed: non-ASCII headers")?
        .to_ascii_lowercase();
    Ok((headers, &response[end + 4..]))
}

fn content_length(headers: &str) -> Option<usize> {
    headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
}

/// The timezone in a complete `/v1/info` response, validated as a zoneinfo
/// name before it is allowed anywhere near a guest script.
fn parse_info(response: &[u8]) -> Result<String, String> {
    let (headers, body) = split_response(response)?;
    let status = headers.lines().next().unwrap_or_default();
    if !status.starts_with("http/1.1 200 ") && !status.starts_with("http/1.0 200 ") {
        return Err(format!(
            "timezone_lookup_failed: status {}",
            status.chars().take(32).collect::<String>()
        ));
    }
    let body = if headers
        .lines()
        .any(|line| line.starts_with("transfer-encoding:") && line.contains("chunked"))
    {
        dechunk(body)?
    } else {
        match content_length(&headers) {
            Some(length) if body.len() >= length => body[..length].to_vec(),
            Some(_) => return Err("timezone_lookup_failed: truncated body".into()),
            None => body.to_vec(),
        }
    };
    #[derive(Deserialize)]
    struct Info {
        timezone: String,
    }
    let info: Info = serde_json::from_slice(&body)
        .map_err(|_| "timezone_lookup_failed: no timezone in response")?;
    if !super::valid_timezone(&info.timezone) {
        return Err("timezone_lookup_failed: invalid timezone name".into());
    }
    Ok(info.timezone)
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let malformed = || "timezone_lookup_failed: malformed chunked body".to_string();
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(malformed)?;
        let size = std::str::from_utf8(&body[..line_end]).map_err(|_| malformed())?;
        let size = size.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| malformed())?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(malformed());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Root script that points `/etc/localtime` and `/etc/timezone` at `timezone`
/// and turns WSL's Windows-timezone sync off. Installs nothing: a timezone
/// missing from the target's zoneinfo fails the step.
fn apply_script(timezone: &str) -> Result<String, String> {
    // Only ASCII letters, digits and `/_+-.` pass: safe inside single quotes.
    if !super::valid_timezone(timezone) {
        return Err("timezone_lookup_failed: invalid timezone name".into());
    }
    let wsl_conf_set = super::WSL_CONF_SET;
    Ok(format!(
        r#"set -eu
timezone='{timezone}'
zone="/usr/share/zoneinfo/$timezone"
if [ ! -f "$zone" ]; then
    echo 'timezone_not_in_target' >&2
    exit 21
fi
{wsl_conf_set}
ln -sf "$zone" /etc/localtime
printf '%s\n' "$timezone" > /etc/timezone
wsl_conf_set time useWindowsTimezone false
echo ok
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(headers: &str, body: &str) -> Vec<u8> {
        format!("{headers}\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn reads_the_timezone_from_a_plain_or_chunked_answer() {
        let body = r#"{"ip":"192.0.2.8","timezone":"America/Chicago","city":"Kansas City"}"#;
        let plain = response(
            &format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}",
                body.len()
            ),
            body,
        );
        assert_eq!(parse_info(&plain), Ok("America/Chicago".into()));
        assert!(complete(&plain));
        let chunked = response(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
            &format!(
                "10\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                &body[..16],
                body.len() - 16,
                &body[16..]
            ),
        );
        assert_eq!(parse_info(&chunked), Ok("America/Chicago".into()));
        let unframed = response("HTTP/1.0 200 OK", body);
        assert_eq!(parse_info(&unframed), Ok("America/Chicago".into()));
        assert!(!complete(&unframed));
    }

    #[test]
    fn refuses_failures_and_names_that_are_not_zoneinfo_names() {
        let ok_headers = "HTTP/1.1 200 OK";
        for body in [
            r#"{"timezone":"../../etc/passwd"}"#,
            r#"{"timezone":"/etc/localtime"}"#,
            r#"{"timezone":"Asia/Shang'hai"}"#,
            r#"{"timezone":"America/Chicago; reboot"}"#,
            r#"{"timezone":""}"#,
            r#"{"ip":"192.0.2.8"}"#,
            "not json",
        ] {
            assert!(parse_info(&response(ok_headers, body)).is_err(), "{body}");
        }
        let good = r#"{"timezone":"America/Chicago"}"#;
        assert!(parse_info(&response("HTTP/1.1 503 Service Unavailable", good)).is_err());
        assert!(parse_info(&response("HTTP/1.1 200 OK\r\nContent-Length: 999", good)).is_err());
        assert!(parse_info(good.as_bytes()).is_err());
    }

    #[test]
    fn the_guest_script_sets_the_zone_and_stops_windows_timezone_sync() {
        let script = apply_script("America/Chicago").unwrap();
        assert!(script.contains("timezone='America/Chicago'\n"));
        assert!(script.contains("ln -sf \"$zone\" /etc/localtime"));
        assert!(script.contains("wsl_conf_set time useWindowsTimezone false"));
        assert!(script.contains("exit 21"));
        assert!(apply_script("Asia/Shang'hai").is_err());
        assert!(apply_script("../etc").is_err());
    }
}
