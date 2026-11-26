//! Finds a newer release of this program on GitHub and downloads its package.
//!
//! Only the desktop uses this, in its own unelevated process; the controller
//! never goes online for it. Requests go through the configured host SOCKS5
//! (the first hop) or direct, never through the residential hop.
//!
//! The package is unsigned. What is checked here is that the bytes are the
//! ones the release lists in the `.sha256` file published beside the ZIP.
//! That catches a broken or cut download; it does not prove who published the
//! release. Trust rests on GitHub's TLS and on the repository account, the
//! same as for a download by hand.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The repository the release pipeline publishes to.
pub const REPOSITORY: &str = "JungleZy/dick-wsl-proxy";
/// Where people read the release notes and download by hand.
pub const RELEASES_PAGE: &str = "https://github.com/JungleZy/dick-wsl-proxy/releases";

const API_HOST: &str = "api.github.com";
/// Releases up to v0.1.11 are pre-releases, which `/releases/latest` never
/// returns, so the newest one is picked from the most recent page of the list.
const RELEASES_PER_PAGE: u32 = 30;
const LIST_LIMIT: u64 = 4 * 1024 * 1024;
const CHECKSUM_LIMIT: u64 = 1024;
const PACKAGE_LIMIT: u64 = 512 * 1024 * 1024;
/// Status line and headers together.
const HEAD_LIMIT: u64 = 64 * 1024;
const LINE_LIMIT: u64 = 8 * 1024;
/// Asset downloads redirect once, from github.com to GitHub's download host.
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// No byte for this long ends the request: a stalled proxy or server.
const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole list request, redirects included.
const LIST_DEADLINE: Duration = Duration::from_secs(60);
const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(60 * 60);
const BUFFER: usize = 64 * 1024;

/// A release version, `major.minor.patch`, as the workspace and the `v*` tags
/// spell it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl Version {
    /// Parses exactly `major.minor.patch`: digits only, no suffix.
    pub fn parse(text: &str) -> Option<Self> {
        let mut numbers = [0u64; 3];
        let mut parts = text.split('.');
        for number in &mut numbers {
            let part = parts.next()?;
            if part.is_empty() || part.len() > 9 || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *number = part.parse().ok()?;
        }
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major: numbers[0],
            minor: numbers[1],
            patch: numbers[2],
        })
    }

    /// The version this program was built as.
    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).expect("the workspace version is major.minor.patch")
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// One downloadable file of a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    pub url: String,
    pub size: u64,
}

/// A published release that carries the Windows package and its checksum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    pub tag: String,
    pub title: String,
    /// As GitHub reports it, e.g. `2026-11-25T17:43:17Z`; empty when absent.
    pub published_at: String,
    pub page: String,
    pub package: Asset,
    pub checksum: Asset,
}

/// How a request reaches GitHub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Direct,
    /// Through a SOCKS5 proxy without authentication: the host proxy that the
    /// takeover also uses as its first hop.
    Socks5(SocketAddrV4),
}

impl fmt::Display for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("direct"),
            Self::Socks5(proxy) => write!(formatter, "host SOCKS5 {proxy}"),
        }
    }
}

/// Why a check or a download did not finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// GitHub could not be reached, or the connection broke.
    Network(String),
    /// GitHub refuses more unauthenticated requests from this address for now.
    RateLimited,
    /// GitHub answered something this program does not accept.
    Response(String),
    /// The downloaded package does not match its published checksum.
    Checksum,
    /// The package could not be written to or read from disk.
    Storage(String),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(detail) => write!(formatter, "update_network: {detail}"),
            Self::RateLimited => formatter.write_str("update_rate_limited"),
            Self::Response(detail) => write!(formatter, "update_bad_response: {detail}"),
            Self::Checksum => formatter.write_str("update_checksum_mismatch"),
            Self::Storage(detail) => write!(formatter, "update_storage: {detail}"),
        }
    }
}

impl std::error::Error for UpdateError {}

/// A package on disk whose SHA-256 matches the release's checksum file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Downloaded {
    pub path: PathBuf,
    /// Lowercase hex.
    pub sha256: String,
}

/// Asks GitHub for the newest release above `current`, trying each route in
/// turn. `Ok(None)` means this is the newest release.
pub fn check(routes: &[Route], current: Version) -> Result<Option<Release>, UpdateError> {
    let url =
        format!("https://{API_HOST}/repos/{REPOSITORY}/releases?per_page={RELEASES_PER_PAGE}");
    attempt(routes, |route| {
        let mut body = Vec::new();
        let request = Request {
            url: &url,
            accept: "application/vnd.github+json",
            limit: LIST_LIMIT,
            deadline: Instant::now() + LIST_DEADLINE,
        };
        fetch(route, &request, &mut |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        })?;
        newest(&body, current)
    })
}

/// Downloads `release`'s package into `directory` and checks it against the
/// release's checksum file. A complete package already there with the right
/// checksum is used again instead of being downloaded twice. `progress` gets
/// the bytes written so far and the package size.
pub fn download(
    release: &Release,
    routes: &[Route],
    directory: &Path,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Downloaded, UpdateError> {
    fs::create_dir_all(directory).map_err(|error| storage(directory, error))?;
    let path = directory.join(&release.package.name);
    let partial = directory.join(format!("{}.part", release.package.name));
    let total = release.package.size;
    attempt(routes, |route| {
        let expected = fetch_checksum(route, release)?;
        if path.is_file() && file_sha256(&path)? == expected {
            progress(total, total);
            return Ok(Downloaded {
                path: path.clone(),
                sha256: expected,
            });
        }
        let mut file = File::create(&partial).map_err(|error| storage(&partial, error))?;
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        let request = Request {
            url: &release.package.url,
            accept: "application/octet-stream",
            limit: total,
            deadline: Instant::now() + DOWNLOAD_DEADLINE,
        };
        let fetched = fetch(route, &request, &mut |chunk| {
            file.write_all(chunk)
                .map_err(|error| storage(&partial, error))?;
            hasher.update(chunk);
            written += chunk.len() as u64;
            progress(written, total);
            Ok(())
        });
        let finished = fetched.and_then(|_| {
            if written != total {
                return Err(UpdateError::Response(format!(
                    "the package has {written} bytes, the release lists {total}"
                )));
            }
            file.sync_all().map_err(|error| storage(&partial, error))?;
            if hex(&hasher.finalize_reset()) != expected {
                return Err(UpdateError::Checksum);
            }
            Ok(())
        });
        drop(file);
        if let Err(error) = finished {
            let _ = fs::remove_file(&partial);
            return Err(error);
        }
        if path.exists() {
            fs::remove_file(&path).map_err(|error| storage(&path, error))?;
        }
        fs::rename(&partial, &path).map_err(|error| storage(&path, error))?;
        Ok(Downloaded {
            path: path.clone(),
            sha256: expected,
        })
    })
}

/// The lowercase hex SHA-256 of a file.
pub fn file_sha256(path: &Path) -> Result<String, UpdateError> {
    let mut file = File::open(path).map_err(|error| storage(path, error))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| storage(path, error))?;
        if read == 0 {
            return Ok(hex(&hasher.finalize()));
        }
        hasher.update(&buffer[..read]);
    }
}

/// Picks the newest release above `current` from GitHub's release list.
/// Drafts, tags other than `vX.Y.Z`, and releases without both Windows files
/// at their expected addresses are skipped, not treated as errors.
pub fn newest(list: &[u8], current: Version) -> Result<Option<Release>, UpdateError> {
    let releases: Vec<ApiRelease> = serde_json::from_slice(list)
        .map_err(|error| UpdateError::Response(format!("release list: {error}")))?;
    Ok(releases
        .into_iter()
        .filter_map(release)
        .filter(|release| release.version > current)
        .max_by_key(|release| release.version))
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    published_at: Option<String>,
    html_url: String,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    size: u64,
    browser_download_url: String,
}

fn release(api: ApiRelease) -> Option<Release> {
    if api.draft {
        return None;
    }
    let version = Version::parse(api.tag_name.strip_prefix('v')?)?;
    let tag = format!("v{version}");
    if api.tag_name != tag
        || api.html_url != format!("https://github.com/{REPOSITORY}/releases/tag/{tag}")
    {
        return None;
    }
    let package_name = format!("wsl-proxy-{version}-windows-x64.zip");
    let checksum_name = format!("{package_name}.sha256");
    let asset = |name: &str, limit: u64| {
        let found = api.assets.iter().find(|asset| asset.name == name)?;
        let url = format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{name}");
        (found.browser_download_url == url && found.size > 0 && found.size <= limit).then(|| {
            Asset {
                name: name.to_owned(),
                url,
                size: found.size,
            }
        })
    };
    let package = asset(&package_name, PACKAGE_LIMIT)?;
    let checksum = asset(&checksum_name, CHECKSUM_LIMIT)?;
    Some(Release {
        version,
        title: api
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| tag.clone()),
        tag,
        published_at: api.published_at.unwrap_or_default(),
        page: api.html_url,
        package,
        checksum,
    })
}

fn fetch_checksum(route: Route, release: &Release) -> Result<String, UpdateError> {
    let mut body = Vec::new();
    let request = Request {
        url: &release.checksum.url,
        accept: "application/octet-stream",
        limit: CHECKSUM_LIMIT,
        deadline: Instant::now() + LIST_DEADLINE,
    };
    fetch(route, &request, &mut |chunk| {
        body.extend_from_slice(chunk);
        Ok(())
    })?;
    let text = std::str::from_utf8(&body)
        .map_err(|_| UpdateError::Response("the checksum file is not text".into()))?;
    parse_checksum(text, &release.package.name)
        .ok_or_else(|| UpdateError::Response("the checksum file is malformed".into()))
}

/// Reads `<64 hex digits>  <file name>` (the name is optional, `*` marks
/// binary mode). Returns the digest in lowercase.
fn parse_checksum(text: &str, package: &str) -> Option<String> {
    let line = text.trim_start_matches('\u{feff}').lines().next()?;
    let mut fields = line.split_whitespace();
    let digest = fields.next()?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    match fields.next() {
        Some(name) if name.trim_start_matches('*') != package => return None,
        _ => {}
    }
    fields.next().is_none().then(|| digest.to_ascii_lowercase())
}

/// Runs `step` on each route until one succeeds. When all fail, a definite
/// answer from GitHub (rate limit, bad response, checksum, disk) wins over
/// network failures, which are reported together.
fn attempt<T>(
    routes: &[Route],
    mut step: impl FnMut(Route) -> Result<T, UpdateError>,
) -> Result<T, UpdateError> {
    let mut network = Vec::new();
    let mut definite = None;
    for &route in routes {
        match step(route) {
            Ok(value) => return Ok(value),
            Err(UpdateError::Network(detail)) => network.push(format!("{route}: {detail}")),
            Err(error) => definite = Some(error),
        }
    }
    Err(definite.unwrap_or_else(|| {
        if network.is_empty() {
            UpdateError::Network("no route to try".into())
        } else {
            UpdateError::Network(network.join("; "))
        }
    }))
}

struct Request<'a> {
    url: &'a str,
    accept: &'a str,
    limit: u64,
    deadline: Instant,
}

type Sink<'a> = dyn FnMut(&[u8]) -> Result<(), UpdateError> + 'a;

/// One GET, following redirects to GitHub's own hosts. The body goes to
/// `sink`; returns its length.
fn fetch(route: Route, request: &Request<'_>, sink: &mut Sink<'_>) -> Result<u64, UpdateError> {
    let mut url = request.url.to_owned();
    for _ in 0..=MAX_REDIRECTS {
        let target = Target::parse(&url)?;
        let stream = open(route, &target.host, request.deadline)?;
        let mut tls = tls_connect(&target.host, stream)?;
        let api = if target.host == API_HOST {
            "X-GitHub-Api-Version: 2022-11-28\r\n"
        } else {
            ""
        };
        write!(
            tls,
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: wsl-proxy-desktop/{}\r\nAccept: {}\r\n{api}Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
            target.path,
            target.host,
            env!("CARGO_PKG_VERSION"),
            request.accept,
        )
        .and_then(|()| tls.flush())
        .map_err(|error| network(&target.host, "send", error))?;
        let mut reader = BufReader::with_capacity(BUFFER, tls);
        let head = read_head(&mut reader)?;
        match head.status {
            200 => return read_body(&mut reader, &head, request.limit, request.deadline, sink),
            301 | 302 | 303 | 307 | 308 => {
                let location = head
                    .header("location")
                    .ok_or_else(|| UpdateError::Response("a redirect without a location".into()))?;
                url = target.resolve(location);
            }
            429 => return Err(UpdateError::RateLimited),
            403 if head.header("x-ratelimit-remaining") == Some("0") => {
                return Err(UpdateError::RateLimited);
            }
            status => {
                return Err(UpdateError::Response(format!(
                    "HTTP {status} from {}",
                    target.host
                )));
            }
        }
    }
    Err(UpdateError::Response("too many redirects".into()))
}

/// An `https://` address on one of GitHub's hosts.
#[derive(Debug, PartialEq, Eq)]
struct Target {
    host: String,
    /// Path and query, starting with `/`.
    path: String,
}

impl Target {
    fn parse(url: &str) -> Result<Self, UpdateError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| UpdateError::Response(format!("not an https address: {url}")))?;
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let host = rest[..split].to_ascii_lowercase();
        let path = match &rest[split..] {
            "" => "/".to_owned(),
            query if query.starts_with('?') => format!("/{query}"),
            path => path.to_owned(),
        };
        if !allowed_host(&host) {
            return Err(UpdateError::Response(format!(
                "refused to follow an address outside GitHub: {host}"
            )));
        }
        if path.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(UpdateError::Response(
                "an address with spaces or control characters".into(),
            ));
        }
        Ok(Self { host, path })
    }

    /// The address a `Location` header points to, relative to this one.
    fn resolve(&self, location: &str) -> String {
        if location.starts_with("https://") || location.starts_with("http://") {
            location.to_owned()
        } else if location.starts_with('/') {
            format!("https://{}{location}", self.host)
        } else {
            let base = self.path.rsplit_once('/').map_or("", |(base, _)| base);
            format!("https://{}{base}/{location}", self.host)
        }
    }
}

/// GitHub's API and site, and the hosts its release downloads redirect to.
fn allowed_host(host: &str) -> bool {
    let valid = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    valid
        && (host == "github.com"
            || host == API_HOST
            || (host.ends_with(".githubusercontent.com") && !host.starts_with('.')))
}

fn open(route: Route, host: &str, deadline: Instant) -> Result<TcpStream, UpdateError> {
    let stream = match route {
        Route::Direct => {
            let addresses = (host, 443)
                .to_socket_addrs()
                .map_err(|error| network(host, "resolve", error))?;
            let mut last = None;
            let mut connected = None;
            for address in addresses {
                match TcpStream::connect_timeout(&address, connect_budget(deadline)?) {
                    Ok(stream) => {
                        connected = Some(stream);
                        break;
                    }
                    Err(error) => last = Some(error),
                }
            }
            let stream = connected.ok_or_else(|| match last {
                Some(error) => network(host, "connect", error),
                None => UpdateError::Network(format!("{host}: no address")),
            })?;
            stalls(&stream, host)?;
            stream
        }
        Route::Socks5(proxy) => {
            let mut stream =
                TcpStream::connect_timeout(&SocketAddr::V4(proxy), connect_budget(deadline)?)
                    .map_err(|error| UpdateError::Network(format!("connect {proxy}: {error}")))?;
            stalls(&stream, host)?;
            socks5_connect(&mut stream, host, 443)?;
            stream
        }
    };
    Ok(stream)
}

/// The routes to try, in order: the host SOCKS5 when one is configured, since
/// that is how this machine usually reaches GitHub, then direct.
pub fn routes(first_hop: Option<SocketAddrV4>) -> Vec<Route> {
    first_hop
        .map(Route::Socks5)
        .into_iter()
        .chain([Route::Direct])
        .collect()
}

fn connect_budget(deadline: Instant) -> Result<Duration, UpdateError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .map(|left| left.min(CONNECT_TIMEOUT))
        .ok_or_else(|| UpdateError::Network("timed out".into()))
}

fn stalls(stream: &TcpStream, host: &str) -> Result<(), UpdateError> {
    stream
        .set_read_timeout(Some(STALL_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(STALL_TIMEOUT)))
        .map_err(|error| network(host, "socket", error))
}

/// SOCKS5 without authentication, CONNECT by name (address type 3), so the
/// proxy resolves GitHub itself.
fn socks5_connect<S: Read + Write>(
    stream: &mut S,
    host: &str,
    port: u16,
) -> Result<(), UpdateError> {
    let refused = |what: &str| UpdateError::Network(format!("host SOCKS5 {what}"));
    let io = |error: io::Error| UpdateError::Network(format!("host SOCKS5: {error}"));
    let name = host.as_bytes();
    let length = u8::try_from(name.len()).map_err(|_| refused("cannot take a name this long"))?;
    stream.write_all(&[5, 1, 0]).map_err(io)?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).map_err(io)?;
    if method != [5, 0] {
        return Err(refused("refused access without a password"));
    }
    let mut connect = vec![5, 1, 0, 3, length];
    connect.extend_from_slice(name);
    connect.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&connect).map_err(io)?;
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).map_err(io)?;
    if reply[0] != 5 || reply[1] != 0 {
        return Err(refused(&format!(
            "could not reach {host} (reply {})",
            reply[1]
        )));
    }
    let bound = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).map_err(io)?;
            usize::from(length[0])
        }
        _ => return Err(refused("answered with an unknown address type")),
    };
    let mut rest = vec![0u8; bound + 2];
    stream.read_exact(&mut rest).map_err(io)?;
    Ok(())
}

fn tls_connect(
    host: &str,
    stream: TcpStream,
) -> Result<native_tls::TlsStream<TcpStream>, UpdateError> {
    let mut builder = native_tls::TlsConnector::builder();
    builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
    let connector = builder
        .build()
        .map_err(|error| UpdateError::Network(format!("tls: {error}")))?;
    connector
        .connect(host, stream)
        .map_err(|error| UpdateError::Network(format!("{host}: tls: {error}")))
}

/// Status and headers; header names in lowercase.
#[derive(Debug)]
struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

fn read_head<R: BufRead>(reader: &mut R) -> Result<Head, UpdateError> {
    let mut budget = HEAD_LIMIT;
    let mut next_line = |reader: &mut R| -> Result<String, UpdateError> {
        let line = read_line(reader, budget.min(LINE_LIMIT))?;
        budget = budget.saturating_sub(line.len() as u64 + 2);
        if budget == 0 {
            return Err(UpdateError::Response("response headers too large".into()));
        }
        Ok(line)
    };
    loop {
        let status_line = next_line(reader)?;
        let mut fields = status_line.split_whitespace();
        let status = match (fields.next(), fields.next()) {
            (Some(version), Some(code)) if version.starts_with("HTTP/1.") => {
                code.parse::<u16>().ok()
            }
            _ => None,
        }
        .ok_or_else(|| UpdateError::Response("not an HTTP/1.x response".into()))?;
        let mut headers = Vec::new();
        loop {
            let line = next_line(reader)?;
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| UpdateError::Response("malformed response header".into()))?;
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
        // An interim answer (100 Continue) is followed by the real one.
        if !(100..200).contains(&status) {
            return Ok(Head { status, headers });
        }
    }
}

/// One line without its line break. A connection closed mid-line is an error.
fn read_line<R: BufRead>(reader: &mut R, limit: u64) -> Result<String, UpdateError> {
    let mut line = Vec::new();
    reader
        .take(limit)
        .read_until(b'\n', &mut line)
        .map_err(|error| UpdateError::Network(format!("read: {error}")))?;
    if line.last() != Some(&b'\n') {
        return Err(if line.len() as u64 >= limit {
            UpdateError::Response("response line too long".into())
        } else {
            UpdateError::Network("the connection closed early".into())
        });
    }
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).map_err(|_| UpdateError::Response("non-UTF-8 response header".into()))
}

fn read_body<R: BufRead>(
    reader: &mut R,
    head: &Head,
    limit: u64,
    deadline: Instant,
    sink: &mut Sink<'_>,
) -> Result<u64, UpdateError> {
    let chunked = head
        .header("transfer-encoding")
        .and_then(|value| value.rsplit(',').next())
        .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"));
    let mut copied = 0u64;
    if chunked {
        loop {
            let line = read_line(reader, LINE_LIMIT)?;
            let size = line.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size, 16)
                .map_err(|_| UpdateError::Response("malformed chunk size".into()))?;
            if size == 0 {
                // Trailers, if any, end with an empty line.
                while !read_line(reader, LINE_LIMIT)?.is_empty() {}
                return Ok(copied);
            }
            copy(reader, Some(size), limit, deadline, &mut copied, sink)?;
            if !read_line(reader, LINE_LIMIT)?.is_empty() {
                return Err(UpdateError::Response("malformed chunk end".into()));
            }
        }
    }
    let length = match head.header("content-length") {
        Some(value) => Some(
            value
                .parse::<u64>()
                .map_err(|_| UpdateError::Response("malformed content length".into()))?,
        ),
        None => None,
    };
    if length.is_some_and(|length| length > limit) {
        return Err(UpdateError::Response(format!(
            "the response is larger than {limit} bytes"
        )));
    }
    copy(reader, length, limit, deadline, &mut copied, sink)?;
    Ok(copied)
}

/// Copies `length` bytes, or everything up to the end of the stream when the
/// length is unknown, keeping the running total within `limit`.
fn copy<R: Read>(
    reader: &mut R,
    length: Option<u64>,
    limit: u64,
    deadline: Instant,
    copied: &mut u64,
    sink: &mut Sink<'_>,
) -> Result<(), UpdateError> {
    let mut buffer = vec![0u8; BUFFER];
    let mut left = length;
    while left != Some(0) {
        if Instant::now() >= deadline {
            return Err(UpdateError::Network("timed out".into()));
        }
        let want = left.map_or(BUFFER, |left| left.min(BUFFER as u64) as usize);
        let read = match reader.read(&mut buffer[..want]) {
            Ok(0) if left.is_none() => return Ok(()),
            Ok(0) => return Err(UpdateError::Network("the connection closed early".into())),
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(UpdateError::Network(format!("read: {error}"))),
        };
        *copied += read as u64;
        if *copied > limit {
            return Err(UpdateError::Response(format!(
                "the response is larger than {limit} bytes"
            )));
        }
        sink(&buffer[..read])?;
        left = left.map(|left| left - read as u64);
    }
    Ok(())
}

fn network(host: &str, step: &str, error: io::Error) -> UpdateError {
    UpdateError::Network(format!("{host}: {step}: {error}"))
}

fn storage(path: &Path, error: io::Error) -> UpdateError {
    UpdateError::Storage(format!("{}: {error}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
