// Release selection, HTTP framing, SOCKS5 and checksum tests. The network
// itself is exercised only by the ignored live test at the end.
use super::*;
use serde_json::json;
use std::io::Cursor;

fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn asset(tag: &str, name: &str, size: u64) -> serde_json::Value {
    json!({
        "name": name,
        "size": size,
        "browser_download_url": format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"),
    })
}

fn listed(number: &str, prerelease: bool) -> serde_json::Value {
    let tag = format!("v{number}");
    let zip = format!("wsl-proxy-{number}-windows-x64.zip");
    json!({
        "tag_name": tag,
        "name": format!("WSL Proxy {number}"),
        "draft": false,
        "prerelease": prerelease,
        "published_at": "2026-11-25T17:43:17Z",
        "html_url": format!("https://github.com/{REPOSITORY}/releases/tag/{tag}"),
        "assets": [asset(&tag, &zip, 43_189_826), asset(&tag, &format!("{zip}.sha256"), 99)],
    })
}

fn pick(list: serde_json::Value, current: &str) -> Option<Release> {
    newest(&serde_json::to_vec(&list).unwrap(), version(current)).unwrap()
}

#[test]
fn versions_parse_only_major_minor_patch_and_compare_numerically() {
    assert_eq!(version("0.1.11").to_string(), "0.1.11");
    assert!(version("0.1.11") > version("0.1.9"));
    assert!(version("1.0.0") > version("0.99.99"));
    for bad in [
        "",
        "0.1",
        "0.1.11.1",
        "v0.1.11",
        "0.1.11-rc1",
        "0..1",
        "0.1.x",
        " 0.1.1",
        "0.1.1234567890",
    ] {
        assert_eq!(Version::parse(bad), None, "{bad:?}");
    }
    assert_eq!(Version::current().to_string(), env!("CARGO_PKG_VERSION"));
}

#[test]
fn picks_the_newest_newer_release_including_pre_releases() {
    let list = json!([
        listed("0.1.11", true),
        listed("0.1.13", true),
        listed("0.1.12", false)
    ]);
    let release = pick(list, "0.1.11").unwrap();
    assert_eq!(release.version, version("0.1.13"));
    assert_eq!(release.tag, "v0.1.13");
    assert_eq!(release.title, "WSL Proxy 0.1.13");
    assert_eq!(release.published_at, "2026-11-25T17:43:17Z");
    assert_eq!(
        release.page,
        format!("https://github.com/{REPOSITORY}/releases/tag/v0.1.13")
    );
    assert_eq!(release.package.name, "wsl-proxy-0.1.13-windows-x64.zip");
    assert_eq!(release.package.size, 43_189_826);
    assert_eq!(
        release.checksum.name,
        "wsl-proxy-0.1.13-windows-x64.zip.sha256"
    );
    assert_eq!(
        release.checksum.url,
        format!(
            "https://github.com/{REPOSITORY}/releases/download/v0.1.13/wsl-proxy-0.1.13-windows-x64.zip.sha256"
        )
    );
}

#[test]
fn the_same_or_an_older_release_is_not_an_update() {
    assert_eq!(
        pick(
            json!([listed("0.1.11", true), listed("0.1.10", true)]),
            "0.1.11"
        ),
        None
    );
    assert_eq!(pick(json!([]), "0.1.11"), None);
}

#[test]
fn skips_releases_this_program_cannot_install() {
    let mut draft = listed("0.2.0", true);
    draft["draft"] = json!(true);
    let mut odd_tag = listed("0.2.1", true);
    odd_tag["tag_name"] = json!("release-0.2.1");
    let mut suffixed = listed("0.2.2", true);
    suffixed["tag_name"] = json!("v0.2.2-rc1");
    let mut no_checksum = listed("0.2.3", true);
    no_checksum["assets"].as_array_mut().unwrap().pop();
    let mut foreign_url = listed("0.2.4", true);
    foreign_url["assets"][0]["browser_download_url"] =
        json!("https://example.com/wsl-proxy-0.2.4-windows-x64.zip");
    let mut foreign_page = listed("0.2.5", true);
    foreign_page["html_url"] = json!("https://github.com/someone/fork/releases/tag/v0.2.5");
    let mut empty = listed("0.2.6", true);
    empty["assets"][0]["size"] = json!(0);
    let list = json!([
        draft,
        odd_tag,
        suffixed,
        no_checksum,
        foreign_url,
        foreign_page,
        empty,
        listed("0.1.12", true)
    ]);
    assert_eq!(pick(list, "0.1.11").unwrap().version, version("0.1.12"));
}

#[test]
fn a_release_without_a_name_is_titled_by_its_tag() {
    let mut release = listed("0.1.12", true);
    release["name"] = json!(null);
    assert_eq!(pick(json!([release]), "0.1.11").unwrap().title, "v0.1.12");
}

#[test]
fn a_list_that_is_not_json_is_a_bad_response() {
    assert!(matches!(
        newest(b"<html>", version("0.1.11")),
        Err(UpdateError::Response(_))
    ));
}

#[test]
fn only_https_addresses_on_github_hosts_are_followed() {
    let target = Target::parse("https://github.com/a/b?x=1").unwrap();
    assert_eq!(
        target,
        Target {
            host: "github.com".into(),
            path: "/a/b?x=1".into()
        }
    );
    assert_eq!(Target::parse("https://API.GitHub.com").unwrap().path, "/");
    assert_eq!(
        Target::parse("https://api.github.com?page=2").unwrap().path,
        "/?page=2"
    );
    assert!(Target::parse("https://release-assets.githubusercontent.com/x").is_ok());
    assert!(Target::parse("https://objects.githubusercontent.com/x").is_ok());
    for refused in [
        "http://github.com/x",
        "https://example.com/x",
        "https://github.com.example.com/x",
        "https://evilgithubusercontent.com/x",
        "https://github.com:8443/x",
        "https://user@github.com/x",
        "https://github.com/a b",
        "https://github.com/a\r\nHost: x",
        "ftp://github.com/x",
    ] {
        assert!(Target::parse(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn redirect_locations_resolve_against_the_current_address() {
    let target = Target::parse("https://github.com/o/r/releases/download/v1/a.zip").unwrap();
    assert_eq!(
        target.resolve("https://release-assets.githubusercontent.com/x?y=1"),
        "https://release-assets.githubusercontent.com/x?y=1"
    );
    assert_eq!(target.resolve("/o/r/other"), "https://github.com/o/r/other");
    assert_eq!(
        target.resolve("b.zip"),
        "https://github.com/o/r/releases/download/v1/b.zip"
    );
}

fn body(response: &str, limit: u64) -> Result<(u16, Vec<u8>), UpdateError> {
    let mut reader = Cursor::new(response.as_bytes().to_vec());
    let head = read_head(&mut reader)?;
    let mut collected = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let length = read_body(&mut reader, &head, limit, deadline, &mut |chunk| {
        collected.extend_from_slice(chunk);
        Ok(())
    })?;
    assert_eq!(length, collected.len() as u64);
    Ok((head.status, collected))
}

#[test]
fn reads_bodies_by_length_by_chunks_and_to_the_end() {
    assert_eq!(
        body(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello trailing",
            100
        )
        .unwrap(),
        (200, b"hello".to_vec())
    );
    assert_eq!(
        body("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n", 100).unwrap(),
        (200, b"hello world".to_vec())
    );
    assert_eq!(
        body("HTTP/1.0 200 OK\r\n\r\nuntil close", 100).unwrap(),
        (200, b"until close".to_vec())
    );
    // An interim answer is skipped.
    assert_eq!(
        body(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            100
        )
        .unwrap(),
        (200, b"ok".to_vec())
    );
}

#[test]
fn header_names_are_case_insensitive_and_values_trimmed() {
    let mut reader = Cursor::new(b"HTTP/1.1 302 Found\r\nLOCATION:  https://github.com/x \r\nX-RateLimit-Remaining: 0\r\n\r\n".to_vec());
    let head = read_head(&mut reader).unwrap();
    assert_eq!(head.status, 302);
    assert_eq!(head.header("location"), Some("https://github.com/x"));
    assert_eq!(head.header("x-ratelimit-remaining"), Some("0"));
}

#[test]
fn oversized_cut_and_malformed_responses_are_refused() {
    assert!(matches!(
        body("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nx", 10),
        Err(UpdateError::Response(_))
    ));
    assert!(matches!(
        body("HTTP/1.1 200 OK\r\n\r\n0123456789AB", 10),
        Err(UpdateError::Response(_))
    ));
    assert!(matches!(
        body(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nB\r\n0123456789A\r\n0\r\n\r\n",
            10
        ),
        Err(UpdateError::Response(_))
    ));
    assert!(matches!(
        body("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc", 10),
        Err(UpdateError::Network(_))
    ));
    assert!(matches!(
        body(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            10
        ),
        Err(UpdateError::Response(_))
    ));
    assert!(matches!(
        body(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nabX\r\n0\r\n\r\n",
            10
        ),
        Err(UpdateError::Response(_))
    ));
    assert!(matches!(
        body("SSH-2.0-OpenSSH\r\n\r\n", 10),
        Err(UpdateError::Response(_))
    ));
    assert!(matches!(
        body("HTTP/1.1 200 OK\r\nContent-Len", 10),
        Err(UpdateError::Network(_))
    ));
    let long = format!(
        "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
        "a".repeat(LINE_LIMIT as usize)
    );
    assert!(matches!(body(&long, 10), Err(UpdateError::Response(_))));
}

/// Plays back a proxy's answers and records what the client sent.
struct Scripted {
    answers: Cursor<Vec<u8>>,
    sent: Vec<u8>,
}

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.answers.read(buffer)
    }
}

impl Write for Scripted {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.sent.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn proxy(answers: &[u8]) -> Scripted {
    Scripted {
        answers: Cursor::new(answers.to_vec()),
        sent: Vec::new(),
    }
}

#[test]
fn socks5_connects_by_name_without_a_password() {
    let mut stream = proxy(&[5, 0, 5, 0, 0, 1, 10, 0, 0, 1, 0x1f, 0x90]);
    socks5_connect(&mut stream, "api.github.com", 443).unwrap();
    let mut expected = vec![5, 1, 0, 5, 1, 0, 3, 14];
    expected.extend_from_slice(b"api.github.com");
    expected.extend_from_slice(&[1, 187]);
    assert_eq!(stream.sent, expected);
    // A bound address given as a name or as IPv6 is read in full too.
    let mut named = proxy(&[5, 0, 5, 0, 0, 3, 3, b'a', b'b', b'c', 0, 80]);
    socks5_connect(&mut named, "github.com", 443).unwrap();
    assert_eq!(
        named.answers.position() as usize,
        named.answers.get_ref().len()
    );
    let mut six = vec![5, 0, 5, 0, 0, 4];
    six.extend_from_slice(&[0; 18]);
    socks5_connect(&mut proxy(&six), "github.com", 443).unwrap();
}

#[test]
fn socks5_refusals_are_network_failures() {
    for answers in [
        &[5u8, 2][..],
        &[5, 0, 5, 5, 0, 1, 0, 0, 0, 0, 0, 0][..],
        &[5, 0, 5, 0, 0, 9][..],
        &[5][..],
    ] {
        assert!(
            matches!(
                socks5_connect(&mut proxy(answers), "github.com", 443),
                Err(UpdateError::Network(_))
            ),
            "{answers:?}"
        );
    }
}

#[test]
fn checksum_files_carry_one_digest_for_the_named_package() {
    let digest = "2CD2342BD9524E2649B8FC48ABAEA4E1E3E389DACDF40F12FB5D66A5FE184EED";
    let name = "wsl-proxy-0.1.12-windows-x64.zip";
    let lower = digest.to_ascii_lowercase();
    assert_eq!(
        parse_checksum(&format!("{digest}  {name}\n"), name),
        Some(lower.clone())
    );
    assert_eq!(
        parse_checksum(&format!("{digest} *{name}"), name),
        Some(lower.clone())
    );
    assert_eq!(
        parse_checksum(&format!("\u{feff}{lower}\n"), name),
        Some(lower.clone())
    );
    assert_eq!(
        parse_checksum(&format!("{digest}  other.zip\n"), name),
        None
    );
    assert_eq!(
        parse_checksum(&format!("{digest}  {name} extra\n"), name),
        None
    );
    assert_eq!(
        parse_checksum(&format!("{}  {name}\n", &digest[..63]), name),
        None
    );
    assert_eq!(parse_checksum("", name), None);
}

#[test]
fn files_hash_to_lowercase_hex() {
    let directory =
        std::env::temp_dir().join(format!("wsl-proxy-update-test-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("abc.txt");
    fs::write(&path, b"abc").unwrap();
    assert_eq!(
        file_sha256(&path).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    fs::remove_dir_all(&directory).unwrap();
    assert!(matches!(file_sha256(&path), Err(UpdateError::Storage(_))));
}

#[test]
fn routes_try_the_host_proxy_first_then_direct() {
    let proxy: SocketAddrV4 = "127.0.0.1:7890".parse().unwrap();
    assert_eq!(
        routes(Some(proxy)),
        vec![Route::Socks5(proxy), Route::Direct]
    );
    assert_eq!(routes(None), vec![Route::Direct]);
}

#[test]
fn a_definite_answer_wins_over_network_failures() {
    let proxy: SocketAddrV4 = "127.0.0.1:7890".parse().unwrap();
    let both = routes(Some(proxy));
    let mut calls = Vec::new();
    let error = attempt(&both, |route| -> Result<(), UpdateError> {
        calls.push(route);
        Err(UpdateError::Network(format!("down {}", calls.len())))
    })
    .unwrap_err();
    assert_eq!(
        error,
        UpdateError::Network("host SOCKS5 127.0.0.1:7890: down 1; direct: down 2".into())
    );
    let error = attempt(&both, |route| -> Result<(), UpdateError> {
        match route {
            Route::Socks5(_) => Err(UpdateError::RateLimited),
            Route::Direct => Err(UpdateError::Network("down".into())),
        }
    })
    .unwrap_err();
    assert_eq!(error, UpdateError::RateLimited);
    assert_eq!(
        attempt(&both, |route| match route {
            Route::Socks5(_) => Err(UpdateError::Network("down".into())),
            Route::Direct => Ok(7),
        }),
        Ok(7)
    );
    assert_eq!(
        attempt(&[], |_| Ok(1)),
        Err(UpdateError::Network("no route to try".into()))
    );
}

#[test]
fn errors_name_their_kind_for_the_desktop() {
    assert_eq!(UpdateError::RateLimited.to_string(), "update_rate_limited");
    assert_eq!(
        UpdateError::Checksum.to_string(),
        "update_checksum_mismatch"
    );
    assert_eq!(
        UpdateError::Network("x".into()).to_string(),
        "update_network: x"
    );
}

/// Asks the real GitHub for the release after 0.1.10 and downloads it. Run by
/// hand on Windows: `cargo test -p wsl-proxyctl --lib update::tests::live -- --ignored`
/// Set `WSL_PROXY_UPDATE_TEST_SOCKS5=127.0.0.1:7890` to go only through that
/// proxy, with no direct fallback, so a pass proves the SOCKS5 route.
#[test]
#[ignore = "downloads about 40 MB from GitHub"]
fn live_check_and_download() {
    let routes = match std::env::var("WSL_PROXY_UPDATE_TEST_SOCKS5") {
        Ok(proxy) => vec![Route::Socks5(proxy.parse().unwrap())],
        Err(_) => vec![Route::Direct],
    };
    let release = check(&routes, version("0.1.10"))
        .unwrap()
        .expect("a release after 0.1.10");
    assert!(release.version > version("0.1.10"));
    let directory =
        std::env::temp_dir().join(format!("wsl-proxy-update-live-{}", std::process::id()));
    let mut last = (0, 0);
    let downloaded = download(&release, &routes, &directory, &mut |done, total| {
        last = (done, total)
    })
    .unwrap();
    assert_eq!(last, (release.package.size, release.package.size));
    assert_eq!(file_sha256(&downloaded.path).unwrap(), downloaded.sha256);
    // A second run finds the checked package and does not download it again.
    let mut calls = 0;
    let again = download(&release, &routes, &directory, &mut |_, _| calls += 1).unwrap();
    assert_eq!((again, calls), (downloaded, 1));
    fs::remove_dir_all(&directory).unwrap();
}
