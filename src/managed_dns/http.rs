use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use super::MAX_DNS;

pub(super) struct DeadlineStream {
    pub(super) socket: TcpStream,
    pub(super) deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream deadline"))
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn http_line(reader: &mut impl BufRead, budget: &mut usize) -> Result<String, String> {
    let mut line = Vec::new();
    loop {
        if *budget == 0 || line.len() >= 8192 {
            return Err("DNS HTTPS headers exceed limit".into());
        }
        let mut byte = [0];
        reader
            .read_exact(&mut byte)
            .map_err(|e| format!("read DNS HTTPS header: {e}"))?;
        *budget -= 1;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if !line.ends_with(b"\r\n") {
        return Err("invalid DNS HTTPS header line".into());
    }
    line.truncate(line.len() - 2);
    String::from_utf8(line).map_err(|_| "non-ASCII DNS HTTPS header".into())
}

pub(super) fn read_http(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
    let mut budget = 16_384;
    let status = http_line(reader, &mut budget)?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        return Err("DNS HTTPS upstream did not return HTTP 200".into());
    }
    let mut length = None;
    let mut chunked = false;
    let mut content_type = false;
    loop {
        let line = http_line(reader, &mut budget)?;
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':').ok_or("malformed DNS HTTPS header")?;
        let value = value.trim();
        match key.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.is_some() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("ambiguous DNS HTTPS Content-Length".into());
                }
                let size = value
                    .parse::<usize>()
                    .map_err(|_| "invalid DNS HTTPS length")?;
                if !(12..=MAX_DNS).contains(&size) {
                    return Err("DNS HTTPS body size outside limits".into());
                }
                length = Some(size);
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err("unsupported DNS HTTPS transfer encoding".into());
                }
                chunked = true;
            }
            "content-type" => {
                if content_type || !value.eq_ignore_ascii_case("application/dns-message") {
                    return Err("invalid DNS HTTPS content type".into());
                }
                content_type = true;
            }
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err("compressed DNS HTTPS body is unsupported".into());
            }
            _ => {}
        }
    }
    if !content_type || (chunked && length.is_some()) {
        return Err("ambiguous DNS HTTPS response framing".into());
    }
    let mut body = Vec::new();
    if let Some(length) = length {
        body.resize(length, 0);
        reader
            .read_exact(&mut body)
            .map_err(|e| format!("read DNS HTTPS body: {e}"))?;
    } else if chunked {
        loop {
            let line = http_line(reader, &mut budget)?;
            if line.is_empty() || line.len() > 8 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid DNS HTTPS chunk size".into());
            }
            let size = usize::from_str_radix(&line, 16).map_err(|_| "invalid DNS HTTPS chunk")?;
            if size == 0 {
                // Reject trailers rather than allow a second interpretation of
                // content type, length, or the authenticated message boundary.
                if !http_line(reader, &mut budget)?.is_empty() {
                    return Err("DNS HTTPS trailers are unsupported".into());
                }
                break;
            }
            if size > MAX_DNS - body.len() {
                return Err("DNS HTTPS body exceeds limit".into());
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader
                .read_exact(&mut body[start..])
                .map_err(|e| format!("read DNS HTTPS chunk: {e}"))?;
            let mut end = [0; 2];
            reader
                .read_exact(&mut end)
                .map_err(|e| format!("read DNS HTTPS chunk end: {e}"))?;
            if end != *b"\r\n" {
                return Err("invalid DNS HTTPS chunk end".into());
            }
        }
    } else {
        return Err("DNS HTTPS response requires explicit body framing".into());
    }
    if body.len() < 12 {
        return Err("short DNS HTTPS body".into());
    }
    Ok(body)
}
