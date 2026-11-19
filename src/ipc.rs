use serde_json::Value;

/// Sends one request without retrying a possibly applied mutation.
pub fn request(req: &Value) -> Result<Value, String> {
    #[cfg(windows)]
    {
        windows::request(req)
    }
    #[cfg(not(windows))]
    {
        let _ = req;
        Err("unsupported_platform: native controller IPC requires Windows".into())
    }
}

/// Starts only the verified sibling controller, never an existing CLI session.
pub fn ensure_daemon() -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::ensure_daemon()
    }
    #[cfg(not(windows))]
    {
        Err("unsupported_platform: native controller IPC requires Windows".into())
    }
}

/// Serves until an idle-only shutdown response has been received and acknowledged.
pub fn serve(handler: impl FnMut(Value) -> (Value, bool)) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::serve(handler)
    }
    #[cfg(not(windows))]
    {
        let _ = handler;
        Err("unsupported_platform: native controller IPC requires Windows".into())
    }
}

#[cfg(any(windows, test))]
#[path = "ipc/framing.rs"]
mod framing;

#[cfg(windows)]
#[path = "ipc/windows.rs"]
mod windows;

#[cfg(test)]
mod tests {
    use super::framing::*;
    use std::io::{self, Cursor, Read, Write};

    struct ShortIo {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        max_chunk: usize,
    }

    impl Read for ShortIo {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let length = bytes.len().min(self.max_chunk);
            self.input.read(&mut bytes[..length])
        }
    }

    impl Write for ShortIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let length = bytes.len().min(self.max_chunk);
            self.output.extend_from_slice(&bytes[..length]);
            Ok(length)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed(value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &encode(value).unwrap()).unwrap();
        bytes
    }

    #[test]
    fn partial_io_preserves_exactly_one_json_frame() {
        let value = serde_json::json!({"action": "状态", "items": [1, 2, 3]});
        let first = framed(&value);
        let mut two = first.clone();
        two.extend(framed(&serde_json::json!({"second": true})));
        let mut stream = ShortIo {
            input: Cursor::new(two),
            output: Vec::new(),
            max_chunk: 1,
        };
        assert_eq!(read_frame(&mut stream).unwrap(), value);
        assert_eq!(stream.input.position() as usize, first.len());
        write_frame(&mut stream, &encode(&value).unwrap()).unwrap();
        assert_eq!(stream.output, first);
    }

    #[test]
    fn oversized_and_empty_frames_are_rejected_before_body_allocation() {
        for length in [0, MAX_FRAME as u32 + 1, u32::MAX] {
            let error = read_frame(&mut Cursor::new(length.to_le_bytes())).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        let huge = serde_json::Value::String("x".repeat(MAX_FRAME));
        assert_eq!(
            encode(&huge).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncation_and_invalid_json_never_expose_payload() {
        let mut truncated = Cursor::new(vec![10, 0, 0, 0, b'{']);
        assert_eq!(
            read_frame(&mut truncated).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        let secret = b"private-password: not JSON";
        let mut bytes = (secret.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(secret);
        assert_eq!(
            read_frame(&mut Cursor::new(bytes)).unwrap_err().to_string(),
            "ipc_invalid_json"
        );
    }

    #[test]
    fn shutdown_response_requires_ack_after_successful_write() {
        for ack in [Vec::new(), vec![0], vec![ACK]] {
            let expected_success = ack == [ACK];
            let mut stream = ShortIo {
                input: Cursor::new(ack),
                output: Vec::new(),
                max_chunk: 2,
            };
            assert_eq!(
                respond(&mut stream, &serde_json::json!({"idle": true})).is_ok(),
                expected_success
            );
            assert_eq!(
                read_frame(&mut Cursor::new(stream.output)).unwrap(),
                serde_json::json!({"idle": true})
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn unsupported_platform_never_calls_handler() {
        assert!(
            super::request(&serde_json::json!({}))
                .unwrap_err()
                .starts_with("unsupported_platform:")
        );
        assert!(
            super::ensure_daemon()
                .unwrap_err()
                .starts_with("unsupported_platform:")
        );
        assert!(
            super::serve(|_| panic!("must not execute on unsupported platform"))
                .unwrap_err()
                .starts_with("unsupported_platform:")
        );
    }
}
