// IPC frame codec.
mod inner {
    use serde_json::Value;
    use std::io::{self, Read, Write};

    pub(crate) const MAX_FRAME: usize = 1024 * 1024;
    pub(crate) const ACK: u8 = 0x06;

    struct LimitedBuffer(Vec<u8>);

    impl Write for LimitedBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > MAX_FRAME - self.0.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ipc_frame_too_large",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub(crate) fn encode(value: &Value) -> io::Result<Vec<u8>> {
        let mut bytes = LimitedBuffer(Vec::new());
        serde_json::to_writer(&mut bytes, value)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ipc_frame_too_large"))?;
        Ok(bytes.0)
    }

    pub(crate) fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc_invalid_frame_length",
            ));
        }
        stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
        stream.write_all(bytes)
    }

    pub(crate) fn read_frame(stream: &mut impl Read) -> io::Result<Value> {
        let mut header = [0; 4];
        stream.read_exact(&mut header)?;
        let length = u32::from_le_bytes(header) as usize;
        if length == 0 || length > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc_invalid_frame_length",
            ));
        }
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes)?;
        // Parser diagnostics can contain JSON strings, including credentials.
        serde_json::from_slice(&bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ipc_invalid_json"))
    }

    pub(crate) fn respond(stream: &mut (impl Read + Write), value: &Value) -> io::Result<()> {
        write_frame(stream, &encode(value)?)?;
        // FlushFileBuffers on a pipe can wait forever for a disconnected/stalled
        // reader. A bounded transport ACK proves receipt without that API.
        let mut ack = [0];
        stream.read_exact(&mut ack)?;
        if ack[0] != ACK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ipc_invalid_ack",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) use inner::MAX_FRAME;
pub(super) use inner::{ACK, encode, read_frame, respond, write_frame};
