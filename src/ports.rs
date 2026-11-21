use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};
use std::num::NonZeroU16;

use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};

#[derive(Serialize)]
pub struct PortCheck {
    pub address: SocketAddrV4,
    pub tcp_error: Option<String>,
    pub udp_error: Option<String>,
}

impl PortCheck {
    pub fn available(&self) -> bool {
        self.tcp_error.is_none() && self.udp_error.is_none()
    }
}

pub(crate) fn bind_exclusive(
    address: SocketAddrV4,
    kind: Type,
    protocol: Protocol,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, kind, Some(protocol))?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOL_SOCKET, WSAGetLastError, setsockopt,
        };
        let exclusive = 1i32;
        // Winsock copies the BOOL during setsockopt; the owned socket remains live until bind.
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&exclusive as *const i32).cast(),
                size_of::<i32>() as i32,
            )
        };
        if result != 0 {
            // SAFETY: read the calling thread's socket error immediately after failure.
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    socket.bind(&address.into())?;
    Ok(socket)
}

pub(crate) fn bind_exclusive_v6(
    address: SocketAddrV6,
    kind: Type,
    protocol: Protocol,
) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, kind, Some(protocol))?;
    socket.set_only_v6(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOL_SOCKET, WSAGetLastError, setsockopt,
        };
        let exclusive = 1i32;
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&exclusive as *const i32).cast(),
                size_of::<i32>() as i32,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    socket.bind(&address.into())?;
    Ok(socket)
}

/// Brief exclusive binds, not listeners. A later controller must acquire its own sockets again.
pub fn check(ip: Ipv4Addr, port: NonZeroU16) -> PortCheck {
    let address = SocketAddrV4::new(ip, port.get());
    let tcp = bind_exclusive(address, Type::STREAM, Protocol::TCP);
    let udp = bind_exclusive(address, Type::DGRAM, Protocol::UDP);
    PortCheck {
        address,
        tcp_error: tcp.err().map(|e| e.to_string()),
        udp_error: udp.err().map(|e| e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupied_udp_blocks_even_when_tcp_is_free() {
        let held = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = NonZeroU16::new(held.local_addr().unwrap().port()).unwrap();
        let result = check(Ipv4Addr::LOCALHOST, port);
        assert!(!result.available());
        assert!(result.udp_error.is_some());
    }
}
