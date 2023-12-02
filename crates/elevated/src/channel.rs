use std::{io::Cursor, marker::PhantomData, net::UdpSocket};

use serde::{de::DeserializeOwned, Serialize};
use windows::Win32::Networking::WinSock::WSAEMSGSIZE;

pub struct InterProcessChannelPeer<T> {
    socket: UdpSocket,
    phantom: PhantomData<T>,
}

impl<T> InterProcessChannelPeer<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn new() -> (Self, Self) {
        let socket1 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket1_addr = socket1.local_addr().unwrap();
        let socket2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket2_addr = socket2.local_addr().unwrap();
        socket1.connect(socket2_addr).unwrap();
        socket2.connect(socket1_addr).unwrap();
        (
            InterProcessChannelPeer {
                socket: socket1,
                phantom: PhantomData,
            },
            InterProcessChannelPeer {
                socket: socket2,
                phantom: PhantomData,
            },
        )
    }

    pub fn send(&mut self, data: &T) -> Result<(), String> {
        let payload =
            serde_json::to_string(&data).map_err(|err| format!("serialize error: {err}"))?;
        let payload_len = payload.len() as u32;
        let payload_len_bytes: [u8; 4] = payload_len.to_be_bytes();
        let mut buf = vec![0u8; payload.len() + payload_len_bytes.len()];
        buf[..payload_len_bytes.len()].copy_from_slice(&payload_len_bytes);
        buf[payload_len_bytes.len()..].copy_from_slice(payload.as_bytes());
        self.socket
            .send(&buf)
            .map_err(|err| format!("send error: {err}"))?;
        Ok(())
    }

    pub fn recv(&self) -> Result<T, String> {
        let mut len_bytes: [u8; 4] = [0; 4];
        let ret = self.socket.peek(&mut len_bytes);
        match ret {
            Ok(_) => (),
            Err(err) if err.raw_os_error() == Some(WSAEMSGSIZE.0) => (),
            _ => return Err("invalid packet".to_string()),
        };
        let payload_len = u32::from_be_bytes(len_bytes);
        let len = payload_len as usize + len_bytes.len();
        let mut buf = vec![0u8; len];
        let read_len = self
            .socket
            .recv(&mut buf)
            .map_err(|err| format!("recv error: {err}"))?;
        if read_len != len {
            return Err("length not match".to_string());
        }
        let message: Vec<u8> = buf.drain(len_bytes.len()..).collect();
        Ok(serde_json::from_reader(Cursor::new(message))
            .map_err(|err| format!("deserialize error: {err}"))?)
    }
}
