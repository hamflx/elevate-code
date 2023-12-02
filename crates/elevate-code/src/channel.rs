use std::net::UdpSocket;

pub struct InterProcessChannelPeer {
    socket: UdpSocket,
}

impl InterProcessChannelPeer {
    pub fn new() -> (Self, Self) {
        let socket1 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket1_addr = socket1.local_addr().unwrap();
        let socket2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket2_addr = socket2.local_addr().unwrap();
        socket1.connect(socket2_addr).unwrap();
        socket2.connect(socket1_addr).unwrap();
        (
            InterProcessChannelPeer { socket: socket1 },
            InterProcessChannelPeer { socket: socket2 },
        )
    }

    pub fn send(&mut self, data: &[u8]) {
        self.socket.send(data).unwrap();
    }

    pub fn recv(&self) -> Vec<u8> {
        let mut buf = vec![0; 1048576];
        let len = self.socket.recv(&mut buf).unwrap();
        buf.truncate(len);
        buf
    }
}
