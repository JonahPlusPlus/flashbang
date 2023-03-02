use std::{
    io::Error,
    net::{ToSocketAddrs, UdpSocket},
};

pub fn connect(socket: UdpSocket, addr: impl ToSocketAddrs) -> Result<(), Error> {
    let addr = match addr.to_socket_addrs()?.next() {
        Some(a) => a,
        None => {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "`addr` was empty",
            ))
        }
    };

    Ok(())
}
