#![allow(dead_code)]

#[forbid(unsafe_code)]
use async_std::{
    net::{TcpStream, UdpSocket},
    task,
};

use futures::{task::Poll, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io;
use std::pin::Pin;
use std::vec;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

#[rustfmt::skip]
pub mod consts {
    pub const VERSION:                          u8 = 0x05;
}


#[macro_export]
macro_rules! read_exact {
    ($stream: expr, $array: expr) => {{
        let mut x = $array;
        //        $stream
        //            .read_exact(&mut x)
        //            .await
        //            .map_err(|_| io_err("lol"))?;
        $stream.read_exact(&mut x).await.map(|_| x)
    }};
}

// o  X'00' NO AUTHENTICATION REQUIRED
// o  X'01' GSSAPI
// o  X'02' USERNAME/PASSWORD
// o  X'03' to X'7F' IANA ASSIGNED
// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
// o  X'FF' NO ACCEPTABLE METHODS
pub enum Authentication {
    None,
    Password { username: String, password: String },
}

impl Authentication {
    pub fn as_u8(&self) -> u8 {
        match self {
            Authentication::None           => 00,
            Authentication::Password{ .. } => 02,
        }
    }

    pub fn from_u8(v: u8) -> Option<Authentication> {
        match v {
            0x00 => Some(Authentication::None),
            0x02 => Some(Authentication::Password{
                username: String::from(""),
                password: String::from(""),
            }),
            _  => Option::None,
        }
    }
}

enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl Command {
    pub fn as_u8(&self) -> u8 {
        match self {
            Command::Connect      => 0x01,
            Command::Bind         => 0x02,
            Command::UdpAssociate => 0x03,
        }
    }
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn as_bytes(&self, buf: &mut [u8]) -> io::Result<usize>  {
        let padding;
        // ATYP | DST.ADDR | DST.PORT
        match self {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                buf[0] = 0x01;

                padding = 1 + 4 + 2;

                buf[1..5].copy_from_slice(&(addr.ip()).octets());
                buf[5..padding].copy_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                buf[0] = 0x01;

                padding = 1 + 16 + 2;

                buf[1..17].copy_from_slice(&(addr.ip()).octets());
                buf[17..padding].copy_from_slice(&addr.port().to_be_bytes());
            }
            TargetAddr::Domain(domain, port) => {
                buf[0] = 0x03;

                padding = 1 + 1 + domain.len() + 2;

                buf[1] = domain.len() as u8;
                buf[2..(2 + domain.len())].copy_from_slice(domain.as_bytes());
                buf[(2 + domain.len())..padding].copy_from_slice(&port.to_be_bytes());
            }
        }

        Ok(padding)
    }
}

impl std::net::ToSocketAddrs for TargetAddr {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<vec::IntoIter<SocketAddr>> {
        match *self {
            TargetAddr::Ip(addr) => Ok(vec![addr].into_iter()),
            TargetAddr::Domain(_, _) => Err(io::Error::new(
                io::ErrorKind::Other,
                "Domain name has to be explicitly resolved, please use TargetAddr::resolve_dns().",
            )),
        }
    }
}

pub struct SocksClient {
    socket: TcpStream,
}

pub type Result<T> = io::Result<T>;

impl SocksClient {
    pub async fn new<T>(
        proxy: T,
        methods: Vec<Authentication>,
    ) -> Result<SocksClient>
        where T: async_std::net::ToSocketAddrs
    {
        if methods.len() == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "no method provided"));
        }

        let mut socket = TcpStream::connect(&proxy).await?;

        // The client connects to the server, and sends a version
        // identifier/method selection message:
        //
        //                 +----+----------+----------+
        //                 |VER | NMETHODS | METHODS  |
        //                 +----+----------+----------+
        //                 | 1  |    1     | 1 to 255 |
        //                 +----+----------+----------+
        //
        // The VER field is set to X'05' for this version of the protocol.  The
        // NMETHODS field contains the number of method identifier octets that
        // appear in the METHODS field.
        let methods_u8 = methods.iter().map(|l| l.as_u8()).collect::<Vec<_>>();

        socket.write(&[consts::VERSION, methods.len() as u8]).await?;

        socket.write(&methods_u8).await?;



        // The server selects from one of the methods given in METHODS, and
        // sends a METHOD selection message:
        //
        //                       +----+--------+
        //                       |VER | METHOD |
        //                       +----+--------+
        //                       | 1  |   1    |
        //                       +----+--------+
        //
        // If the selected METHOD is X'FF', none of the methods listed by the
        // client are acceptable, and the client MUST close the connection.
        //
        // The values currently defined for METHOD are:
        //
        //        o  X'00' NO AUTHENTICATION REQUIRED
        //        o  X'01' GSSAPI
        //        o  X'02' USERNAME/PASSWORD
        //        o  X'03' to X'7F' IANA ASSIGNED
        //        o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        //        o  X'FF' NO ACCEPTABLE METHODS
        let [version, method] = read_exact!(socket, [0u8; 2])?;

        if version != consts::VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
        }

        if method == 0xff {
            return Err(io::Error::new(io::ErrorKind::Other, "no acceptable auth methods"));
        }
        if let Some(method) = Authentication::from_u8(method) {
            match method {
                Authentication::None => {}
                Authentication::Password{..} => {
                    // TODO
                    return Err(io::Error::new(io::ErrorKind::Other, "..."));
                }
            }
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "unknown auth method"))
        };

        Ok(SocksClient { socket })
    }

    pub async fn connect(
        mut self,
        target_addr: TargetAddr,
    ) -> Result<SocksStream>
    {
        self.write_request(Command::Connect, &target_addr).await?;

        let addr = get_reply(&mut self.socket).await?;

        Ok(SocksStream {
            socket: self.socket,
            proxy_addr: addr,
        })
    }

    pub async fn bind(
        mut self,
        target_addr: TargetAddr,
    ) -> Result<SocksListener>
    {
        self.write_request(Command::Bind, &target_addr).await?;

        let addr = get_reply(&mut self.socket).await?;

        Ok(SocksListener {
            socket: self.socket,
            proxy_addr: addr,
        })
    }

    pub async fn bind_udp<T>(
        mut self,
        target_addr: T,
    ) -> Result<SocksDatagram>
        where T: async_std::net::ToSocketAddrs
    {
        // we don't know what our IP is from the perspective of the proxy, so
        // don't try to pass `addr` in here.
        let dst = TargetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0,
        ));

        self.write_request(Command::UdpAssociate, &dst).await?;
        let addr = get_reply(&mut self.socket).await?;

        let stream = SocksStream {
            socket: self.socket,
            proxy_addr: addr,
        };

        let socket = UdpSocket::bind(target_addr).await?;

        let proxy_addr = stream.proxy_addr()
            .to_socket_addrs()?
            .next()
            .ok_or(io::Error::new(
                io::ErrorKind::Other,
                "failed to convert proxy addr"
            ))?;
        socket.connect(proxy_addr).await?;

        Ok(SocksDatagram {
            socket: socket,
            stream: stream,
        })
    }

    async fn write_request(
        &mut self,
        command: Command,
        target_addr: &TargetAddr
    ) -> Result<()>
    {
        // Once the method-dependent subnegotiation has completed, the client
        // sends the request details.  If the negotiated method includes
        // encapsulation for purposes of integrity checking and/or
        // confidentiality, these requests MUST be encapsulated in the method-
        // dependent encapsulation.
        //
        // The SOCKS request is formed as follows:
        //
        //      +----+-----+-------+------+----------+----------+
        //      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //      +----+-----+-------+------+----------+----------+
        //      | 1  |  1  | X'00' |  1   | Variable |    2     |
        //      +----+-----+-------+------+----------+----------+
        //
        //   Where:
        //
        //        o  VER    protocol version: X'05'
        //        o  CMD
        //           o  CONNECT X'01'
        //           o  BIND X'02'
        //           o  UDP ASSOCIATE X'03'
        //        o  RSV    RESERVED
        //        o  ATYP   address type of following address
        //           o  IP V4 address: X'01'
        //           o  DOMAINNAME: X'03'
        //           o  IP V6 address: X'04'
        //        o  DST.ADDR       desired destination address
        //        o  DST.PORT desired destination port in network octet
        //           order
        //
        // The SOCKS server will typically evaluate the request based on source
        // and destination addresses, and return one or more reply messages, as
        // appropriate for the request type.


        let mut packet = [0u8; 1 + 1 + 1 + 1 + 256 + 2];



        // VER | CMD |  RSV
        packet[..3].copy_from_slice(&[
            consts::VERSION,
            command.as_u8(),
            0x00,
        ]);

        // ATYP | DST.ADDR | DST.PORT
        let padding = target_addr.as_bytes(&mut packet[3..])?;

        self.socket
            .write_all(&packet[..padding])
            .await?;

        Ok(())
    }

}

pub struct SocksStream {
    socket: TcpStream,
    proxy_addr: TargetAddr,
}

impl SocksStream {
    pub fn proxy_addr(&self) -> &TargetAddr {
        &self.proxy_addr
    }
}

impl AsyncRead for SocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_read(context, buf)
    }
}

impl AsyncWrite for SocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.socket).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_flush(context)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket).poll_close(context)
    }
}

pub struct SocksListener {
    socket: TcpStream,
    proxy_addr: TargetAddr,
}

impl SocksListener {
    pub async fn accept(mut self) -> io::Result<SocksStream> {
        self.proxy_addr = get_reply(&mut self.socket).await?;
        Ok(SocksStream {
            socket: self.socket,
            proxy_addr: self.proxy_addr,
        })
    }
}

pub struct SocksDatagram {
    socket: UdpSocket,
    stream: SocksStream,
}

impl SocksDatagram {
    pub fn send_to(&self, buf: &[u8], addr: TargetAddr) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "no implemented"))
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, TargetAddr)> {
        Err(io::Error::new(io::ErrorKind::Other, "no implemented"))
    }

    pub fn proxy_addr(&self) -> &TargetAddr {
        &self.stream.proxy_addr
    }

    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }
}


async fn get_reply(
    socket: &mut TcpStream,
) -> Result<TargetAddr>
{
    // The SOCKS request information is sent by the client as soon as it has
    // established a connection to the SOCKS server, and completed the
    // authentication negotiations.  The server evaluates the request, and
    // returns a reply formed as follows:
    //
    //      +----+-----+-------+------+----------+----------+
    //      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //      +----+-----+-------+------+----------+----------+
    //      | 1  |  1  | X'00' |  1   | Variable |    2     |
    //      +----+-----+-------+------+----------+----------+
    //
    //   Where:
    //
    //        o  VER    protocol version: X'05'
    //        o  REP    Reply field:
    //           o  X'00' succeeded
    //           o  X'01' general SOCKS server failure
    //           o  X'02' connection not allowed by ruleset
    //           o  X'03' Network unreachable
    //           o  X'04' Host unreachable
    //           o  X'05' Connection refused
    //           o  X'06' TTL expired
    //           o  X'07' Command not supported
    //           o  X'08' Address type not supported
    //           o  X'09' to X'FF' unassigned
    //        o  RSV    RESERVED
    //        o  ATYP   address type of following address
    //           o  IP V4 address: X'01'
    //           o  DOMAINNAME: X'03'
    //           o  IP V6 address: X'04'
    //        o  BND.ADDR       server bound address
    //        o  BND.PORT       server bound port in network octet order

    // VER | REP |  RSV  | ATYP
    let [version, reply, rsv, address_type] =
        read_exact!(socket, [0u8; 4])?;

    if version != consts::VERSION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid response version"));
    }

    match reply {
        0 => {}
        1 => return Err(io::Error::new(io::ErrorKind::Other, "general SOCKS server failure")),
        2 => return Err(io::Error::new(io::ErrorKind::Other, "connection not allowed by ruleset")),
        3 => return Err(io::Error::new(io::ErrorKind::Other, "network unreachable")),
        4 => return Err(io::Error::new(io::ErrorKind::Other, "host unreachable")),
        5 => return Err(io::Error::new(io::ErrorKind::Other, "connection refused")),
        6 => return Err(io::Error::new(io::ErrorKind::Other, "TTL expired")),
        7 => return Err(io::Error::new(io::ErrorKind::Other, "command not supported")),
        8 => return Err(io::Error::new(io::ErrorKind::Other, "address kind not supported")),
        _ => return Err(io::Error::new(io::ErrorKind::Other, "unknown error")),
    }

    if rsv != 0x00 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid reserved byte"));
    }

    //  BND.ADDR | BND.PORT
    let addr: TargetAddr = match address_type {
        0x01 => {
            let bytes = read_exact!(socket, [0u8; 4])?;
            let port = {
                let [h, l] = read_exact!(socket, [0u8, 2])?;
                (h as u16) << 8 | l as u16
            };
            TargetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(bytes)),
                port,
            ))
        }
        0x04 => {
            let bytes = read_exact!(socket, [0u8; 16])?;
            let port = {
                let [h, l] = read_exact!(socket, [0u8, 2])?;
                (h as u16) << 8 | l as u16
            };
            TargetAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(bytes)),
                port,
            ))
        }
        0x03 => {
            let domain = {
                let [len] = read_exact!(socket, [0])?;
                let bytes = read_exact!(socket, vec![0u8; len as usize])?;
                String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            };
            let port = {
                let [h, l] = read_exact!(socket, [0u8, 2])?;
                (h as u16) << 8 | l as u16
            };
            TargetAddr::Domain(
                domain,
                port,
            )
        }
        _ => return Err(io::Error::new(io::ErrorKind::Other, "unsupported address type")),
    };

    Ok(addr)
}