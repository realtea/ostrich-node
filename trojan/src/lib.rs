pub mod config;
// mod copy;
// mod association;
mod proxy;
mod tcp;
// mod udp;
mod tls;
mod ws;
// mod deplex;
// mod read_buf;
// mod util;


use async_std_resolver::AsyncStdResolver;
use bytes::{Buf, BufMut};
use errors::{Error, Result};
use futures::{channel::oneshot, AsyncRead, AsyncReadExt};

use hex::encode;
pub use proxy::*;

use sha2::{Digest, Sha224};
use std::{
    fmt,
    fmt::{Debug, Formatter},
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc
};

#[derive(Debug)]
pub enum SessionMessage {
    NewPeer(Connection),
    KeepLive(SocketAddr),
    DisConnected(SocketAddr)
}
#[derive(Debug)]
pub struct Connection {
    addr: SocketAddr,
    // task: Task<Result<u8>>,
    // stream: TcpStream,
    terminator: oneshot::Sender<bool>
}

pub const RELAY_BUFFER_SIZE: usize = 2048;

// pub fn load_certs(path: &Path) -> Result<Vec<Certificate>> {
// certs(&mut BufReader::new(File::open(path)?)).map_err(|_| Error::Eor(anyhow!("could not find carts")))
// }
//
// #[macro_export]
// macro_rules! key {
// ($e:expr,$p:ident) => {
// let reader = &mut BufReader::new(File::open($p)?);
// if let Ok(mut keys) = $e(reader) {
// if !keys.is_empty() {
// return Ok(keys.remove(0))
// }
// }
// };
// }
// pub fn load_keys(path: &Path) -> Result<PrivateKey> {
// key!(pkcs8_private_keys, path);
// key!(rsa_private_keys, path);
// Err(Error::Eor(anyhow::anyhow!("invalid key")))
// }

pub fn generate_authenticator(passwd_list: &Vec<String>) -> Result<Vec<String>> {
    let mut authenticator = Vec::with_capacity(passwd_list.len());
    for passwd in passwd_list {
        let mut hasher = Sha224::new();
        hasher.update(passwd.as_bytes());
        let encode_passwd = encode(hasher.finalize());
        authenticator.push(encode_passwd);
    }
    Ok(authenticator)
}
#[inline]
fn to_ipv6_address(addr: &SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(ref a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
        SocketAddr::V6(ref a) => *a
    }
}

/// the following code copy from
/// https://github.com/p4gefau1t/trojan-r/blob/main/src/protocol/mod.rs
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Address {
    /// Socket address (IP Address)
    SocketAddress(SocketAddr),
    /// Domain name address
    DomainNameAddress(String, u16)
}
impl Address {
    const ADDR_TYPE_DOMAIN_NAME: u8 = 3;
    const ADDR_TYPE_IPV4: u8 = 1;
    const ADDR_TYPE_IPV6: u8 = 4;

    #[inline]
    fn serialized_len(&self) -> usize {
        match self {
            Address::SocketAddress(SocketAddr::V4(..)) => 1 + 4 + 2,
            Address::SocketAddress(SocketAddr::V6(..)) => 1 + 8 * 2 + 2,
            Address::DomainNameAddress(ref dmname, _) => 1 + 1 + dmname.len() + 2
        }
    }

    async fn read_from_stream<R>(stream: &mut R) -> Result<Address>
    where R: AsyncRead + Unpin {
        let mut addr_type_buf = [0u8; 1];
        let _ = stream.read_exact(&mut addr_type_buf).await?;

        let addr_type = addr_type_buf[0];
        match addr_type {
            Self::ADDR_TYPE_IPV4 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
                let mut cursor = Cursor::new(buf);

                let v4addr = Ipv4Addr::new(cursor.get_u8(), cursor.get_u8(), cursor.get_u8(), cursor.get_u8());
                let port = cursor.get_u16();
                Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port))))
            }
            Self::ADDR_TYPE_IPV6 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;

                let mut cursor = Cursor::new(&buf);
                let v6addr = Ipv6Addr::new(
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16(),
                    cursor.get_u16()
                );
                let port = cursor.get_u16();

                Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6addr, port, 0, 0))))
            }
            Self::ADDR_TYPE_DOMAIN_NAME => {
                let mut length_buf = [0u8; 1];
                let mut addr_buf = [0u8; 255 + 2];
                stream.read_exact(&mut length_buf).await?;
                let length = length_buf[0] as usize;

                // Len(Domain) + Len(Port)
                stream.read_exact(&mut addr_buf[..length + 2]).await?;

                let domain_buf = &addr_buf[..length];
                let addr = match String::from_utf8(domain_buf.to_vec()) {
                    Ok(addr) => addr,
                    Err(..) => return Err(Error::Eor(anyhow::anyhow!("invalid address encoding")))
                };
                let mut port_buf = &addr_buf[length..length + 2];
                let port = port_buf.get_u16();

                Ok(Address::DomainNameAddress(addr, port))
            }
            _ => {
                // Wrong Address Type . Socks5 only supports ipv4, ipv6 and domain name
                Err(Error::Eor(anyhow::anyhow!("not supported address type {:#x}", addr_type)))
            }
        }
    }

    fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::SocketAddress(SocketAddr::V4(addr)) => {
                buf.put_u8(Self::ADDR_TYPE_IPV4);
                buf.put_slice(&addr.ip().octets());
                buf.put_u16(addr.port());
            }
            Self::SocketAddress(SocketAddr::V6(addr)) => {
                buf.put_u8(Self::ADDR_TYPE_IPV6);
                for seg in &addr.ip().segments() {
                    buf.put_u16(*seg);
                }
                buf.put_u16(addr.port());
            }
            Self::DomainNameAddress(domain_name, port) => {
                buf.put_u8(Self::ADDR_TYPE_DOMAIN_NAME);
                buf.put_u8(domain_name.len() as u8);
                buf.put_slice(&domain_name.as_bytes()[..]);
                buf.put_u16(*port);
            }
        }
    }

    // pub fn to_socket_addr(self) -> Option<SocketAddr> {
    //     let addr = match self {
    //         Address::SocketAddress(addr) => Some(addr),
    //         Address::DomainNameAddress(_, _) => None
    //     };
    //     addr
    // }

    pub fn is_ipv4_unspecified(&self) -> bool {
        match self {
            Address::SocketAddress(SocketAddr::V4(addr)) => {
                if addr.eq(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
                    return true
                }
                false
            }
            Address::SocketAddress(SocketAddr::V6(..)) => false,
            Address::DomainNameAddress(_, _) => false
        }
    }

    pub async fn to_ipv6(&self, resolver: &Arc<AsyncStdResolver>) -> Result<SocketAddrV6> {
        match self {
            Address::SocketAddress(addr) => Ok(to_ipv6_address(&addr)),

            Address::DomainNameAddress(ref addr, ref port) => {
                let response = resolver
                    .lookup_ip(addr)
                    .await
                    .map_err(|e| Error::Eor(anyhow::anyhow!("loop ip domain: {},error: {:?}", &addr, e)))?;

                // There can be many addresses associated with the name,
                //  this can return IPv4 and/or IPv6 addresses
                let ip = response.iter().next().ok_or(Error::Eor(anyhow::anyhow!("cant lookup domain: {}", &addr)))?;

                let socket = SocketAddr::new(ip, *port);
                Ok(to_ipv6_address(&socket))
            }
        }
    }

    pub async fn to_socket_addr(&self, resolver: &Arc<AsyncStdResolver>) -> Result<SocketAddr> {
        match self {
            Address::SocketAddress(addr) => Ok(*addr),

            Address::DomainNameAddress(ref addr, ref port) => {
                let response = resolver
                    .lookup_ip(addr)
                    .await
                    .map_err(|e| Error::Eor(anyhow::anyhow!("loop ip domain: {},error: {:?}", &addr, e)))?;

                // There can be many addresses associated with the name,
                //  this can return IPv4 and/or IPv6 addresses
                let ip = response.iter().next().ok_or(Error::Eor(anyhow::anyhow!("cant lookup domain: {}", &addr)))?;

                let socket = SocketAddr::new(ip, *port);
                Ok(socket)
            }
        }
    }
}

impl Debug for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port)
        }
    }
}

impl fmt::Display for Address {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Address::SocketAddress(ref addr) => write!(f, "{}", addr),
            Address::DomainNameAddress(ref addr, ref port) => write!(f, "{}:{}", addr, port)
        }
    }
}
impl From<SocketAddr> for Address {
    fn from(s: SocketAddr) -> Address {
        Address::SocketAddress(s)
    }
}
