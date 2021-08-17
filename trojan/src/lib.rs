pub mod config;
mod copy;
mod proxy;
use anyhow::anyhow;
use bytes::{Buf, BufMut};
use errors::{Error, Result};
use futures::{AsyncRead, AsyncReadExt};
use hex::encode;
pub use proxy::*;
use rustls::{
    internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys},
    Certificate, PrivateKey
};
use sha2::{Digest, Sha224};
use std::{
    fmt,
    fmt::{Debug, Formatter},
    fs::File,
    io::{BufReader, Cursor},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::Path
};

pub fn load_certs(path: &Path) -> Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?)).map_err(|_| Error::Eor(anyhow!("could not find carts")))
}

#[macro_export]
macro_rules! key {
    ($e:expr,$p:ident) => {
        let reader = &mut BufReader::new(File::open($p)?);
        if let Ok(mut keys) = $e(reader) {
            if !keys.is_empty() {
                return Ok(keys.remove(0))
            }
        }
    };
}
pub fn load_keys(path: &Path) -> Result<PrivateKey> {
    key!(pkcs8_private_keys, path);
    key!(rsa_private_keys, path);
    Err(Error::Eor(anyhow::anyhow!("invalid key")))
}

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

/// the following code copy from
/// https://github.com/p4gefau1t/trojan-r/blob/main/src/protocol/mod.rs
#[derive(Clone, PartialEq, Eq, Hash)]
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
