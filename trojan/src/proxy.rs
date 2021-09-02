use crate::{load_certs, load_keys, Address};
use async_std::{
    net::{TcpListener, TcpStream, UdpSocket},
    task::spawn
};
use async_tls::{server::TlsStream, TlsAcceptor};
use bytes::BufMut;
use errors::{Error, Result};
use futures_util::{
    future::Either, io::AsyncReadExt, stream::StreamExt, AsyncRead, AsyncWrite, AsyncWriteExt, FutureExt
};
use log::{debug, error, info};
use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc
};

use futures_lite::io::copy;
use rustls::{NoClientAuth, ServerConfig};
// use futures_lite::AsyncWriteExt;
// use glommio::{
//     channels::shared_channel::{SharedReceiver, SharedSender},
//     net::{TcpListener, TcpStream, UdpSocket},
//     Local
// };

#[derive(Clone)]
pub struct ProxyBuilder {
    addr: String,
    key: String,
    cert: String,
    authenticator: Vec<String>,
    fallback: String
}


impl ProxyBuilder {
    pub fn new(addr: String, key: String, cert: String, authenticator: Vec<String>, fallback: String) -> Self {
        Self { addr, key, cert, authenticator, fallback }
    }

    pub async fn start(self, mut receiver: async_channel::Receiver<bool>) -> Result<()> {
        // let listener = TcpListener::bind(&self.addr).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
        let listener = TcpListener::bind(&self.addr).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
        info!("proxy started at: {}", self.addr);

        let certs = load_certs(self.cert.as_ref())?;
        let key = load_keys(self.key.as_ref())?;
        let verifier = NoClientAuth::new();
        let mut tls_config = ServerConfig::new(verifier);
        tls_config.set_single_cert(certs, key).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let mut tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let mut incoming = listener.incoming();
        use futures::select;
        // let mut receiver = receiver.into_stream();
        // let incoming_stream = incoming.next().fuse().or_else();
        // loop {
        //     select! {
        //         incoming_stream = incoming.next().fuse() => {
        //             let shared_authenticator = Arc::new(self.authenticator.clone());
        //             let acceptor = Arc::new(self.acceptor.clone());
        //             let fallback = self.fallback.clone();
        //             let incoming_stream = incoming_stream.unwrap().unwrap();
        //             Local::local(async move {
        //                 process_stream(acceptor.clone(), incoming_stream, shared_authenticator.clone(),
        // fallback.clone()).await             })
        //             .detach();
        //         },
        //         _ = receiver.next().fuse() =>{
        //             warn!("proxy process do exit");
        //             break
        //         }
        //     }
        // }
        loop {
            // let mut receiver = receiver.clone();
            select! {
                incoming_stream = incoming.next().fuse() =>  {
                    // Some(incoming_stream) =>{
                    let incoming_stream = incoming_stream.ok_or(Error::Eor(anyhow::anyhow!("got an empty incoming stream")))??;
                    spawn(process_stream(
                        tls_acceptor.clone(),
                        incoming_stream,
                        self.authenticator.clone(),
                        self.fallback.clone(),
                    ));
                    },
                _ = receiver.next().fuse() =>{
                    let certs = load_certs(self.cert.as_ref())?;
                    let key = load_keys(self.key.as_ref())?;
                    let verifier = NoClientAuth::new();
                    let mut tls_config = ServerConfig::new(verifier);
                    tls_config.set_single_cert(certs, key).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
                    tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
                    info!("tls config has been reloaded");
                }
            }
        }
        // while let Some(Ok(incoming_stream)) = incoming.next().await {
        //     // spawn(process_stream(
        //     //     acceptor,
        //     //     incoming_stream,
        //     //     shared_authenticator.clone(),
        //     //     self.fallback.clone(),
        //     // ));
        //     let shared_authenticator = Arc::new(self.authenticator.clone());
        //     let acceptor = Arc::new(self.acceptor.clone());
        //     let fallback = self.fallback.clone();
        //     Local::local(async move {
        //         process_stream(acceptor.clone(), incoming_stream, shared_authenticator.clone(),
        // fallback.clone()).await     })
        //     .detach();
        // }
        Ok(())
    }
}
/// start TLS stream at addr to target
// async fn process_stream(
//     acceptor: Arc<TlsAcceptor>, raw_stream: TcpStream, authenticator: Arc<Vec<String>>, fallback: String
// )
async fn process_stream(acceptor: TlsAcceptor, raw_stream: TcpStream, authenticator: Vec<String>, fallback: String) {
    let source = raw_stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_else(|_| "".to_owned());

    debug!("new connection from {}", source);

    let handshake = acceptor.accept(raw_stream).await;

    match handshake {
        Ok(inner_stream) => {
            debug!("handshake success from: {}", source);
            if let Err(err) = proxy(inner_stream, source.clone(), authenticator, fallback).await {
                error!("error processing tls: {:?} from source: {}", err, source);
            }
        }
        Err(err) => error!("error handshaking: {:?} from source: {}", err, source)
    }
}
const HASH_STR_LEN: usize = 56;

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```
///
/// ```plain
/// +------+----------+----------+--------+---------+----------+
/// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
/// +------+----------+----------+--------+---------+----------+
/// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
/// +------+----------+----------+--------+---------+----------+
/// ```
pub struct UdpAssociateHeader {
    pub addr: Address,
    pub payload_len: u16
}

impl UdpAssociateHeader {
    #[inline]
    pub fn new(addr: &Address, payload_len: usize) -> Self {
        Self { addr: addr.clone(), payload_len: payload_len as u16 }
    }

    pub async fn read_from<R>(stream: &mut R) -> Result<Self>
    where R: AsyncRead + Unpin {
        let addr = Address::read_from_stream(stream).await?;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        let len = ((buf[0] as u16) << 8) | (buf[1] as u16);
        stream.read_exact(&mut buf).await?;
        Ok(Self { addr, payload_len: len })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> Result<()>
    where W: AsyncWrite + Unpin {
        let mut buf = Vec::with_capacity(self.addr.serialized_len() + 2 + 1);
        let cursor = &mut buf;
        self.addr.write_to_buf(cursor);
        cursor.put_u16(self.payload_len);
        cursor.put_slice(b"\r\n");
        w.write_all(&buf).await?;
        Ok(())
    }
}
const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
async fn redirect_fallback(source: &str, target: &str, tls_stream: TlsStream<TcpStream>, buf: &[u8]) -> Result<()> {
    let mut tcp_stream = TcpStream::connect(target).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

    debug!("connect to fallback: {}", target);
    tcp_stream.write_all(buf).await?;

    let (mut target_stream, mut target_sink) = tcp_stream.split();
    let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();

    let s_t = format!("{}->{}", source.to_string(), target.to_string());
    let t_s = format!("{}->{}", target.to_string(), source.to_string());
    let source_to_target_ft = async move {
        match copy(&mut from_tls_stream, &mut target_sink).await {
            Ok(len) => {
                debug!("total {} bytes copied from source to target: {}", len, s_t);
            }
            Err(err) => {
                error!("{} error copying: {}", s_t, err);
            }
        }
        target_sink.close().await?;
        Ok::<(), Error>(())
    };

    let target_to_source_ft = async move {
        match copy(&mut target_stream, &mut from_tls_sink).await {
            Ok(len) => {
                debug!("total {} bytes copied from target: {}", len, t_s);
            }
            Err(err) => {
                error!("{} error copying: {}", t_s, err);
            }
        }
        from_tls_sink.close().await?;
        Ok::<(), Error>(())
    };
    futures::pin_mut!(source_to_target_ft);
    futures::pin_mut!(target_to_source_ft);
    // spawn(source_to_target_ft);
    // spawn(target_to_source_ft);
    let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
    match res {
        Either::Left((Err(e), fut_right)) => {
            debug!("udp copy to remote closed");
            std::mem::drop(fut_right);
            Err(anyhow::anyhow!("tcp proxy copy local to remote error: {:?}", e))?
        }
        Either::Right((Err(e), fut_left)) => {
            debug!("udp copy to local closed");
            std::mem::drop(fut_left);
            Err(anyhow::anyhow!("tcp proxy copy remote to local error: {:?}", e))?
        }
        Either::Left((Ok(_), fut_right)) => {
            std::mem::drop(fut_right);
        }
        Either::Right((Ok(_), fut_left)) => {
            std::mem::drop(fut_left);
        }
    };
    Ok(())
}
// async fn proxy(
//     mut tls_stream: TlsStream<TcpStream>, source: String, authenticator: Arc<Vec<String>>, fallback: String
// )
async fn proxy(
    mut tls_stream: TlsStream<TcpStream>, source: String, authenticator: Vec<String>, fallback: String
) -> Result<()> {
    let mut passwd_buf = [0u8; HASH_STR_LEN];
    let len = tls_stream.read(&mut passwd_buf).await?;
    if len != HASH_STR_LEN {
        // first_packet.extend_from_slice(&hash_buf[..len]);
        error!("first packet too short");
        redirect_fallback(&source, &fallback, tls_stream, &passwd_buf).await?;

        return Err(Error::Eor(anyhow::anyhow!("first packet too short")))
    }
    debug!("received client passwd: {:?}", String::from_utf8_lossy(&passwd_buf).to_string());
    if !authenticator.contains(&String::from_utf8_lossy(&passwd_buf).to_string()) {
        debug!("authentication failed, dropping connection");
        redirect_fallback(&source, &fallback, tls_stream, &passwd_buf).await?;
        return Err(Error::Eor(anyhow::anyhow!("authenticate failed")))
    } else {
        debug!("authentication succeeded");
    }
    let mut crlf_buf = [0u8; 2];
    let mut cmd_buf = [0u8; 1];

    tls_stream.read_exact(&mut crlf_buf).await?;
    tls_stream.read_exact(&mut cmd_buf).await?;
    let addr = Address::read_from_stream(&mut tls_stream).await?;
    tls_stream.read_exact(&mut crlf_buf).await?;

    match cmd_buf[0] {
        CMD_TCP_CONNECT => {
            debug!("TcpConnect target addr: {:?}", addr);

            let tcp_stream =
                TcpStream::connect(addr.to_string()).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

            debug!("connect to target: {} from source: {}", addr, source);

            let (mut target_stream, mut target_sink) = tcp_stream.split();
            let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();

            let s_t = format!("{}->{}", source, addr.to_string());
            let t_s = format!("{}->{}", addr.to_string(), source);
            let source_to_target_ft = async {
                match copy(&mut from_tls_stream, &mut target_sink).await {
                    Ok(len) => {
                        debug!("total {} bytes copied from source to target: {}", len, s_t);
                    }
                    Err(err) => {
                        error!("{} error copying: {}", s_t, err);
                    }
                }
                target_sink.close().await?;
                Ok::<(), Error>(())
            };

            let target_to_source_ft = async {
                match copy(&mut target_stream, &mut from_tls_sink).await {
                    Ok(len) => {
                        debug!("total {} bytes copied from target: {}", len, t_s);
                    }
                    Err(err) => {
                        error!("{} error copying: {}", t_s, err);
                    }
                }
                from_tls_sink.close().await?;
                Ok::<(), Error>(())
            };
            futures::pin_mut!(source_to_target_ft);
            futures::pin_mut!(target_to_source_ft);
            // spawn(source_to_target_ft);
            // spawn(target_to_source_ft);
            let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
            match res {
                Either::Left((Err(e), fut_right)) => {
                    debug!("udp copy to remote closed");
                    std::mem::drop(fut_right);
                    Err(anyhow::anyhow!("tcp proxy copy local to remote error: {:?}", e))?
                }
                Either::Right((Err(e), fut_left)) => {
                    debug!("udp copy to local closed");
                    std::mem::drop(fut_left);
                    Err(anyhow::anyhow!("tcp proxy copy remote to local error: {:?}", e))?
                }
                Either::Left((Ok(_), fut_right)) => {
                    std::mem::drop(fut_right);
                }
                Either::Right((Ok(_), fut_left)) => {
                    std::mem::drop(fut_left);
                }
            };
            // Ok(RequestHeader::TcpConnect(hash_buf, addr))
        }
        CMD_UDP_ASSOCIATE => {
            debug!("UdpAssociate target addr: {:?}", addr);

            const RELAY_BUFFER_SIZE: usize = 0x4000;
            // let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
            //     .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
                .await
                .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            let (mut tls_stream_reader, mut tls_stream_writer) = tls_stream.split();

            let client_to_server = Box::pin(async {
                let mut buf = [0u8; RELAY_BUFFER_SIZE];
                loop {
                    error!("client_to_server never end");
                    let header = UdpAssociateHeader::read_from(&mut tls_stream_reader).await?;
                    if header.payload_len == 0 {
                        break
                    }

                    tls_stream_reader.read_exact(&mut buf[..header.payload_len as usize]).await?;

                    match outbound.send_to(&buf[..header.payload_len as usize], header.addr.to_string()).await {
                        Ok(n) => {
                            debug!("udp copy to remote: {} bytes", n);
                            if n == 0 {
                                break
                            }
                        }
                        Err(e) => {
                            error!("udp send to upstream error: {:?}", e);
                            break
                        }
                    }
                }
                std::mem::drop(buf);
                Ok(()) as Result<()>
            })
            .fuse();
            let server_to_client = Box::pin(async {
                let mut buf = [0u8; RELAY_BUFFER_SIZE];
                loop {
                    error!("server_to_client never end");
                    let (len, dst) =
                        outbound.recv_from(&mut buf).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
                    if len == 0 {
                        break
                    }
                    let header = UdpAssociateHeader::new(&Address::from(dst), len);
                    header.write_to(&mut tls_stream_writer).await?;
                    tls_stream_writer.write_all(&buf[..len]).await?;
                    debug!("udp copy to client: {} bytes", len);
                }
                tls_stream_writer.flush().await?;
                tls_stream_writer.close().await?;
                std::mem::drop(buf);
                Ok(()) as Result<()>
            })
            .fuse();
            let res = futures::future::select(client_to_server, server_to_client).await;
            match res {
                Either::Left((Err(e), fut_right)) => {
                    debug!("udp copy to remote closed");
                    std::mem::drop(fut_right);
                    Err(anyhow::anyhow!("UdpAssociate copy local to remote error: {:?}", e))?
                }
                Either::Right((Err(e), fut_left)) => {
                    debug!("udp copy to local closed");
                    std::mem::drop(fut_left);
                    Err(anyhow::anyhow!("UdpAssociate copy remote to local error: {:?}", e))?
                }
                Either::Left((Ok(_), fut_right)) => {
                    std::mem::drop(fut_right);
                }
                Either::Right((Ok(_), fut_left)) => {
                    std::mem::drop(fut_left);
                }
            };

            // Ok(RequestHeader::UdpAssociate(hash_buf))
        }
        _ => {
            error!("cant decode incoming stream");
            // Err(Error::Eor(anyhow::anyhow!("invalid command")))
        }
    };
    Ok(())
}
