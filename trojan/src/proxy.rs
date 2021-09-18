#![allow(unreachable_code)]
use crate::{load_certs, load_keys, tcp, Address};
use async_std::{
    future::timeout,
    net::{TcpListener, TcpStream, UdpSocket},
    task::sleep
};
use async_tls::{server::TlsStream, TlsAcceptor};
use bytes::BufMut;
use errors::{Error, Result};
use smolscale::spawn;
// use futures_lite::io::copy;
use async_std::sync::Mutex;
use futures::{
    channel::mpsc,
    io::{ReadHalf, WriteHalf}
};
use futures_util::{
    future::Either, io::AsyncReadExt, stream::StreamExt, AsyncRead, AsyncWrite, AsyncWriteExt, FutureExt
};
use heapless::Vec as StackVec;
use log::{debug, error, info};
use lru_time_cache::LruCache;
use rustls::{NoClientAuth, ServerConfig};
use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs},
    sync::Arc,
    time::Duration
};
use once_cell::sync::Lazy;
use std::net::{SocketAddrV4, Ipv4Addr};


static UNSPECIFIED: Lazy<SocketAddr> =
    Lazy::new(|| SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));

cfg_if::cfg_if! {
    if #[cfg(wss)] {
        use ws_stream_tungstenite::WsStream as AsyncWsStream;
        use crate::ws::WsStream,

    }
}
// use futures_lite::AsyncWriteExt;
// use glommio::{
//     channels::shared_channel::{SharedReceiver, SharedSender},
//     net::{TcpListener, TcpStream, UdpSocket},
//     Local
// };


type AssociationMap<T> = LruCache<Address, WriteHalf<T>>;
type SharedAssociationMap<T> = Arc<Mutex<AssociationMap<T>>>;

#[derive(Clone)]
pub struct ProxyBuilder<T> {
    addr: String,
    key: String,
    cert: String,
    authenticator: Vec<String>,
    fallback: String,
    udp_associate: SharedAssociationMap<T>
}
#[inline]
fn to_ipv6_address(addr: &SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(ref a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
        SocketAddr::V6(ref a) => *a
    }
}

async fn udp_downstream<T>(udp_socket: Arc<UdpSocket>, udp_associate: Arc<Mutex<AssociationMap<T>>>) -> Result<()>
where T: AsyncWrite
{
    // let mut buf = [0u8; RELAY_BUFFER_SIZE];
    let mut buf: StackVec<u8, 65535> = StackVec::new();
    buf.resize(65535, 0);

    loop {
        match timeout(std::time::Duration::from_secs(15), async {
            let (len, dst) = udp_socket.recv_from(&mut buf).await?;
            // if len == 0 {
            //     break
            // }
            Ok((len, dst)) as Result<(usize, SocketAddr)>
            // (len,dst)
        })
        .await?
        {
            Ok((len, dst)) => {
                if len == 0 {
                    break
                }

                let mut udps = udp_associate.lock().await;
                // let dst = to_ipv6_address(&dst);
                let mut is_err: bool = false;

                if let Some(mut write_half) = udps.get_mut(&dst) {
                    let header = UdpAssociateHeader::new(&Address::from(dst), len);
                    header.write_to(&mut write_half).await.map_err(|e| {
                        is_err = true;
                        e
                    })?;
                    write_half.write_all(&buf[..len]).await.map_err(|e| {
                        is_err = true;
                        e
                    })?;
                    debug!("udp copy to client: {} bytes", len);
                }
                if is_err{
                    udps.remove(&dst);
                }
            }
            Err(e) => {
                error!("reading client socket timeout:{:?}", e);
                break
            }
        }
    }
    Ok(()) as Result<()>
}


async fn udp_upstream<T>(mut inbound: ReadHalf<T>, outbound: Arc<UdpSocket>) -> Result<()>
where T: AsyncRead
{
    let mut buf: StackVec<u8, 65535> = StackVec::new();

    loop {
        // let mut buf = [0u8; RELAY_BUFFER_SIZE];
        let mut buf: StackVec<u8, 65535> = StackVec::new();
        // buf.resize(RELAY_BUFFER_SIZE, 0);

        loop {
            // error!("client_to_server never end");
            let header = UdpAssociateHeader::read_from(&mut inbound).await?;
            if header.payload_len == 0 {
                break
            }
            buf.resize(header.payload_len as usize, 0);

            // tls_stream_reader.read_exact(&mut buf[..header.payload_len as usize]).await?;

            match timeout(std::time::Duration::from_secs(5), async {
                inbound.read_exact(&mut buf[..header.payload_len as usize]).await?;
                Ok(()) as Result<()>
            })
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    error!("reading client socket timeout:{:?}", e);
                    break
                }
            }

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
    }
    std::mem::drop(buf);
    Ok(()) as Result<()>
}

impl <T>ProxyBuilder<T>
where T: AsyncWrite + Send + 'static
{
    pub async fn new(
        addr: String, key: String, cert: String, authenticator: Vec<String>, fallback: String, time_to_live: Duration,udp_socket: Arc<UdpSocket>
    ) -> Result<Self> {
        let udp_associate = Arc::new(Mutex::new(LruCache::with_expiry_duration(time_to_live)));



        let downstream_associate = udp_associate.clone();
        spawn(async move {
            udp_downstream(udp_socket.clone(),downstream_associate ).await?;
            Ok(()) as Result<()>
        })
            .detach();


        let (keepalive_tx, mut keepalive_rx) = mpsc::channel(256);

        // let keepalive_abortable = {
        //     let assoc_map = udp_associate.clone();
        //     spawn(async move {
        //         while let Some(peer_addr) = keepalive_rx.next().await {
        //             assoc_map.lock().await.get(&peer_addr);
        //         }
        //     })
        //         .detach()
        // };


        let keepalive_abortable = {
            let assoc_map = udp_associate.clone();
            spawn(async move {
                while let Some(peer_addr) = keepalive_rx.next().await {
                    assoc_map.lock().await.get(&peer_addr);
                }
            })
                .detach()
        };


        Ok(Self { addr, key, cert, authenticator, fallback, udp_associate })
    }

    pub async fn start(self, mut receiver: async_channel::Receiver<bool>) -> Result<()> {
        // let listener = TcpListener::bind(&self.addr).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
        // let addr: SocketAddr = self.addr
        //     .parse()
        //     .expect("Unable to parse socket address");

        // let ipv6 = to_ipv6_address(addr);
        // use socket2::{Domain, Socket, Type};
        // let socket = Socket::new(Domain::ipv6(), Type::stream(), None)?;
        // socket.set_only_v6(false)?;
        // socket.set_nonblocking(true)?;
        // socket.set_read_timeout(Some(Duration::from_secs(60)))?;
        // socket.set_write_timeout(Some(Duration::from_secs(60)))?;
        // socket.set_linger(Some(Duration::from_secs(10)))?;
        // socket.set_keepalive(Some(Duration::from_secs(60)))?;
        // socket.bind(&ipv6.into())?;
        // socket.listen(128)?;
        // let listener = TcpListener::from(socket.into_tcp_listener());


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

        spawn(async {}).detach();


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
                        self.udp_associate.clone()
                    )).detach();
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
async fn process_stream<T>(acceptor: TlsAcceptor, raw_stream: TcpStream, authenticator: Vec<String>, fallback: String,udp_associate: SharedAssociationMap<T>) {
    let source = raw_stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_else(|_| "".to_owned());

    debug!("new connection from {}", source);

    let handshake = acceptor.accept(raw_stream).await;

    match handshake {
        Ok(inner_stream) => {
            #[cfg(feature = "wss")]
            let inner_stream = WsStream::<TlsStream<TcpStream>>(AsyncWsStream::new(
                async_tungstenite::accept_async(inner_stream).await.expect("cannot accept websockets connection")
            ));

            debug!("handshake success from: {}", source);
            if let Err(err) = proxy(inner_stream, source.clone(), authenticator, fallback,udp_associate).await {
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
const READ_TIMEOUT_WHEN_ONE_SHUTDOWN: std::time::Duration = std::time::Duration::from_secs(5);

async fn redirect_fallback<#[cfg(feature = "wss")] S: AsyncRead + AsyncWrite + Unpin + Send>(
    source: &str, target: &str, #[cfg(not(feature = "wss"))] mut tls_stream: TlsStream<TcpStream>,
    #[cfg(feature = "wss")] mut tls_stream: WsStream<S>, buf: &[u8]
) -> Result<()> {
    let mut tcp_stream = TcpStream::connect(target).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

    debug!("connect to fallback: {}", target);
    tcp_stream.write_all(buf).await?;

    let copy_future = tcp::CopyFuture::new(tls_stream, tcp_stream, Duration::from_secs(5));

    copy_future.await?;


    // let (mut target_stream, mut target_sink) = tcp_stream.split();
    // let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();
    //
    // let s_t = format!("{}->{}", source.to_string(), target.to_string());
    // let t_s = format!("{}->{}", target.to_string(), source.to_string());
    // let source_to_target_ft = async move {
    //     match copy(&mut from_tls_stream, &mut target_sink).await {
    //         Ok(len) => {
    //             debug!("total {} bytes copied from source to target: {}", len, s_t);
    //             Ok(())
    //         }
    //         Err(err) => {
    //             error!("{} error copying: {}", s_t, err);
    //             target_sink.close().await?;
    //             Err(err)
    //         }
    //     }
    // };
    //
    // let target_to_source_ft = async move {
    //     match copy(&mut target_stream, &mut from_tls_sink).await {
    //         Ok(len) => {
    //             debug!("total {} bytes copied from target: {}", len, t_s);
    //             Ok(())
    //         }
    //         Err(err) => {
    //             error!("{} error copying: {}", t_s, err);
    //             from_tls_sink.close().await?;
    //             Err(err)
    //         }
    //     }
    // };
    // futures::pin_mut!(source_to_target_ft);
    // futures::pin_mut!(target_to_source_ft);
    // // spawn(source_to_target_ft);
    // // spawn(target_to_source_ft);
    // let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
    // match res {
    //     Either::Left((Err(e), fut_right)) => {
    //         debug!("udp copy to remote closed");
    //         // std::mem::drop(fut_right);
    //         let _ = timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
    //             fut_right.await;
    //             Ok(()) as Result<()>
    //         })
    //         .await;
    //         Err(anyhow::anyhow!("tcp proxy copy local to remote error: {:?}", e))?
    //     }
    //     Either::Right((Err(e), fut_left)) => {
    //         debug!("udp copy to local closed");
    //         std::mem::drop(fut_left);
    //         Err(anyhow::anyhow!("tcp proxy copy remote to local error: {:?}", e))?
    //     }
    //     Either::Left((Ok(_), right_fut)) => {
    //         timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
    //             right_fut.await;
    //             Ok(()) as Result<()>
    //         })
    //         .await
    //     }
    //     Either::Right((Ok(_), left_fut)) => {
    //         timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
    //             left_fut.await;
    //             Ok(()) as Result<()>
    //         })
    //         .await
    //     }
    // };
    Ok(())
}
// async fn proxy(
//     mut tls_stream: TlsStream<TcpStream>, source: String, authenticator: Arc<Vec<String>>, fallback: String
// )
async fn proxy<T,#[cfg(feature = "wss")] S: AsyncRead + AsyncWrite + Unpin + Send>(
    #[cfg(not(feature = "wss"))] mut tls_stream: TlsStream<TcpStream>,
    #[cfg(feature = "wss")] mut tls_stream: WsStream<S>, source: String, authenticator: Vec<String>, fallback: String,
    udp_associate: SharedAssociationMap<T>,
) -> Result<()> {
    let mut passwd_buf: StackVec<u8, HASH_STR_LEN> = StackVec::new();
    passwd_buf.resize(HASH_STR_LEN, 0);

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
    // let mut crlf_buf = [0u8; 2];
    // let mut cmd_buf = [0u8; 1];

    let mut crlf_buf: StackVec<u8, 2> = StackVec::new();
    crlf_buf.resize(2, 0);

    let mut cmd_buf: StackVec<u8, 1> = StackVec::new();
    cmd_buf.resize(1, 0);

    tls_stream.read_exact(&mut crlf_buf).await?;
    tls_stream.read_exact(&mut cmd_buf).await?;
    let addr = Address::read_from_stream(&mut tls_stream).await?;
    tls_stream.read_exact(&mut crlf_buf).await?;

    match cmd_buf[0] {
        CMD_TCP_CONNECT => {
            debug!("TcpConnect target addr: {:?}", addr);

            let mut tcp_stream =
                TcpStream::connect(addr.to_string()).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

            // let mut target_stream = tcp_stream.clone();
            // let mut target_sink = tcp_stream.clone();

            debug!("connect to target: {} from source: {}", addr, source);

            // use crate::deplex::Duplex;
            // let duplex = Duplex::new(tls_stream,tcp_stream);
            // duplex.await?;

            // let (mut target_stream, mut target_sink) = tcp_stream.split();
            // let tls_inner = tls_stream.io.clone();
            // let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();

            let copy_future = tcp::CopyFuture::new(tls_stream, tcp_stream, Duration::from_secs(5));

            copy_future.await?;

            // let s_t = format!("{}->{}", source, addr.to_string());
            // let t_s = format!("{}->{}", addr.to_string(), source);
            // let source_to_target_ft = async {
            //     match copy(&mut target_stream, &mut from_tls_sink).await {
            //         Ok(len) => {
            //             debug!("total {} bytes copied from source to target: {}", len, s_t);
            //         }
            //         Err(err) => {
            //             error!("{} error copying: {}", s_t, err);
            //         }
            //     }
            //     from_tls_sink.close().await?;
            //     Ok(()) as Result<()>
            // };
            //
            // let target_to_source_ft = async {
            //     match copy(&mut from_tls_stream, &mut target_sink).await {
            //         Ok(len) => {
            //             debug!("total {} bytes copied from target: {}", len, t_s);
            //         }
            //         Err(err) => {
            //             error!("{} error copying: {}", t_s, err);
            //         }
            //     }
            //     // tcp_stream.close().await?;
            //     Ok(()) as Result<()>
            // };
            // futures::pin_mut!(source_to_target_ft);
            // futures::pin_mut!(target_to_source_ft);
            // // spawn(source_to_target_ft);
            // // spawn(target_to_source_ft);
            // let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
            // match res {
            //     Either::Left((Err(e), fut_right)) => {
            //         debug!("udp copy to remote closed");
            //         std::mem::drop(fut_right);
            //         // let _ = timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
            //         //     fut_right.await;
            //         //     Ok(()) as Result<()>
            //         // })
            //         //     .await;
            //         Err(anyhow::anyhow!("tcp proxy copy local to remote error: {:?}", e))?
            //     }
            //     Either::Right((Err(e), fut_left)) => {
            //         debug!("udp copy to local closed");
            //         std::mem::drop(fut_left);
            //         // timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
            //         //     fut_left.await;
            //         //     Ok(()) as Result<()>
            //         // })
            //         //     .await;
            //         Err(anyhow::anyhow!("tcp proxy copy remote to local error: {:?}", e))?
            //     }
            //     Either::Left((Ok(_), right_fut)) => {
            //         timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
            //             right_fut.await?;
            //             Ok(()) as Result<()>
            //         })
            //             .await
            //     },
            //     Either::Right((Ok(_), left_fut)) => {
            //         timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
            //             left_fut.await?;
            //             Ok(()) as Result<()>
            //         })
            //             .await
            //     }
            // };
            // use std::net::Shutdown;
            // tcp_stream.shutdown(Shutdown::Both)?;
            // tls_inner.shutdown(Shutdown::Both)?;

            // Ok(RequestHeader::TcpConnect(hash_buf, addr))
        }
        CMD_UDP_ASSOCIATE => {
            debug!("UdpAssociate target addr: {:?}", addr);

            let (mut tls_stream_reader, mut tls_stream_writer) = tls_stream.split();

            let cached = {
                if addr == *UNSPECIFIED {
                    Some(tls_stream_writer)
                } else {
                    // let addr = to_ipv6_address(&addr);
                    let mut udp_pairs = udp_associate.lock().await;
                    if udp_pairs.contains_key(&addr) {
                        Some(tls_stream_writer)
                    } else {
                        udp_pairs.insert(addr, tls_stream_writer);
                        None
                    }
                }
            };
            if cached {
                udp_upstream(tls_stream_reader).await?;
                return
            }


            const RELAY_BUFFER_SIZE: usize = 0x4000;
            // let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
            //     .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
                .await
                .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            // let tls_inner = tls_stream;

            let client_to_server = async {
                // let mut buf = [0u8; RELAY_BUFFER_SIZE];
                let mut buf: StackVec<u8, 65535> = StackVec::new();
                // buf.resize(RELAY_BUFFER_SIZE, 0);

                loop {
                    // error!("client_to_server never end");
                    let header = UdpAssociateHeader::read_from(&mut tls_stream_reader).await?;
                    if header.payload_len == 0 {
                        break
                    }
                    buf.resize(header.payload_len as usize, 0);

                    // tls_stream_reader.read_exact(&mut buf[..header.payload_len as usize]).await?;

                    match timeout(std::time::Duration::from_secs(5), async {
                        tls_stream_reader.read_exact(&mut buf[..header.payload_len as usize]).await?;
                        Ok(()) as Result<()>
                    })
                    .await
                    {
                        Ok(_) => {}
                        Err(e) => {
                            error!("reading client socket timeout:{:?}", e);
                            break
                        }
                    }

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
            };
            let server_to_client = async {
                // let mut buf = [0u8; RELAY_BUFFER_SIZE];
                let mut buf: StackVec<u8, 65535> = StackVec::new();
                buf.resize(65535, 0);

                loop {
                    // let (len, dst) = outbound.recv_from(&mut buf).await?;
                    //
                    // if len == 0 {
                    //     break
                    // }
                    // let header = UdpAssociateHeader::new(&Address::from(dst), len);
                    // header.write_to(&mut tls_stream_writer).await?;
                    // tls_stream_writer.write_all(&buf[..len]).await?;
                    // debug!("udp copy to client: {} bytes", len);

                    match timeout(std::time::Duration::from_secs(15), async {
                        let (len, dst) = outbound.recv_from(&mut buf).await?;
                        // if len == 0 {
                        //     break
                        // }
                        Ok((len, dst)) as Result<(usize, SocketAddr)>
                        // (len,dst)
                    })
                    .await?
                    {
                        Ok((len, dst)) => {
                            if len == 0 {
                                break
                            }
                            let header = UdpAssociateHeader::new(&Address::from(dst), len);
                            header.write_to(&mut tls_stream_writer).await?;
                            tls_stream_writer.write_all(&buf[..len]).await?;
                            debug!("udp copy to client: {} bytes", len);
                        }
                        Err(e) => {
                            error!("reading client socket timeout:{:?}", e);
                            break
                        }
                    }
                }
                tls_stream_writer.flush().await?;
                tls_stream_writer.close().await?;
                std::mem::drop(buf);
                Ok(()) as Result<()>
            };

            futures::pin_mut!(client_to_server);
            futures::pin_mut!(server_to_client);

            let res = futures::future::select(client_to_server, server_to_client).await;
            match res {
                Either::Left((Err(e), fut_right)) => {
                    debug!("udp copy to remote closed");
                    std::mem::drop(fut_right);
                    // timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
                    //     fut_right.await;
                    //     Ok(()) as Result<()>
                    // })
                    //     .await;
                    Err(anyhow::anyhow!("UdpAssociate copy local to remote error: {:?}", e))?
                }
                Either::Right((Err(e), fut_left)) => {
                    debug!("udp copy to local closed");
                    std::mem::drop(fut_left);
                    // timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
                    //     fut_left.await;
                    //     Ok(()) as Result<()>
                    // })
                    //     .await;
                    Err(anyhow::anyhow!("UdpAssociate copy remote to local error: {:?}", e))?
                }
                Either::Left((Ok(_), fut_right)) => {
                    timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
                        fut_right.await?;
                        Ok(()) as Result<()>
                    })
                    .await
                }
                Either::Right((Ok(_), fut_left)) => {
                    timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
                        fut_left.await?;
                        Ok(()) as Result<()>
                    })
                    .await
                }
            };
            // use std::net::Shutdown;
            // tls_inner.shutdown(Shutdown::Both)?;
            // Ok(RequestHeader::UdpAssociate(hash_buf))
        }
        _ => {
            error!("cant decode incoming stream");
            // Err(Error::Eor(anyhow::anyhow!("invalid command")))
        }
    };
    Ok(())
}
