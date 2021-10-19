#![allow(unreachable_code)]
use crate::{tcp, Address, Connection, SessionMessage, RELAY_BUFFER_SIZE, to_ipv6_address};
// use async_std::{
//     future::timeout,
//     net::{TcpListener, TcpStream, UdpSocket},
//     task::{spawn}
// };

// use async_std::sync::Mutex;
use async_std_resolver::{config, resolver, AsyncStdResolver};
// use async_tls::{server::TlsStream, TlsAcceptor};
use bytes::BufMut;
use errors::{Error, Result};
use futures::{channel::oneshot, io::WriteHalf, select};
use futures_util::{
    future::Either, io::AsyncReadExt, stream::StreamExt, AsyncRead, AsyncWrite, AsyncWriteExt, FutureExt, SinkExt
};
use glommio::{
    net::{TcpListener, TcpStream, UdpSocket},
    spawn_local
};
use heapless::Vec as StackVec;
use log::{debug, error, info};
use lru_time_cache::{LruCache, TimedEntry};
use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    ops::Add,
    sync::Arc,
    time::Duration
};
use std::str::FromStr;
use futures_rustls::{TlsAcceptor, server::TlsStream};
use crate::config::Config;
use crate::tls::make_config;
// use async_std::net::{TcpStream, UdpSocket,TcpListener};
// use socket2::{Domain, Socket, Type};

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

#[derive(Clone)]
pub struct ProxyBuilder {
    addr: String,
    key: String,
    cert: String,
    authenticator: Vec<String>,
    fallback: String
}


impl ProxyBuilder {
    pub fn new(
        addr: String, key: String, cert: String, authenticator: Vec<String>, fallback: String, time_to_live: Duration,
        mut connection_activity_rx: futures::channel::mpsc::Receiver<SessionMessage>
    ) -> Result<Self> {
        spawn_local(async move {
            // let mut inter = interval(time_to_live.add(Duration::from_secs(45)));
            // inter.set_missed_tick_behavior(MissedTickBehavior::Burst);

            use async_io::Timer;
            let mut timer = Timer::interval(time_to_live.add(Duration::from_secs(45)));

            let mut endpoint: LruCache<SocketAddr, Connection> =
                LruCache::with_expiry_duration_and_capacity(time_to_live, u16::MAX as usize);

            use crate::SessionMessage::{DisConnected, KeepLive, NewPeer};

            loop {
                select! {
                    _ = timer.next().fuse() => {
                        let mut expired = endpoint
                            .notify_iter()
                            .filter_map(|entry| {
                                match entry {
                                    TimedEntry::Expired(key, value) => Some((key, value)),
                                    _ => None
                                }
                            })
                            .collect::<Vec<_>>();
                        let remains = endpoint.len();
                        error!("expired connections  num: {}",expired.len());
                        while let Some((_k,  mut w)) = expired.pop() {
                            // if w.is_some() {
                            error!("starting to terminate task from client connection: {:?}",&w.addr);
                            std::mem::drop(w.terminator);
                            // w.stream.close().await?;
                            // let _ = w.task.await.map_err(|e|{
                            //     error!("wait task exit error: {:?}",e);
                            //     Error::Eor(anyhow::anyhow!("{:?}",e))
                            // })?;
                            // w.task.abort();

                            error!("task terminated from client connection: {:?}",&w.addr)
                            // }
                        }
                        error!("connections remained num: {}",remains);
                    },
                    session =  connection_activity_rx.next().fuse() =>{
                        if session.is_some(){
                        let session = session.unwrap();
                            match session {
                                NewPeer(connection) => {
                                    if endpoint.contains_key(&connection.addr){
                                        endpoint.get(&connection.addr);
                                    }else {
                                        endpoint.insert(connection.addr, connection);
                                    }
                                },
                                KeepLive(addr)=>{
                                      match endpoint.get(&addr){
                                        Some(_connection) =>{
                                            // error!("keepalive session message from {} -- {}",&addr,&connection.addr)
                                        },
                                        None =>{
                                            error!("keepalive session message invalid {}",&addr)
                                        }
                                    }
                                },
                                DisConnected(addr)=>{
                                      match endpoint.remove(&addr){
                                        Some(mut connection) =>{
                                            // error!("disconnected session message from {} -- {}",&addr,&connection.addr);
                                            std::mem::drop(connection.terminator);
                                            // connection.stream.close().await?;
                                            // let _= connection.task.await.map_err(|e|{
                                            //     error!("wait task exit error: {:?}",e);
                                            //     Error::Eor(anyhow::anyhow!("{:?}",e))
                                            // })?;
                                            error!("disconnected from client connection: {:?}",&connection.addr)
                                            // connection.task.abort();
                                        },
                                        None =>{
                                            error!("disconnected session message invalid {}",&addr)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(()) as Result<()>
        })
        .detach();
        Ok(Self { addr, key, cert, authenticator, fallback })
    }

    pub async fn start(
        self,
        config: &Config,
        mut receiver: async_channel::Receiver<bool>,
        mut connection_activity_tx: futures::channel::mpsc::Sender<SessionMessage>
    ) -> Result<()> {
        // let listener = TcpListener::bind(&self.addr).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
        // let addr: SocketAddr = self.addr.parse().expect("Unable to parse socket address");
        // let addr = SocketAddr::from_str(self.addr.as_ref())
        //     .map_err(|e| anyhow::anyhow!("unable to convert string ip:port to SocketAddr: {:?}", e))?;
        //
        // let ipv6 = to_ipv6_address(&addr);
        // let socket = Socket::new(Domain::ipv6(), Type::stream(), None)?;
        // socket.set_only_v6(false)?;
        // socket.set_nonblocking(true)?;
        // // socket.set_read_timeout(Some(Duration::from_secs(60)))?;
        // // socket.set_write_timeout(Some(Duration::from_secs(60)))?;
        // socket.set_reuse_address(true)?;
        // socket.set_reuse_port(true)?;
        // // socket.set_linger(Some(Duration::from_secs(10)))?;
        // // socket.set_keepalive(Some(Duration::from_secs(60 * 5)))?;
        // socket.bind(&ipv6.into())?;
        // socket.listen(8192)?;
        // use async_std::net::TcpListener;
        //
        // let listener = TcpListener::from(socket.into_tcp_listener());

        let listener = TcpListener::bind(&self.addr).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
        info!("proxy started at: {}", self.addr);

        let resolver = Arc::new(
            // for cloudflare dns, there is an issue: error notifying wait, possible future leak: TrySendError
            resolver(config::ResolverConfig::google(), config::ResolverOpts::default())
                .await
                .expect("failed to connect resolver")
        );


        let mut tls_config = make_config(config);

        let mut tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let mut incoming = listener.incoming();

        loop {
            // let mut receiver = receiver.clone();
            select! {
                incoming_stream = incoming.next().fuse() =>  {
                    // Some(incoming_stream) =>{
                    let incoming_stream = incoming_stream.ok_or(Error::Eor(anyhow::anyhow!("got an empty incoming stream")))?.map_err(|e|Error::Eor(anyhow::anyhow!("{:?}",e)))?;
                    let source = incoming_stream.peer_addr().map_err(|e|Error::Eor(anyhow::anyhow!("{:?}",e)))?;
                    let (terminator_tx, terminator_rx) = oneshot::channel();
                    let authenticator = self.authenticator.clone();
                    let fallback = self.fallback.clone();
                    let resolver = resolver.clone();
                    let mut connection_activity_loop_tx = connection_activity_tx.clone();
                    // let tcp_stream = incoming_stream.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let task =
                            spawn_local(
                                async move {
                                    let process = process_stream(
                                        tls_acceptor,
                                        incoming_stream,
                                        source,
                                        authenticator,
                                        fallback,
                                        resolver,
                                        connection_activity_loop_tx.clone()
                                    );
                                    let terminator = async {
                                        terminator_rx.await.map_err(|e|{
                                            error!("terminator received: {:?}",e);
                                            Error::Eor(anyhow::anyhow!("{:?}",e))
                                        })?;
                                        Ok(()) as Result<()>
                                    };

                                    futures::pin_mut!(terminator);
                                    futures::pin_mut!(process);

                                    match futures::future::select(process, terminator).await{
                                        Either::Left(_) => {
                                            connection_activity_loop_tx.send(SessionMessage::DisConnected(source)).await.map_err(|e| {
                                            log::error!("send disconnected message error: {:?}", e);
                                            Error::Eor(anyhow::anyhow!("{:?}", e))
                                            })?;
                                            error!("task exit from client connection processor: {:}",&source)
                                        },
                                        Either::Right(_) => {error!("task exit from client connection terminator: {:}",&source)},
                                    }
                                    Ok(()) as Result<()>
                                }
                            ).detach();

                        let conneccion = SessionMessage::NewPeer(Connection{
                                addr: source,
                                // task,
                                // stream: tcp_stream,
                                terminator: terminator_tx,
                        });
                        connection_activity_tx.send(conneccion).await.map_err(|e|{
                            error!("{}",e);
                            Error::Eor(anyhow::anyhow!("{:?}",e))
                        })?;
                    },
                _ = receiver.next().fuse() =>{
                    tls_config = make_config(config);;
                    tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
                    info!("tls config has been reloaded");
                }
            }
        }
        Ok(())
    }
}
/// start TLS stream at addr to target
// async fn process_stream(
//     acceptor: Arc<TlsAcceptor>, raw_stream: TcpStream, authenticator: Arc<Vec<String>>, fallback: String
// )
// const DEFAULT_BUFFER_SIZE: usize = 2 * 4096;

async fn process_stream(
    acceptor: TlsAcceptor, mut raw_stream: TcpStream, source: SocketAddr, authenticator: Vec<String>, fallback: String,
    resolver: Arc<AsyncStdResolver>, mut connection_activity_tx: futures::channel::mpsc::Sender<SessionMessage>
) -> Result<()> {
    // let source = raw_stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_else(|_| "".to_owned());
    //
    // debug!("new connection from {}", source);
    // let mut raw_stream_clone = raw_stream.clone();

    let handshake = acceptor.accept(raw_stream).await;

    // let  handshake = timeout(
    //     Duration::from_secs(5),
    //     acceptor.accept_with(raw_stream, |s| {
    //         s.set_buffer_limit(DEFAULT_BUFFER_SIZE);
    //     })
    // )
    // .await?
    // .map_err(|e| Error::Eor(anyhow::anyhow!("tls handshake within 5 secs: {:?}", e)));


    match handshake {
        Ok(inner_stream) => {
            #[cfg(feature = "wss")]
            let inner_stream = WsStream::<TlsStream<TcpStream>>(AsyncWsStream::new(
                async_tungstenite::accept_async(inner_stream).await.expect("cannot accept websockets connection")
            ));

            debug!("handshake success from: {}", source);
            match proxy(inner_stream, source, authenticator, fallback, resolver, connection_activity_tx).await {
                Ok(_) => Ok(()),
                Err(err) => {
                    error!("error processing tls: {:?} from source: {}", err, source);
                    Err(err)
                }
            }
        }
        Err(err) => {
            connection_activity_tx.send(SessionMessage::DisConnected(source)).await.map_err(|e| {
                log::error!("send disconnected message error: {:?}", e);
                Error::Eor(anyhow::anyhow!("{:?}", e))
            })?;
            error!("error handshaking: {:?} from source: {}", err, source);
            Err(Error::Eor(anyhow::anyhow!("{:?}", err)))
        }
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

async fn redirect_fallback<#[cfg(feature = "wss")] S: AsyncRead + AsyncWrite + Unpin + Send>(
    // source: &str,
    target: &str,
    #[cfg(not(feature = "wss"))] tls_stream: TlsStream<TcpStream>,
    #[cfg(feature = "wss")] mut tls_stream: WsStream<S>,
    buf: &[u8]
) -> Result<()> {
    let mut tcp_stream = TcpStream::connect(target).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

    debug!("connect to fallback: {}", target);
    tcp_stream.write_all(buf).await?;

    // let copy_future = tcp::CopyFuture::new(tls_stream, tcp_stream, Duration::from_secs(10));
    //
    // copy_future.await?;
    Ok(())
}
// async fn proxy(
//     mut tls_stream: TlsStream<TcpStream>, source: String, authenticator: Arc<Vec<String>>, fallback: String
// )
async fn proxy(
    #[cfg(not(feature = "wss"))] mut tls_stream: TlsStream<TcpStream>,
    #[cfg(feature = "wss")] mut tls_stream: WsStream<S>, source: SocketAddr, authenticator: Vec<String>,
    fallback: String, _resolver: Arc<AsyncStdResolver>,
    mut connection_activity_tx: futures::channel::mpsc::Sender<SessionMessage>
) -> Result<()> {
    let mut passwd_buf: StackVec<u8, HASH_STR_LEN> = StackVec::new();
    passwd_buf.resize(HASH_STR_LEN, 0).map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;

    let len = tls_stream.read(&mut passwd_buf).await?;
    if len != HASH_STR_LEN {
        error!("first packet too short");
        redirect_fallback(/* &source, */ &fallback, tls_stream, &passwd_buf).await?;

        return Err(Error::Eor(anyhow::anyhow!("first packet too short")))
    }
    debug!("received client passwd: {:?}", String::from_utf8_lossy(&passwd_buf).to_string());
    if !authenticator.contains(&String::from_utf8_lossy(&passwd_buf).to_string()) {
        debug!("authentication failed, dropping connection");
        redirect_fallback(/* &source, */ &fallback, tls_stream, &passwd_buf).await?;
        return Err(Error::Eor(anyhow::anyhow!("authenticate failed")))
    } else {
        debug!("authentication succeeded");
    }

    let mut crlf_buf: StackVec<u8, 2> = StackVec::new();
    crlf_buf.resize(2, 0).map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;

    let mut cmd_buf: StackVec<u8, 1> = StackVec::new();
    cmd_buf.resize(1, 0).map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;

    tls_stream.read_exact(&mut crlf_buf).await?;
    tls_stream.read_exact(&mut cmd_buf).await?;
    let addr = Address::read_from_stream(&mut tls_stream).await?;
    tls_stream.read_exact(&mut crlf_buf).await?;

    match cmd_buf[0] {
        CMD_TCP_CONNECT => {
            debug!("TcpConnect target addr: {:?}", addr);
            // error!("before {:?}", &addr);
            // let socket_addr = addr.to_socket_addr(&resolver).await?;
            //
            // let domain_type = if socket_addr.is_ipv4() {
            //     Domain::ipv4()
            // } else {
            //     Domain::ipv6()
            // };
            //
            // let socket = Socket::new(domain_type, Type::stream(), None)?;
            // socket.set_read_timeout(Some(Duration::from_secs(60)))?;
            // socket.set_write_timeout(Some(Duration::from_secs(60)))?;
            // // socket.set_linger(Some(Duration::from_secs(10)))?;
            // // socket.set_keepalive(Some(Duration::from_secs(60 )))?;
            // socket.connect_timeout(&SockAddr::from(socket_addr), Duration::from_secs(15))?;
            // socket.set_nonblocking(true)?;
            // let tcp_stream = TcpStream::from(socket.into_tcp_stream());
            // error!("after {:?}", &socket_addr);
            let tcp_stream =
                TcpStream::connect(addr.to_string()).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            debug!("connect to target: {} from source: {}", addr, source);

            let copy_future = tcp::CopyFuture::new(
                tls_stream,
                tcp_stream,
                Duration::from_secs(60 * 5),
                source,
                connection_activity_tx
            );
            copy_future.await.map_err(|e| e)?;
        }
        CMD_UDP_ASSOCIATE => {
            debug!("UdpAssociate target addr: {:?}", addr);
            let (mut tls_stream_reader, mut tls_stream_writer) = tls_stream.split();

            // let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
            //     .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
                .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            // let tls_inner = tls_stream;

            let mut connection_activity_loop_tx = connection_activity_tx.clone();
            let client_to_server = async {
                // let mut buf = [0u8; RELAY_BUFFER_SIZE];
                let mut buf: StackVec<u8, RELAY_BUFFER_SIZE> = StackVec::new();
                // buf.resize(RELAY_BUFFER_SIZE, 0);

                loop {
                    // error!("client_to_server never end");
                    let header = UdpAssociateHeader::read_from(&mut tls_stream_reader).await?;
                    if header.payload_len == 0 {
                        break
                    }
                    buf.resize(header.payload_len as usize, 0)
                        .map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;

                    tls_stream_reader.read_exact(&mut buf[..header.payload_len as usize]).await?;

                    connection_activity_loop_tx.try_send(SessionMessage::KeepLive(source)).map_err(|e| {
                        log::error!("send keepalive message error: {:?}", e);
                        std::io::Error::new(std::io::ErrorKind::WriteZero, format!("{:?}", e))
                    })?;

                    //                    let header = match timeout(std::time::Duration::from_secs(60), async {
                    // let header = UdpAssociateHeader::read_from(&mut tls_stream_reader).await?;
                    // if header.payload_len == 0 {
                    // return Err(anyhow::anyhow!("udp associate header reading timeout"))
                    // }
                    // buf.resize(header.payload_len as usize, 0)
                    // .map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;
                    // tls_stream_reader.read_exact(&mut buf[..header.payload_len as usize]).await?;
                    // Ok(header)
                    // })
                    // .await
                    // {
                    // Ok(header) => header?,
                    // Err(e) => {
                    // error!("reading client socket timeout:{:?}", e);
                    // break
                    // }
                    // };
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
                let mut buf: StackVec<u8, RELAY_BUFFER_SIZE> = StackVec::new();
                buf.resize(RELAY_BUFFER_SIZE, 0)
                    .map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;

                loop {
                    let (len, dst) = outbound.recv_from(&mut buf).await.map_err(|e|Error::Eor(anyhow::anyhow!("{:?}",e)))?;

                    if len == 0 {
                        break
                    }
                    let header = UdpAssociateHeader::new(&Address::from(dst), len);
                    header.write_to(&mut tls_stream_writer).await?;
                    tls_stream_writer.write_all(&buf[..len]).await?;
                    debug!("udp copy to client: {} bytes", len);

                    connection_activity_tx.try_send(SessionMessage::KeepLive(source)).map_err(|e| {
                        log::error!("send keepalive message error: {:?}", e);
                        std::io::Error::new(std::io::ErrorKind::WriteZero, format!("{:?}", e))
                    })?;

/*                    match timeout(std::time::Duration::from_secs(60), async {
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
                    }*/
                }
                tls_stream_writer.flush().await?;
                tls_stream_writer.close().await?;
                std::mem::drop(buf);
                Ok(()) as Result<()>
            };

            futures::pin_mut!(client_to_server);
            futures::pin_mut!(server_to_client);

            let _res = futures::future::join(client_to_server, server_to_client).await;
            // let ret = match res {
            //     Either::Left((Err(e), fut_right)) => {
            //         debug!("udp copy to remote closed");
            //         fut_right.await?;
            //         // std::mem::drop(fut_right);
            //         // let _ = timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
            //         //     fut_right.await?;
            //         //     Ok(()) as Result<()>
            //         // })
            //         // .await?;
            //         Err(anyhow::anyhow!("UdpAssociate copy local to remote error: {:?}", e))?
            //     }
            //     Either::Right((Err(e), fut_left)) => {
            //         debug!("udp copy to local closed");
            //         std::mem::drop(fut_left);
            //         // timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async{
            //         //     fut_left.await;
            //         //     Ok(()) as Result<()>
            //         // })
            //         //     .await;
            //         Err(anyhow::anyhow!("UdpAssociate copy remote to local error: {:?}", e))?
            //     }
            //     Either::Left((Ok(_), fut_right)) => {
            //         fut_right.await
            //         // timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
            //         //     fut_right.await?;
            //         //     Ok(()) as Result<()>
            //         // })
            //         // .await?
            //     }
            //     Either::Right((Ok(_), fut_left)) => {
            //         timeout(READ_TIMEOUT_WHEN_ONE_SHUTDOWN, async {
            //             fut_left.await?;
            //             Ok(()) as Result<()>
            //         })
            //         .await?
            //     }
            // };
            return Ok(())
            // return Err(anyhow::anyhow!("{:?}", ret))?
            // use std::net::Shutdown;
            // tls_inner.shutdown(Shutdown::Both)?;
            // Ok(RequestHeader::UdpAssociate(hash_buf))
        }
        _ => {
            tls_stream.close().await?;
            error!("cant decode incoming stream");
            // Err(Error::Eor(anyhow::anyhow!("invalid command")))
        }
    };
    Ok(())
}
