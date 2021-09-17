//! UDP Association Managing

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration
};

use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, error, trace, warn};
use lru_time_cache::LruCache;
// use shadowsocks::{
//     lookup_then,
//     net::UdpSocket as ShadowUdpSocket,
//     relay::{
//         udprelay::{ProxySocket, MAXIMUM_UDP_PAYLOAD_SIZE},
//         Address,
//     },
// };
use spin::Mutex as SpinMutex;


use crate::{
    local::{context::ServiceContext, loadbalancing::PingBalancer},
    net::MonProxySocket,
    Address
};

use async_std::{
    net::UdpSocket,
    sync::Mutex,
    task::{spawn, JoinHandle}
};
use futures::channel::mpsc;

/// Writer for sending packets back to client
///
/// Currently it requires `async-trait` for `async fn` in trait, which will allocate a `Box`ed `Future` every call of
/// `send_to`. This performance issue could be solved when `generic_associated_types` and `generic_associated_types` are
/// stablized.
#[async_trait]
pub trait UdpInboundWrite {
    /// Sends packet `data` received from `remote_addr` back to `peer_addr`
    async fn send_to(&self, peer_addr: SocketAddr, remote_addr: &Address, data: &[u8]) -> io::Result<()>;
}

type AssociationMap<W> = LruCache<SocketAddr, UdpAssociation<W>>;
type SharedAssociationMap<W> = Arc<Mutex<AssociationMap<W>>>;

/// UDP association manager
pub struct UdpAssociationManager<W>
where W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static
{
    respond_writer: W,
    context: Arc<ServiceContext>,
    assoc_map: SharedAssociationMap<W>,
    cleanup_abortable: JoinHandle<()>,
    keepalive_abortable: JoinHandle<()>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
}

impl<W> Drop for UdpAssociationManager<W>
where W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static
{
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
        self.keepalive_abortable.abort();
    }
}

impl<W> UdpAssociationManager<W>
where W: UdpInboundWrite + Clone + Send + Sync + Unpin + 'static
{
    /// Create a new `UdpAssociationManager`
    pub fn new(
        context: Arc<ServiceContext>, respond_writer: W, time_to_live: Option<Duration>, capacity: Option<usize>,
        balancer: PingBalancer
    ) -> UdpAssociationManager<W> {
        let time_to_live = time_to_live.unwrap_or(crate::DEFAULT_UDP_EXPIRY_DURATION);
        let assoc_map = Arc::new(Mutex::new(match capacity {
            Some(capacity) => LruCache::with_expiry_duration_and_capacity(time_to_live, capacity),
            None => LruCache::with_expiry_duration(time_to_live)
        }));

        let cleanup_abortable = {
            let assoc_map = assoc_map.clone();
            spawn(async move {
                loop {
                    time::sleep(time_to_live).await;

                    // cleanup expired associations. iter() will remove expired elements
                    let _ = assoc_map.lock().await.iter();
                }
            })
        };

        let (keepalive_tx, mut keepalive_rx) = mpsc::channel(256);

        let keepalive_abortable = {
            let assoc_map = assoc_map.clone();
            spawn(async move {
                while let Some(peer_addr) = keepalive_rx.recv().await {
                    assoc_map.lock().await.get(&peer_addr);
                }
            })
        };

        UdpAssociationManager {
            respond_writer,
            context,
            assoc_map,
            cleanup_abortable,
            keepalive_abortable,
            keepalive_tx,
        }
    }

    /// Sends `data` from `peer_addr` to `target_addr`
    pub async fn send_to(&self, peer_addr: SocketAddr, target_addr: Address, data: &[u8]) -> io::Result<()> {
        // Check or (re)create an association

        let mut assoc_map = self.assoc_map.lock().await;

        if let Some(assoc) = assoc_map.get(&peer_addr) {
            return assoc.try_send((target_addr, Bytes::copy_from_slice(data)))
        }

        let assoc = UdpAssociation::new(
            self.context.clone(),
            peer_addr,
            self.keepalive_tx.clone(),
            self.balancer.clone(),
            self.respond_writer.clone()
        );

        trace!("created udp association for {}", peer_addr);

        assoc.try_send((target_addr, Bytes::copy_from_slice(data)))?;
        assoc_map.insert(peer_addr, assoc);

        Ok(())
    }
}

struct UdpAssociation<W>
where W: UdpInboundWrite + Send + Sync + Unpin + 'static
{
    assoc: Arc<UdpAssociationContext<W>>,
    sender: mpsc::Sender<(Address, Bytes)>
}

impl<W> Drop for UdpAssociation<W>
where W: UdpInboundWrite + Send + Sync + Unpin + 'static
{
    fn drop(&mut self) {
        self.assoc.proxied_socket.lock().abort();
    }
}

impl<W> UdpAssociation<W>
where W: UdpInboundWrite + Send + Sync + Unpin + 'static
{
    fn new(
        context: Arc<ServiceContext>, peer_addr: SocketAddr, keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer, respond_writer: W
    ) -> UdpAssociation<W> {
        let (assoc, sender) = UdpAssociationContext::new(context, peer_addr, keepalive_tx, balancer, respond_writer);
        UdpAssociation { assoc, sender }
    }

    fn try_send(&self, data: (Address, Bytes)) -> io::Result<()> {
        if let Err(..) = self.sender.try_send(data) {
            let err = io::Error::new(ErrorKind::Other, "udp relay channel full");
            return Err(err)
        }
        Ok(())
    }
}

enum UdpAssociationBypassState {
    Empty,
    Connected { socket: Arc<UdpSocket>, abortable: JoinHandle<io::Result<()>> },
    Aborted
}

impl Drop for UdpAssociationBypassState {
    fn drop(&mut self) {
        if let UdpAssociationBypassState::Connected { ref abortable, .. } = *self {
            abortable.abort();
        }
    }
}

impl UdpAssociationBypassState {
    fn empty() -> UdpAssociationBypassState {
        UdpAssociationBypassState::Empty
    }

    fn set_connected(&mut self, socket: Arc<UdpSocket>, abortable: JoinHandle<io::Result<()>>) {
        *self = UdpAssociationBypassState::Connected { socket, abortable };
    }

    fn abort(&mut self) {
        *self = UdpAssociationBypassState::Aborted;
    }
}

enum UdpAssociationProxyState {
    Empty,
    Connected { socket: Arc<MonProxySocket>, abortable: JoinHandle<io::Result<()>> },
    Aborted
}

impl Drop for UdpAssociationProxyState {
    fn drop(&mut self) {
        self.abort_inner();
    }
}

impl UdpAssociationProxyState {
    fn empty() -> UdpAssociationProxyState {
        UdpAssociationProxyState::Empty
    }

    fn reset(&mut self) {
        self.abort_inner();
        *self = UdpAssociationProxyState::Empty;
    }

    fn set_connected(&mut self, socket: Arc<MonProxySocket>, abortable: JoinHandle<io::Result<()>>) {
        self.abort_inner();
        *self = UdpAssociationProxyState::Connected { socket, abortable };
    }

    fn abort(&mut self) {
        self.abort_inner();
        *self = UdpAssociationProxyState::Aborted;
    }

    fn abort_inner(&mut self) {
        if let UdpAssociationProxyState::Connected { ref abortable, .. } = *self {
            abortable.abort();
        }
    }
}

struct UdpAssociationContext<W>
where W: UdpInboundWrite + Send + Sync + Unpin + 'static
{
    context: Arc<ServiceContext>,
    peer_addr: SocketAddr,
    proxied_socket: SpinMutex<UdpAssociationProxyState>,
    keepalive_tx: mpsc::Sender<SocketAddr>,
    respond_writer: W
}

impl<W> Drop for UdpAssociationContext<W>
where W: UdpInboundWrite + Send + Sync + Unpin + 'static
{
    fn drop(&mut self) {
        trace!("udp association for {} is closed", self.peer_addr);
    }
}

impl<W> UdpAssociationContext<W>
where W: UdpInboundWrite + Send + Sync + Unpin + 'static
{
    fn new(
        context: Arc<ServiceContext>, peer_addr: SocketAddr, keepalive_tx: mpsc::Sender<SocketAddr>,
        balancer: PingBalancer, respond_writer: W
    ) -> (Arc<UdpAssociationContext<W>>, mpsc::Sender<(Address, Bytes)>) {
        // Pending packets 1024 should be good enough for a server.
        // If there are plenty of packets stuck in the channel, dropping exccess packets is a good way to protect the
        // server from being OOM.
        let (sender, receiver) = mpsc::channel(1024);

        let assoc = Arc::new(UdpAssociationContext {
            context,
            peer_addr,
            proxied_socket: SpinMutex::new(UdpAssociationProxyState::empty()),
            keepalive_tx,
            respond_writer
        });

        let l2r_task = {
            let assoc = assoc.clone();
            assoc.copy_l2r(receiver)
        };
        spawn(l2r_task);

        (assoc, sender)
    }

    async fn copy_l2r(self: Arc<Self>, mut receiver: mpsc::Receiver<(Address, Bytes)>) {
        while let Some((target_addr, data)) = receiver.recv().await {
            let assoc = self.clone();

            if let Err(err) = assoc.copy_proxied_l2r(&target_addr, &data).await {
                error!(
                    "udp relay {} -> {} (proxied) with {} bytes, error: {}",
                    self.peer_addr,
                    target_addr,
                    data.len(),
                    err
                );
            }
        }
    }

    async fn copy_proxied_l2r(self: Arc<Self>, target_addr: &Address, data: &[u8]) -> io::Result<()> {
        let mut last_err = io::Error::new(ErrorKind::Other, "udp relay sendto failed after retry");

        for tried in 0..3 {
            let socket = {
                let mut handle = self.proxied_socket.lock();

                match *handle {
                    UdpAssociationProxyState::Empty => {
                        // Create a new connection to proxy server

                        let server = self.balancer.best_udp_server();
                        let svr_cfg = server.server_config();

                        let socket = ProxySocket::connect_with_opts(
                            self.context.context(),
                            svr_cfg,
                            self.context.connect_opts_ref()
                        )
                        .await?;
                        let socket = MonProxySocket::from_socket(socket, self.context.flow_stat());
                        let socket = Arc::new(socket);

                        // CLIENT <- REMOTE
                        let r2l_abortable = {
                            let assoc = self.clone();
                            spawn(assoc.copy_proxied_r2l(socket.clone()))
                        };

                        debug!(
                            "created udp association for {} <-> {} (proxied) with {:?}",
                            self.peer_addr,
                            svr_cfg.addr(),
                            self.context.connect_opts_ref()
                        );

                        handle.set_connected(socket.clone(), r2l_abortable);
                        socket
                    }
                    UdpAssociationProxyState::Connected { ref socket, .. } => socket.clone(),
                    UdpAssociationProxyState::Aborted => {
                        debug!(
                            "udp association for {} (proxied) have been aborted, dropped packet {} bytes to {}",
                            self.peer_addr,
                            data.len(),
                            target_addr
                        );
                        return Ok(())
                    }
                }
            };

            match socket.send(target_addr, data).await {
                Ok(..) => return Ok(()),
                Err(err) => {
                    debug!(
                        "{} -> {} (proxied) sending {} bytes failed, tried: {}, error: {}",
                        self.peer_addr,
                        target_addr,
                        data.len(),
                        tried + 1,
                        err
                    );
                    last_err = err;

                    // Reset for reconnecting
                    self.proxied_socket.lock().reset();

                    tokio::task::yield_now().await;
                }
            }
        }

        Err(last_err)
    }

    async fn copy_proxied_r2l(self: Arc<Self>, outbound: Arc<MonProxySocket>) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        loop {
            let (n, addr) = match outbound.recv(&mut buffer).await {
                Ok((n, addr)) => {
                    trace!("udp relay {} <- {} (proxied) received {} bytes", self.peer_addr, addr, n);
                    // Keep association alive in map
                    let _ = self.keepalive_tx.send_timeout(self.peer_addr, Duration::from_secs(1)).await;
                    (n, addr)
                }
                Err(err) => {
                    // Socket that connected to remote server returns an error, it should be ECONNREFUSED in most cases.
                    // That indicates that the association on the server side have been dropped.
                    //
                    // There is no point to keep this socket. Drop it immediately.
                    self.proxied_socket.lock().reset();

                    error!(
                        "udp failed to receive from proxied outbound socket, peer_addr: {}, error: {}",
                        self.peer_addr, err
                    );
                    time::sleep(Duration::from_secs(1)).await;
                    continue
                }
            };

            let data = &buffer[..n];

            // Send back to client
            if let Err(err) = self.respond_writer.send_to(self.peer_addr, &addr, data).await {
                warn!(
                    "udp failed to send back to client {}, from target {} (proxied), error: {}",
                    self.peer_addr, addr, err
                );
                continue
            }

            trace!("udp relay {} <- {} (proxied) with {} bytes", self.peer_addr, addr, data.len());
        }
    }
}
