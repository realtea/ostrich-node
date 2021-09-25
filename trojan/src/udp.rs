use futures::{future::{Future, FutureExt}, io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader}, ready, AsyncReadExt, AsyncWriteExt};
use futures_timer::Delay;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration
};
use async_std::net::{TcpStream, UdpSocket};
use crate::{RELAY_BUFFER_SIZE, UdpAssociateHeader};
use heapless::Vec as StackVec;
use std::net::SocketAddr;
use log::{error,debug};
use errors::{Error, Result};


pub struct CopyFuture {
    tcp: TcpStream,
    udp: UdpSocket,

    active_timeout: Delay,
    configured_timeout: Duration
}

impl CopyFuture {
    pub fn new(tcp: TcpStream, udp: UdpSocket, timeout: Duration) -> Self {
        CopyFuture {
            tcp,
            udp,
            active_timeout: Delay::new(timeout),
            configured_timeout: timeout
        }
    }
}

impl Future for CopyFuture
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        let mut reset_timer = false;

        loop {
            enum Status {
                Pending,
                Done,
                Progressed
            }
            let mut buf: StackVec<u8, RELAY_BUFFER_SIZE> = StackVec::new();

            let src_status = match upstream(&this.tcp, &this.udp, &mut buf) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => Status::Done,
                Poll::Ready(Ok(false)) => Status::Progressed,
                Poll::Pending => Status::Pending
            };

            let dst_status = match downstream(&this.udp, &this.tcp, &mut buf) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(true)) => Status::Done,
                Poll::Ready(Ok(false)) => Status::Progressed,
                Poll::Pending => Status::Pending
            };

            match (src_status, dst_status) {
                // Both source and destination are done sending data.
                (Status::Done, Status::Done) => return Poll::Ready(Ok(())),
                // Either source or destination made progress, thus reset timer.
                (Status::Progressed, _) | (_, Status::Progressed) => reset_timer = true,
                // Both are pending. Check if timer fired, otherwise return Poll::Pending.
                (Status::Pending, Status::Pending) => break,
                // One is done sending data, the other is pending. Check if timer fired, otherwise
                // return Poll::Pending.
                (Status::Pending, Status::Done) | (Status::Done, Status::Pending) => break
            }
        }

        if reset_timer {
            this.active_timeout = Delay::new(this.configured_timeout);
        }

        if let Poll::Ready(()) = this.active_timeout.poll_unpin(cx) {
            // ready!(Pin::new(&mut self.src).poll_flush(cx))?;
            log::error!("!!! before delay close !!!");
            // ready!(Pin::new(&mut self.dst).poll_flush(cx))?;
            ready!(Pin::new(&mut self.tcp).poll_close(cx)).map_err(|e| {
                log::error!("udp's associate tcp connection close: {:?}", e);
                e
            })?;
            log::error!("after delay close");
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()))
        }

        Poll::Pending
    }
}

async fn upstream(mut tcp: &TcpStream, udp: &UdpSocket, buf: &mut StackVec<u8, RELAY_BUFFER_SIZE>) -> Poll<io::Result<bool>>{
    // let mut buf: StackVec<u8, RELAY_BUFFER_SIZE> = StackVec::new();
    // buf.resize(RELAY_BUFFER_SIZE, 0);


        // error!("client_to_server never end");
        // let header = UdpAssociateHeader::read_from(&mut tcp).await?;
        // if header.payload_len == 0 {
        //     break
        // }
        // buf.resize(header.payload_len as usize, 0)
        //     .map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;

        // tcp.read_exact(&mut buf[..header.payload_len as usize]).await?;

        match timeout(std::time::Duration::from_secs(60), async {
            let header = UdpAssociateHeader::read_from(&mut tcp).await?;
            if header.payload_len == 0 {
                return  Poll::Ready(Ok(true))
            }
            buf.resize(header.payload_len as usize, 0)
                .map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;
            tcp.read_exact(&mut buf[..header.payload_len as usize]).await?;
            Ok(()) as Result<()>
        })
            .await
        {
            Ok(_) => {}
            Err(e) => {
                error!("reading client socket timeout:{:?}", e);
                return  Poll::Ready(Err(e))
            }
        }

        match outbound.send_to(&buf[..header.payload_len as usize], header.addr.to_string()).await {
            Ok(n) => {
                debug!("udp copy to remote: {} bytes", n);
                if n == 0 {
                    return  Poll::Ready(Ok(true))
                }
            }
            Err(e) => {
                error!("udp send to upstream error: {:?}", e);
                return  Poll::Ready(Err(e))
            }
        }

    std::mem::drop(buf);
    Poll::Ready(Ok(false))
}
async fn downstream(udp: &UdpSocket, mut tcp: &TcpStream, buf: &mut StackVec<u8, RELAY_BUFFER_SIZE>) -> Poll<io::Result<bool>>{
    // let mut buf: StackVec<u8, RELAY_BUFFER_SIZE> = StackVec::new();
        buf.resize(RELAY_BUFFER_SIZE, 0)
        .map_err(|_| Error::Eor(anyhow::anyhow!("cant resize vec on stack")))?;


        // let (len, dst) = outbound.recv_from(&mut buf).await?;
        //
        // if len == 0 {
        //     break
        // }
        // let header = UdpAssociateHeader::new(&Address::from(dst), len);
        // header.write_to(&mut tcp).await?;
        // tcp.write_all(&buf[..len]).await?;
        // debug!("udp copy to client: {} bytes", len);

        match timeout(std::time::Duration::from_secs(60), async {
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
                    tcp.flush().await?;
                    tcp.close().await?;
                    return  Poll::Ready(Ok(true))
                }
                let header = UdpAssociateHeader::new(&Address::from(dst), len);
                header.write_to(&mut tcp).await?;
                tcp.write_all(&buf[..len]).await?;
                debug!("udp copy to client: {} bytes", len);
            }
            Err(e) => {
                error!("reading client socket timeout:{:?}", e);
                return  Poll::Ready(Err(e))

            }
        }
    Poll::Ready(Ok(false))
}