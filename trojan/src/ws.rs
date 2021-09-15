cfg_if::cfg_if! {
    if #[cfg(wss)] {

use async_std::net::TcpStream;
use async_tls::server::TlsStream;
// use async_tungstenite::{tungstenite, tungstenite::Message, WebSocketStream};
use futures::{AsyncRead, AsyncWrite, Sink, Stream};
use futures_lite::StreamExt;
use std::{
    pin::Pin,
    task::{Context, Poll}
};
use ws_stream_tungstenite::WsStream as AsyncWsStream;

/// A WebSocket or WebSocket+TLS connection.
pub struct WsStream<S: AsyncRead + AsyncWrite + Unpin + Send>(pub AsyncWsStream<S>);


impl<S> AsyncRead for WsStream<S>
where S: AsyncRead + AsyncWrite + Send + Unpin
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for WsStream<S>
where S: AsyncRead + AsyncWrite + Send + Unpin
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

    }
}

// impl Sink<Message> for WsStream
//     where  S: AsyncRead + AsyncWrite + Unpin
// {
//     type Error = tungstenite::Error;
//
//     fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         Pin::new(&mut self.0).poll_ready(cx)
//
//     }
//
//     fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
//         Pin::new(&mut self.0).start_send(item)
//     }
//
//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         Pin::new(&mut self.0).poll_flush(cx)
//
//     }
//
//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         Pin::new(&mut self.0).poll_close(cx)
//
//     }
// }
//
// impl <S>Stream for WsStream<S>
// where  S: AsyncRead + AsyncWrite + Unpin
// {
//     type Item = tungstenite::Result<Message>;
//
//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         Pin::new(&mut self.0).poll_next(cx)
//     }
// }
//
//
// impl <S>AsyncRead for WsStream<S>
//     where  S: AsyncRead + AsyncWrite + Unpin
// {
//     fn poll_read(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut [u8],
//     ) -> Poll<std::io::Result<usize>> {
//         Pin::new(&mut self.0).poll_read(cx, buf)
//     }
// }

// use async_tungstenite::{WebSocketStream, tungstenite};
// use async_std::net::TcpStream;
// use futures::{Sink, Stream};
// use async_tungstenite::tungstenite::Message;
// use std::pin::Pin;
// use std::task::{Context, Poll};
// use async_tls::server::TlsStream;
//
// /// A WebSocket or WebSocket+TLS connection.
// enum WsStream {
//     /// A plain WebSocket connection.
//     Plain(WebSocketStream<TcpStream>),
//
//     /// A WebSocket connection secured by TLS.
//     Tls(WebSocketStream<TlsStream<TcpStream>>),
// }
//
// impl Sink<Message> for WsStream {
//     type Error = tungstenite::Error;
//
//     fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         match &mut *self {
//             WsStream::Plain(s) => Pin::new(s).poll_ready(cx),
//             WsStream::Tls(s) => Pin::new(s).poll_ready(cx),
//         }
//     }
//
//     fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
//         match &mut *self {
//             WsStream::Plain(s) => Pin::new(s).start_send(item),
//             WsStream::Tls(s) => Pin::new(s).start_send(item),
//         }
//     }
//
//     fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         match &mut *self {
//             WsStream::Plain(s) => Pin::new(s).poll_flush(cx),
//             WsStream::Tls(s) => Pin::new(s).poll_flush(cx),
//         }
//     }
//
//     fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
//         match &mut *self {
//             WsStream::Plain(s) => Pin::new(s).poll_close(cx),
//             WsStream::Tls(s) => Pin::new(s).poll_close(cx),
//         }
//     }
// }
//
// impl Stream for WsStream {
//     type Item = tungstenite::Result<Message>;
//
//     fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
//         match &mut *self {
//             WsStream::Plain(s) => Pin::new(s).poll_next(cx),
//             WsStream::Tls(s) => Pin::new(s).poll_next(cx),
//         }
//     }
// }
