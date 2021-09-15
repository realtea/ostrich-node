#![cfg_attr(nightly, feature(doc_cfg))]
#![cfg_attr( nightly, cfg_attr( nightly, doc = include_str!("../README.md") ))]
//! // empty doc line to handle missing doc warning when the feature is missing.
#![doc(html_root_url = "https://docs.rs/ws_stream_tungstenite")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![allow(clippy::suspicious_else_formatting)]
#![warn(
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_qualifications,
    single_use_lifetimes,
    unreachable_pub,
    variant_size_differences
)]


mod ws_err;
mod ws_event;
mod ws_stream;

pub(crate) mod tung_websocket;

pub use self::{ws_err::WsErr, ws_event::WsEvent, ws_stream::WsStream};


mod import {
    pub(crate) use async_io_stream::IoStream;
    pub(crate) use async_tungstenite::WebSocketStream as ATungSocket;
    pub(crate) use bitflags::bitflags;
    pub(crate) use futures_core::{ready, Stream};
    pub(crate) use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
    pub(crate) use futures_sink::Sink;
    pub(crate) use futures_util::FutureExt;
    pub(crate) use log::error;
    pub(crate) use pharos::{Observable, Observe, ObserveConfig, PharErr, Pharos};
    pub(crate) use std::{
        borrow::Cow,
        collections::VecDeque,
        fmt, io,
        io::{IoSlice, IoSliceMut},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll}
    };
    pub(crate) use tungstenite::{
        protocol::{frame::coding::CloseCode, CloseFrame},
        Error as TungErr, Message as TungMessage
    };


    #[cfg(feature = "tokio")]
    //
    pub(crate) use tokio::io::{AsyncRead as TokAsyncRead, AsyncWrite as TokAsyncWrite};


    #[cfg(test)]
    //
    pub(crate) use {
        assert_matches::assert_matches,
        futures::future::join,
        futures::{executor::block_on, SinkExt, StreamExt},
        futures_ringbuf::Endpoint,
        futures_test::task::noop_waker,
        log::*,
        pharos::Channel,
        tungstenite::protocol::Role
    };
}
