//! Utilities for TCP relay
//!
//! The `CopyBuffer`, `Copy` and `CopyBidirection` are borrowed from the [tokio](https://github.com/tokio-rs/tokio) project.
//! LICENSE MIT

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures::{ready, AsyncRead, AsyncWrite, AsyncBufRead};
use pin_project::pin_project;
// use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use async_io_timeout::TimeoutReader;
use futures::io::ErrorKind;


pin_project! {
        struct CopyFuture<R, W> {
            #[pin]
            reader: R,
            #[pin]
            writer: W,
            amt: u64,
        }
    }

impl<R, W>  CopyFuture<R, W>
    where
        R: AsyncBufRead,
        W: AsyncWrite + Unpin,
{
    // type Output = io::Result<u64>;

    fn poll_copy(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let mut this = self.project();
        loop {
            let buffer = ready!(this.reader.as_mut().poll_fill_buf(cx))?;
            if buffer.is_empty() {
                ready!(this.writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(*this.amt));
            }

            let i = ready!(this.writer.as_mut().poll_write(cx, buffer))?;
            if i == 0 {
                return Poll::Ready(Err(ErrorKind::WriteZero.into()));
            }
            *this.amt += i as u64;
            this.reader.as_mut().consume(i);
        }
    }
}


// #[derive(Debug)]
// struct CopyBuffer {
//     read_done: bool,
//     pos: usize,
//     cap: usize,
//     amt: u64,
//     buf: Box<[u8]>,
// }
//
// impl CopyBuffer {
//     fn new(buffer_size: usize) -> Self {
//         Self {
//             read_done: false,
//             pos: 0,
//             cap: 0,
//             amt: 0,
//             buf: vec![0; buffer_size].into_boxed_slice(),
//         }
//     }
//
//     fn poll_copy<R, W>(
//         &mut self,
//         cx: &mut Context<'_>,
//         mut reader: Pin<&mut R>,
//         mut writer: Pin<&mut W>,
//     ) -> Poll<io::Result<u64>>
//         where
//             R: AsyncRead + ?Sized,
//             W: AsyncWrite + ?Sized,
//     {
//         loop {
//             // If our buffer is empty, then we need to read some data to
//             // continue.
//             if self.pos == self.cap && !self.read_done {
//                 let me = &mut *self;
//                 let mut buf = ReadBuf::new(&mut me.buf);
//                 ready!(reader.as_mut().poll_read(cx, &mut buf))?;
//                 let n = buf.filled().len();
//                 if n == 0 {
//                     self.read_done = true;
//                 } else {
//                     self.pos = 0;
//                     self.cap = n;
//                 }
//             }
//
//             // If our buffer has some data, let's write it out!
//             while self.pos < self.cap {
//                 let me = &mut *self;
//                 let i = ready!(writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]))?;
//                 if i == 0 {
//                     return Poll::Ready(Err(io::Error::new(
//                         io::ErrorKind::WriteZero,
//                         "write zero byte into writer",
//                     )));
//                 } else {
//                     self.pos += i;
//                     self.amt += i as u64;
//                 }
//             }
//
//             // If we've written all the data and we've seen EOF, flush out the
//             // data and finish the transfer.
//             if self.pos == self.cap && self.read_done {
//                 ready!(writer.as_mut().poll_flush(cx))?;
//                 return Poll::Ready(Ok(self.amt));
//             }
//         }
//     }
// }

/// A future that asynchronously copies the entire contents of a reader into a
/// writer.
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct Copy<'a, R: ?Sized, W: ?Sized> {
    reader: &'a mut R,
    writer: &'a mut W,
    buf: CopyBuffer,
}

impl<R, W> Future for Copy<'_, R, W>
    where
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let me = &mut *self;

        me.buf
            .poll_copy(cx, Pin::new(&mut *me.reader), Pin::new(&mut *me.writer))
    }
}





fn plain_read_buffer_size() -> usize {
    // match method.category() {
    //     CipherCategory::Aead => super::aead::MAX_PACKET_SIZE,
    //     #[cfg(feature = "stream-cipher")]
    //     CipherCategory::Stream => 1 << 14,
    //     CipherCategory::None =>
        1 << 14
}



enum TransferState {
    Running(CopyBuffer),
    ShuttingDown(u64),
    Done(u64),
}

#[pin_project(project = CopyBidirectionalProj)]
struct CopyBidirectional<'a, A: ?Sized, B: ?Sized> {
    #[pin]
    a: TimeoutReader<&'a mut A>,
    #[pin]
    b: TimeoutReader<&'a mut B>,
    a_to_b: TransferState,
    b_to_a: TransferState,
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    mut r: Pin<&mut TimeoutReader<&mut A>>,
    mut w: Pin<&mut TimeoutReader<&mut B>>,
) -> Poll<io::Result<u64>>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_shutdown(cx))?;

                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

impl<'a, A, B> Future for CopyBidirectional<'a, A, B>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
        B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    type Output = io::Result<(u64, u64)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Unpack self into mut refs to each field to avoid borrow check issues.
        let CopyBidirectionalProj {
            mut a,
            mut b,
            a_to_b,
            b_to_a,
        } = self.project();

        let poll_a_to_b = transfer_one_direction(cx, a_to_b, a.as_mut(), b.as_mut())?;
        let poll_b_to_a = transfer_one_direction(cx, b_to_a, b.as_mut(), a.as_mut())?;

        // It is not a problem if ready! returns early because transfer_one_direction for the
        // other direction will keep returning TransferState::Done(count) in future calls to poll

        // When one direction have already finished, FIN have already sent to the writer.
        // But the FIN may have been lost.
        // This timer is for purging those "Half Open" connections.
        const READ_TIMEOUT_WHEN_ONE_SHUTDOWN: Duration = Duration::from_secs(5);

        // Check if one end have already finished
        match (poll_a_to_b, poll_b_to_a) {
            (Poll::Ready(a_to_b), Poll::Ready(b_to_a)) => Poll::Ready(Ok((a_to_b, b_to_a))),

            (Poll::Ready(a_to_b), Poll::Pending) => {
                // a -> b finished, then FIN have already sent to b, setting a read timeout on b
                if b.timeout().is_none() {
                    b.as_mut().set_timeout_pinned(Some(READ_TIMEOUT_WHEN_ONE_SHUTDOWN));

                    // poll again to ensure Waker have already registered to the timer
                    let b_to_a = ready!(transfer_one_direction(cx, b_to_a, b.as_mut(), a.as_mut())?);

                    Poll::Ready(Ok((a_to_b, b_to_a)))
                } else {
                    Poll::Pending
                }
            }

            (Poll::Pending, Poll::Ready(b_to_a)) => {
                // b -> a finished, then FIN have already sent to a, setting a read timeout on a
                if a.timeout().is_none() {
                    a.as_mut().set_timeout_pinned(Some(READ_TIMEOUT_WHEN_ONE_SHUTDOWN));

                    // poll again to ensure Waker have already registered to the timer
                    let a_to_b = ready!(transfer_one_direction(cx, a_to_b, a.as_mut(), b.as_mut())?);

                    Poll::Ready(Ok((a_to_b, b_to_a)))
                } else {
                    Poll::Pending
                }
            }

            (Poll::Pending, Poll::Pending) => Poll::Pending,
        }
    }
}

/// Copies data in both directions between `encrypted` stream and `plain` stream.
///
/// This function returns a future that will read from both streams,
/// writing any data read to the opposing stream.
/// This happens in both directions concurrently.
///
/// If an EOF is observed on one stream, [`shutdown()`] will be invoked on
/// the other, and reading from that stream will stop. Copying of data in
/// the other direction will continue.
///
/// The future will complete successfully once both directions of communication has been shut down.
/// A direction is shut down when the reader reports EOF,
/// at which point [`shutdown()`] is called on the corresponding writer. When finished,
/// it will return a tuple of the number of bytes copied from encrypted to plain
/// and the number of bytes copied from plain to encrypted, in that order.
///
/// [`shutdown()`]: crate::io::AsyncWriteExt::shutdown
///
/// # Errors
///
/// The future will immediately return an error if any IO operation on `encrypted`
/// or `plain` returns an error. Some data read from either stream may be lost (not
/// written to the other stream) in this case.
///
/// # Return value
///
/// Returns a tuple of bytes copied `encrypted` to `plain` and bytes copied `plain` to `encrypted`.
pub async fn copy_encrypted_bidirectional<E, P>(
    src_io: &mut E,
    dst_io: &mut P,
) -> Result<(u64, u64), std::io::Error>
    where
        E: AsyncRead + AsyncWrite + Unpin + ?Sized,
        P: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    CopyBidirectional {
        a: TimeoutReader::new(src_io),
        b: TimeoutReader::new(dst_io),
        a_to_b: TransferState::Running(CopyBuffer::new(plain_read_buffer_size())),
        b_to_a: TransferState::Running(CopyBuffer::new(plain_read_buffer_size())),
    }
        .await
}
