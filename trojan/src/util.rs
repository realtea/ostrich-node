    use bytes::{Buf, BufMut};
    use futures_core::ready;
    use std::io::{self, IoSlice};
    use std::mem::MaybeUninit;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use futures::{AsyncRead, AsyncWrite};
    use crate::read_buf::ReadBuf;

    /// Try to read data from an `AsyncRead` into an implementer of the [`BufMut`] trait.

    #[cfg_attr(not(feature = "io"), allow(unreachable_pub))]
    pub fn poll_read_buf<T: AsyncRead, B: BufMut>(
        io: Pin<&mut T>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        if !buf.has_remaining_mut() {
            return Poll::Ready(Ok(0));
        }

        let n = {
            // let dst = buf.chunk_mut();
            // let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
            // let mut buf = ReadBuf::uninit(dst);
            // let ptr = buf.filled().as_ptr();
            ready!(io.poll_read(cx, buf)?)

            // Ensure the pointer does not change from under us
            // assert_eq!(ptr, buf.filled().as_ptr());
            // buf.filled().len()
        };

        // Safety: This is guaranteed to be the number of initialized (and read)
        // bytes due to the invariants provided by `ReadBuf::filled`.
        unsafe {
            buf.advance_mut(n);
        }

        Poll::Ready(Ok(n))
    }

    /// Try to write data from an implementer of the [`Buf`] trait to an
    /// [`AsyncWrite`], advancing the buffer's internal cursor.
    ///
    /// This function will use [vectored writes] when the [`AsyncWrite`] supports
    /// vectored writes.

    #[cfg_attr(not(feature = "io"), allow(unreachable_pub))]
    pub fn poll_write_buf<T: AsyncWrite, B: Buf>(
        io: Pin<&mut T>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>> {
        const MAX_BUFS: usize = 64;

        if !buf.has_remaining() {
            return Poll::Ready(Ok(0));
        }

        let n =
        //     if io.is_write_vectored() {
        //     let mut slices = [IoSlice::new(&[]); MAX_BUFS];
        //     let cnt = buf.chunks_vectored(&mut slices);
        //     ready!(io.poll_write_vectored(cx, &slices[..cnt]))?
        // } else {
            ready!(io.poll_write(cx, buf.chunk()))?;
        // };

        buf.advance(n);

        Poll::Ready(Ok(n))
    }
