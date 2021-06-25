pub mod hyper_compat {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use crate::api::state::State;
    use crate::db::Db;
    use crate::register::handler::serve;
    use async_std::io;
    use async_std::net::{TcpListener, TcpStream};
    use async_std::prelude::*;
    use async_std::task;
    use async_std::task::spawn;
    use futures_lite::StreamExt;
    use hyper::server::conn::Http;
    use hyper::service::service_fn;
    use log::error;
    use sqlx::pool::PoolConnection;
    use sqlx::Sqlite;
    use std::net::SocketAddr;
    use std::sync::Arc;

    pub async fn serve_register<A, T>(
        addr: A,
        // service: S,
        // max_connections: usize,
        state: Arc<State<T>>,
    ) -> io::Result<()>
    where
        // S: FnMut(Request<Body>) -> F + 'static + Copy,
        // F: Future<Output = Result<Response<Body>, R>> + 'static,
        // R: std::error::Error + 'static + Send + Sync,
        A: Into<SocketAddr>,
        T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>>,
    {
        let listener = TcpListener::bind(addr.into()).await?;
        // let conn_control = Rc::new(Semaphore::new(max_connections as _));
        // loop {
        let mut incoming = listener.incoming();
        while let Some(Ok(stream)) = incoming.next().await {
            // Err(x) => {
            //     return Err(x.into());
            // }
            // Ok(stream) => {
            let addr = stream.local_addr()?;
            let state = state.clone();
            spawn(async move {
                // let _permit = conn_control.acquire_permit(1).await;
                if let Err(x) = Http::new()
                    .with_executor(HyperExecutor)
                    .serve_connection(
                        HyperStream(stream),
                        service_fn(|req| serve(req, state.clone())),
                    )
                    .await
                {
                    error!("Stream from {:?} failed with error {:?}", addr, x);
                }
            });
            // }
        }
        Ok(())
        // }
    }

    #[derive(Clone)]
    pub struct HyperExecutor;

    impl<F> hyper::rt::Executor<F> for HyperExecutor
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        fn execute(&self, fut: F) {
            task::spawn(fut);
        }
    }

    pub struct HyperListener(pub TcpListener);

    impl hyper::server::accept::Accept for HyperListener {
        type Conn = HyperStream;
        type Error = io::Error;

        fn poll_accept(
            self: Pin<&mut Self>,
            cx: &mut Context,
        ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
            let stream = task::ready!(Pin::new(&mut self.0.incoming()).poll_next(cx)).unwrap()?;
            Poll::Ready(Some(Ok(HyperStream(stream))))
        }
    }

    pub struct HyperStream(pub TcpStream);

    impl tokio::io::AsyncRead for HyperStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for HyperStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_close(cx)
        }
    }
}
