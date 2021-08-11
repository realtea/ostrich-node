pub mod hyper_compat {
    use futures_lite::{AsyncRead, AsyncWrite, Future};
    use hyper::service::service_fn;
    use std::{
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use glommio::{
        // enclose,
        net::{TcpListener, TcpStream},
        // sync::Semaphore,
        Local,
        Task,
    };
    use hyper::{server::conn::Http, Body, Request, Response};
    use std::{io};
    use tokio::io::ReadBuf;
    use std::sync::Arc;
    use crate::api::state::State;
    use crate::db::Db;
    use sqlx::pool::PoolConnection;
    use sqlx::Sqlite;
    // use crate::register::handler::serve;
    use log::error;
    use futures_lite::StreamExt;
    // use errors::Result;
    pub async fn serve_register<A, T,S,F,R>(
        addr: A,
        mut service: S,
        // max_connections: usize,
        state: Arc<State<T>>,
    ) -> io::Result<()>
        where
            S: FnMut(Request<Body>,Arc<State<T>>) -> F + 'static + Copy,
            F: Future<Output = Result<Response<Body>, R>> + 'static,
            R: std::error::Error + 'static + Send + Sync,
            A: Into<SocketAddr>,
            T: Send + Sync + 'static + Db<Conn=PoolConnection<Sqlite>>,
    {
        let listener = TcpListener::bind(addr.into())?;
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
            Local::local(async move {
                // let _permit = conn_control.acquire_permit(1).await;
                if let Err(x) = Http::new()
                    .with_executor(HyperExecutor)
                    .serve_connection(
                        HyperStream(stream),
                        service_fn(|req| service(req, state.clone())),
                    )
                    .await
                {
                    error!("Stream from {:?} failed with error {:?}", addr, x);
                }
            }).detach();
            // }
        }
        Ok(())
        // }
    }

    #[derive(Clone)]
    struct HyperExecutor;

    impl<F> hyper::rt::Executor<F> for HyperExecutor
        where
            F: Future + 'static,
            F::Output: 'static,
    {
        fn execute(&self, fut: F) {
            Task::local(fut).detach();
        }
    }

    struct HyperStream(pub TcpStream);

    impl tokio::io::AsyncRead for HyperStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0)
                .poll_read(cx, buf.initialize_unfilled())
                .map(|n| {
                    if n.is_ok() {
                        buf.advance(n.unwrap());
                    }
                    Ok(())
                })
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
