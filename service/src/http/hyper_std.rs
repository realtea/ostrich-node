pub mod hyper_compat {
    use futures_lite::{AsyncRead, AsyncWrite, Future};
    use hyper::{
        server::Server,
        service::{make_service_fn, service_fn}
    };
    use std::{
        net::SocketAddr,
        pin::Pin,
        task::{self, Context, Poll}
    };

    use crate::{api::state::State, db::Db};
    // use glommio::{
    //     net::{TcpListener, TcpStream},
    //     Local, Task
    // };
    use hyper::{server::conn::Http, Body, Request, Response};
    use sqlx::{pool::PoolConnection, Sqlite};
    use std::{io, sync::Arc};
    use tokio::io::ReadBuf;
    // use crate::http::handler::serve;
    use async_std::{
        net::{TcpListener, TcpStream},
        task::spawn
    };
    use futures_lite::StreamExt;
    use log::error;
    use std::convert::Infallible;

    // use errors::Result;
    pub async fn serve_register<A, T, S, F, R>(
        addr: A,
        service: S,
        // max_connections: usize,
        state: Arc<State<T>>
    ) -> io::Result<()>
    where
        S: FnOnce(Request<Body>, Arc<State<T>>) -> F + 'static + Copy + Send + Sync,
        F: Future<Output = Result<Response<Body>, R>> + Send + 'static,
        R: std::error::Error + 'static + Send + Sync,
        A: Into<SocketAddr>,
        T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>>
    {
        let listener = TcpListener::bind(addr.into()).await?;
        // let make_svc =
        //     make_service_fn(move |_|
        // let state = state.clone();
        //
        // async  move {
        //         Ok::<_, Infallible>(service_fn( move|req|
        //             // let state = state.clone();
        //
        //             service(req, state.clone())
        //         ))
        //     });

        // let make_svc = make_service_fn(move |_conn| {
        //     let state = state.clone(); // this moved one line earlier
        //     async move { Ok::<_, Infallible>(service_fn(move |req| service(req, state.clone()))) }
        // });
        //
        // let server = Server::builder(HyperListener(listener)).executor(HyperExecutor).serve(make_svc);
        // server.await;
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
                    .serve_connection(HyperStream(stream), service_fn(|req| service(req, state.clone())))
                    .await
                {
                    error!("Stream from {:?} failed with error {:?}", addr, x);
                }
            });
            // }
        }
        Ok(())
    }

    #[derive(Clone)]
    pub struct HyperExecutor;

    impl<F> hyper::rt::Executor<F> for HyperExecutor
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static
    {
        fn execute(&self, fut: F) {
            spawn(fut);
        }
    }

    pub struct HyperListener(pub TcpListener);

    impl hyper::server::accept::Accept for HyperListener {
        type Conn = HyperStream;
        type Error = io::Error;

        fn poll_accept(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
            let stream = task::ready!(Pin::new(&mut self.0.incoming()).poll_next(cx)).unwrap()?;
            Poll::Ready(Some(Ok(HyperStream(stream))))
        }
    }

    pub struct HyperStream(pub TcpStream);

    impl tokio::io::AsyncRead for HyperStream {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf.initialize_unfilled()).map(|n| {
                if n.is_ok() {
                    buf.advance(n.unwrap());
                }
                Ok(())
            })
        }
    }

    impl tokio::io::AsyncWrite for HyperStream {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
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
