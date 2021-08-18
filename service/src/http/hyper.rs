pub mod hyper_compat {
    use futures_lite::{AsyncRead, AsyncWrite, Future};
    use hyper::service::service_fn;
    use std::{
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll}
    };

    use crate::{api::state::State, db::Db};
    use glommio::{
        net::{TcpListener, TcpStream},
        Local, Task
    };
    use hyper::{server::conn::Http, Body, Request, Response};
    use sqlx::{pool::PoolConnection, Sqlite};
    use std::{io, sync::Arc};
    use tokio::io::ReadBuf;
    // use crate::http::handler::serve;
    use futures_lite::StreamExt;
    use log::error;
    // use errors::Result;
    pub async fn serve_register<A, T, S, F, R>(
        addr: A,
        mut service: S,
        // max_connections: usize,
        state: Arc<State<T>>
    ) -> io::Result<()>
    where
        S: FnMut(Request<Body>, Arc<State<T>>) -> F + 'static + Copy,
        F: Future<Output = Result<Response<Body>, R>> + 'static,
        R: std::error::Error + 'static + Send + Sync,
        A: Into<SocketAddr>,
        T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>>
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
                use routerify::prelude::*;
                use routerify::{Router, RouterService};
                use hyper::{Body, Request, Response, Server};
                // A handler for "/" page.
                async fn home_handler(_: Request<Body>) -> Result<Response<Body>, io::Error> {
                    Ok(Response::new(Body::from("Home page")))
                }

                // Define a handler for "/users/:userName/books/:bookName" page which will have two
// route parameters: `userName` and `bookName`.
                async fn user_book_handler(req: Request<Body>) -> Result<Response<Body>, io::Error> {
                    let user_name = req.param("userName").unwrap();
                    let book_name = req.param("bookName").unwrap();

                    Ok(Response::new(Body::from(format!(
                        "User: {}, Book: {}",
                        user_name, book_name
                    ))))
                }

                fn router() -> Router<Body, io::Error> {
                    // Create a router and specify the the handlers.
                    Router::builder()
                        .get("/", home_handler)
                        .get("/users/:userName/books/:bookName", user_book_handler)
                        .build()
                        .unwrap()
                }

                let router = router();

                // Create a Service from the router above to handle incoming requests.
                let service = RouterService::new(router).unwrap();

                // The address on which the server will be listening.
                let addr = SocketAddr::from(([127, 0, 0, 1], 3001));

                // Create a server by passing the created service to `.serve` method.
                let server = Server::bind(&addr).serve(service);

                if let Err(x) = Http::new()
                    .with_executor(HyperExecutor)
                    .serve_connection(HyperStream(stream), service_fn(|req| service(req, state.clone())))
                    .await
                {
                    error!("Stream from {:?} failed with error {:?}", addr, x);
                }
            })
            .detach();
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
        F::Output: 'static
    {
        fn execute(&self, fut: F) {
            Task::local(fut).detach();
        }
    }

    struct HyperStream(pub TcpStream);

    impl tokio::io::AsyncRead for HyperStream {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf.initialize_unfilled()).map(|n| {
                if n.is_ok() {
                    buf.advance(n?);
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
