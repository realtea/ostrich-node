use errors::Result;

use std::sync::Arc;
use crate::api::state::State;
use std::io;
use async_std::task::block_on;
use crate::http::handler::{handle_create_user, handle_server_query, handle_server_lists_query, handle_acme_challenge, handle_server_update};
use crate::db::Db;
use sqlx::pool::PoolConnection;
use sqlx::Sqlite;
use std::net::SocketAddr;

pub async fn serve_register<A, T>(
    addr: A,
    // service: S,
    // max_connections: usize,
    state: Arc<State<T>>
) -> io::Result<()>
where T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>>,
    A: Into<SocketAddr>{
    block_on(async{
        let mut app = tide::with_state(state);
        app.at("/ostrich/admin/mobile/user/create").post(|req: tide::Request<Arc<State<T>>>| async move {

            handle_create_user(req, ).await.map_err(|e| e.into())
        });
        app.at("/ostrich/api/mobile/server/list").post(|req: tide::Request<Arc<State<T>>>| async move {

            handle_server_query(req).await.map_err(|e| e.into())
        });
        app.at("/ostrich/api/mobile/server/lists").post(|req: tide::Request<Arc<State<T>>>| async move {

            handle_server_lists_query(req).await.map_err(|e| e.into())
        });
        app.at("/.well-known/acme-challenge").get(|req: tide::Request<Arc<State<T>>>| async move {

            handle_acme_challenge(req).await.map_err(|e| e.into())

        });
        app.at("/ostrich/api/server/update").post(|req: tide::Request<Arc<State<T>>>| async move {

            handle_server_update(req, ).await.map_err(|e| e.into())

        });
        app.listen(addr).await?;
        Ok(()) as Result<()>
    });
    Ok(())
}
