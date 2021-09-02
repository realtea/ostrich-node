use crate::{
    api::state::State,
    db::Db,
    http::handler::{
        handle_acme_challenge, handle_create_user, handle_server_lists_query, handle_server_query, handle_server_update
    }
};
use sqlx::{pool::PoolConnection, Sqlite};
use std::{io, sync::Arc};

pub async fn serve_register<T>(
    addr: &str,
    // service: S,
    // max_connections: usize,
    state: Arc<State<T>>
) -> io::Result<()>
where
    T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>>
{
    // block_on(async{
    let mut app = tide::with_state(state);
    app.at("/ostrich/admin/mobile/user/create")
        .post(|req: tide::Request<Arc<State<T>>>| async move { handle_create_user(req).await.map_err(|e| e.into()) });
    app.at("/ostrich/api/mobile/server/list")
        .post(|req: tide::Request<Arc<State<T>>>| async move { handle_server_query(req).await.map_err(|e| e.into()) });
    app.at("/ostrich/api/mobile/server/lists").post(|req: tide::Request<Arc<State<T>>>| {
        async move { handle_server_lists_query(req).await.map_err(|e| e.into()) }
    });
    app.at("/.well-known/acme-challenge/:token")
        .get(|req: tide::Request<Arc<State<T>>>| async move { handle_acme_challenge(req).await.map_err(|e| e.into()) });
    app.at("/ostrich/api/server/update")
        .post(|req: tide::Request<Arc<State<T>>>| async move { handle_server_update(req).await.map_err(|e| e.into()) });
    app.listen(addr).await?;
    // Ok(()) as Result<()>
    // });
    Ok(())
}
