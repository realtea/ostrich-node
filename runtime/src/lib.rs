use once_cell::sync::OnceCell;
use smolscale::Executor;
use std::future::Future;


// static USER_EXEC: OnceCell<&'static Executor> = OnceCell::new();
// /// Spawns a future onto the sosistab worker.
// pub(crate) fn spawn<T: Send + 'static>(
//     future: impl Future<Output = T> + Send + 'static,
// ) -> smol::Task<T> {
//     if let Some(ex) = USER_EXEC.get() {
//         ex.spawn(future)
//     } else {
//         smolscale::spawn(future)
//     }
// }
