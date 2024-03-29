use crate::db::Db;
use async_std::sync::Mutex;
use serde::{Deserialize, Serialize};
use sqlx::{pool::PoolConnection, Sqlite};
use std::collections::VecDeque;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NodeAddress {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub passwd: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub country: String,
    #[serde(skip_serializing, skip_deserializing)]
    pub city: String
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NodeAddressV2 {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub passwd: String,
    pub country: String,
    pub city: String
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Node {
    pub addr: NodeAddress,
    pub count: usize,
    pub total: usize,
    #[serde(skip_serializing, skip_deserializing)]
    pub last_update: i64 /* #[serde(skip_serializing,skip_deserializing)]
                          * pub status: Status */
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct NodeV2 {
    pub addr: NodeAddressV2,
    pub count: usize,
    pub total: usize,
    #[serde(skip_serializing, skip_deserializing)]
    pub last_update: i64 /* #[serde(skip_serializing,skip_deserializing)]
                          * pub status: Status */
}


impl PartialEq for NodeV2 {
    fn eq(&self, other: &NodeV2) -> bool {
        self.addr.ip == other.addr.ip
    }
}
pub struct State<T> {
    pub(crate) db: T,
    pub server: Mutex<VecDeque<NodeV2>> /* pub sq: RwLock<BTreeMap<String, usize>>,
                                       * pub index: AtomicUsize, */
}

// impl<T> Deref for Arc<State<T>> {
//     type Target =  RwLock<Vec<Node>>;
//
//     fn deref(&self) -> &Self::Target {
//         &self.server
//     }
// }
//
// impl<T> DerefMut for Acr<State<T>> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.server
//     }
// }

impl<T> State<T>
where T: Db<Conn = PoolConnection<Sqlite>>
{
    pub fn new(state: T) -> Self {
        Self {
            db: state,
            // sq: RwLock::new(BTreeMap::new()),
            server: Mutex::new(VecDeque::new()) // index: AtomicUsize::new(0),
        }
    }

    pub fn state(&self) -> &T {
        &self.db
    }

    pub fn server(&self) -> &Mutex<VecDeque<NodeV2>> {
        &self.server
    }
}
