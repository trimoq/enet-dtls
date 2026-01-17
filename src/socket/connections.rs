use std::{collections::HashMap, net::SocketAddr};

use slab::{Slab, VacantEntry};

use crate::socket::server::Client;

pub struct Connections {
    clients: Slab<Client>,
    by_ip: HashMap<SocketAddr, usize>,
}

impl Connections {
    pub fn new() -> Self {
        Connections {
            clients: Slab::new(),
            by_ip: HashMap::new(),
        }
    }

    pub(crate) fn vacant_entry(&mut self, addr: SocketAddr) -> VacantEntry<'_, Client> {
        let entry = self.clients.vacant_entry();
        self.by_ip.insert(addr, entry.key());
        entry
    }
    pub(crate) fn get_mut(&mut self, idx: usize) -> Option<&mut Client> {
        self.clients.get_mut(idx)
    }
    pub(crate) fn get_by_ip_mut(&mut self, addr: SocketAddr) -> Option<&mut Client> {
        let idx = self.by_ip.get(&addr)?;
        self.clients.get_mut(*idx)
    }
    pub(crate) fn remove(&mut self, idx: usize) -> Client {
        // todo ensure exists before removing!
        let client = self.clients.remove(idx);
        self.by_ip.remove(&client.addr);
        client
    }
}
