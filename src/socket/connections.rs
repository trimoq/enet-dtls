use std::{cell::RefCell, rc::Rc};

use slab::{Slab, VacantEntry};

use crate::socket::server::Client;

pub struct Connections{
    clients: Slab<Client>
}

impl Connections{
    pub fn new() -> Self{
        Connections { clients: Slab::new() }
    }
    
    pub(crate) fn vacant_entry(&mut self) -> VacantEntry<Client> {
        self.clients.vacant_entry()
    }
    pub(crate) fn get_mut(&mut self, idx: usize) -> Option<&mut Client> {
        self.clients.get_mut(idx)
    }
        pub(crate) fn remove(&mut self, idx: usize) -> Client {
        self.clients.remove(idx)
    }
}