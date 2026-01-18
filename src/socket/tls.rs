use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;

#[derive(Clone, Debug)]
pub struct CookieConfig {
    pub enabled: bool,
    pub secret: [u64; 2],
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            secret: [0x4141414141414141, 0x4141414141414141],
        }
    }
}

pub struct CookieConfigHandle {
    config: Arc<ArcSwap<CookieConfig>>,
    generation: Arc<AtomicU64>,
}

impl CookieConfigHandle {
    pub fn new(config: CookieConfig) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn update(&self, config: CookieConfig) {
        self.config.store(Arc::new(config));
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<CookieConfig>> {
        self.config.load()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl Clone for CookieConfigHandle {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            generation: Arc::clone(&self.generation),
        }
    }
}

pub struct ServerTlsOptions {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub cookie: CookieConfigHandle,
}
impl Default for ServerTlsOptions {
    fn default() -> Self {
        Self {
            cert_path: Default::default(),
            key_path: Default::default(),
            cookie: CookieConfigHandle::new(CookieConfig::default()),
        }
    }
}

pub struct ClientTlsOptions {
    pub ca_cert_path: PathBuf,
    pub domain: String,
    pub verify: bool,
}
impl Default for ClientTlsOptions {
    fn default() -> Self {
        Self {
            ca_cert_path: Default::default(),
            domain: Default::default(),
            verify: Default::default(),
        }
    }
}
