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
    pub secret: u64,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            secret: 0x4141414141414141,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CertConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ConnectTokenConfig {
    _secret: u64,
}

#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    pub cookies: Option<CookieConfig>,
    pub connect_token: Option<ConnectTokenConfig>,
    pub cert: Option<CertConfig>,
}

impl TlsConfig {
    pub fn is_tls_enabled(&self) -> bool {
        self.cert.is_some()
    }
    pub fn are_cookies_enabled(&self) -> bool {
        self.cert.is_some() && self.cookies.is_some()
    }
}

pub struct TlsConfigHandle {
    config: Arc<ArcSwap<TlsConfig>>,
    generation: Arc<AtomicU64>,
}

impl TlsConfigHandle {
    pub fn new(config: TlsConfig) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn update(&self, config: TlsConfig) {
        self.config.store(Arc::new(config));
        self.generation.fetch_add(1, Ordering::Release);
    }

    pub fn load(&self) -> arc_swap::Guard<Arc<TlsConfig>> {
        self.config.load()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

impl Clone for TlsConfigHandle {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            generation: Arc::clone(&self.generation),
        }
    }
}

pub struct ServerTlsOptions {
    pub handle: TlsConfigHandle,
}

impl ServerTlsOptions {
    pub fn new(handle: &TlsConfigHandle) -> Self {
        ServerTlsOptions {
            handle: handle.clone(),
        }
    }
    pub fn new_plaintext() -> Self {
        ServerTlsOptions {
            handle: TlsConfigHandle::new(TlsConfig::default()),
        }
    }
}
impl Default for ServerTlsOptions {
    fn default() -> Self {
        Self {
            handle: TlsConfigHandle::new(TlsConfig::default()),
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
