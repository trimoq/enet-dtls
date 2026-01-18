use std::cell::RefCell;

use crate::tls::{ClientTlsOptions, ServerTlsOptions};

thread_local! {
    static BIND_TLS_OPT: RefCell<ServerTlsOptions> = RefCell::new(ServerTlsOptions::default());
    static CONNECT_TLS_OPT: RefCell<ClientTlsOptions> = RefCell::new(ClientTlsOptions::default());
}

pub fn set_server_tls_options(opt: ServerTlsOptions) {
    BIND_TLS_OPT.set(opt);
}
pub fn take_server_tls_options() -> ServerTlsOptions {
    BIND_TLS_OPT.take()
}
pub fn set_client_tls_options(opt: ClientTlsOptions) {
    CONNECT_TLS_OPT.set(opt);
}
pub fn take_client_tls_options() -> ClientTlsOptions {
    CONNECT_TLS_OPT.take()
}
