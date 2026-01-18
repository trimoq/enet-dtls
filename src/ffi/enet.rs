use bytes::{BufMut, BytesMut};
use enet_sys::*;
use log::{debug, error, trace, warn};
use std::io::{self};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::raw::c_void;
use std::ptr::{slice_from_raw_parts, slice_from_raw_parts_mut};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ffi::addr::{from_enet_addr, to_enet_addr_inplace};
use crate::ffi::local::{take_client_tls_options, take_server_tls_options};
use crate::socket::{
    EnetPacketSocket as EnetPacketSocketWrapper, PacketSocket, ServerSocketOptions,
};

static mut TIME_BASE: u32 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn enet_initialize() -> ::std::os::raw::c_int {
    // does nothing
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_deinitialize() {
    // does nothing
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_host_random_seed() -> enet_uint32 {
    let mut buf = [0u8; 4];
    openssl::rand::rand_bytes(&mut buf).unwrap();
    u32::from_be_bytes(buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_time_get() -> enet_uint32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u32
        - unsafe { TIME_BASE }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_time_set(new_time_base: enet_uint32) {
    unsafe {
        TIME_BASE = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32
            - new_time_base;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_create(tpe: ENetSocketType) -> ENetSocket {
    if tpe != _ENetSocketType_ENET_SOCKET_TYPE_DATAGRAM {
        unimplemented!("Nope")
    }
    let sock = Box::new(EnetPacketSocketWrapper::new());
    let f = Box::into_raw(sock) as *mut c_void;
    trace!("sock: {:p}", f as *mut EnetPacketSocketWrapper);
    f
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_bind(
    sock: ENetSocket,
    addr: *const ENetAddress,
) -> ::std::os::raw::c_int {
    let sock = unsafe { &mut *(sock as *mut EnetPacketSocketWrapper) };
    let addr = unsafe { &*(addr as *const ENetAddress) };

    let addr = from_enet_addr(addr);
    let tsl_opt = take_server_tls_options();
    let opts = ServerSocketOptions { addr, tls: tsl_opt };
    match sock.bind(opts) {
        Ok(_) => {
            debug!("Socket bound");
            0
        }
        Err(e) => {
            error!("Socket bind failed: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_get_address(
    sock: ENetSocket,
    addr: *mut ENetAddress,
) -> ::std::os::raw::c_int {
    let sock = unsafe { &mut *(sock as *mut EnetPacketSocketWrapper) };
    let addr = unsafe { &mut *(addr as *mut ENetAddress) };
    match sock.get_addr() {
        Ok(saddr) => {
            to_enet_addr_inplace(&saddr, addr);
            0
        }
        Err(e) => {
            error!("enet_socket_get_address, can't get addr: {e}");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_send(
    sock: ENetSocket,
    addr: *const ENetAddress,
    buf: *const ENetBuffer,
    buffer_cnt: usize,
) -> ::std::os::raw::c_int {
    // todo: vectored writes?
    // trace!("enet_socket_send");

    let sock = unsafe { &mut *(sock as *mut EnetPacketSocketWrapper) };
    let addr = unsafe { &mut *(addr as *mut ENetAddress) };
    let addr = SocketAddr::new(IpAddr::V4(addr.host.to_ne_bytes().into()), addr.port);

    let buf = unsafe { &*slice_from_raw_parts(buf, buffer_cnt) };

    let total_size = buf.iter().map(|b| b.dataLength).sum();
    let mut bytes = BytesMut::with_capacity(total_size);
    buf.iter()
        .map(|b| unsafe { &mut *slice_from_raw_parts_mut(b.data as *mut u8, b.dataLength) })
        .for_each(|b| bytes.put_slice(b));

    match sock.send(addr, &mut bytes) {
        Ok(_) => bytes.len().try_into().unwrap(),
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock => 0,
            io::ErrorKind::NotConnected => 0,
            _ => -1,
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_receive(
    sock: ENetSocket,
    addr: *mut ENetAddress,
    buf: *mut ENetBuffer,
    buffer_cnt: usize,
) -> ::std::os::raw::c_int {
    let sock = unsafe { &mut *(sock as *mut EnetPacketSocketWrapper) };
    let addr = unsafe { &mut *(addr as *mut ENetAddress) };
    // println!("enet_socket_receive");

    let buf = unsafe { &*slice_from_raw_parts(buf, buffer_cnt) };

    let mut first_buffer =
        unsafe { &mut *slice_from_raw_parts_mut(buf[0].data as *mut u8, buf[0].dataLength) };
    match sock.receive(&mut first_buffer) {
        Ok(res) => {
            to_enet_addr_inplace(&res.saddr, addr);
            trace!(
                "received {} bytes from {}: {:x?}",
                res.len,
                res.saddr,
                &first_buffer[..(res.len as usize)]
            );

            res.len as i32
        }
        Err(e) => match e.kind() {
            io::ErrorKind::WouldBlock => 0,
            io::ErrorKind::NotConnected => 0,
            _ => -1,
        },
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_connect(
    sock: ENetSocket,
    addr: *const ENetAddress,
) -> ::std::os::raw::c_int {
    let sock = unsafe { &mut *(sock as *mut EnetPacketSocketWrapper) };
    let addr = unsafe { &*(addr as *const ENetAddress) };
    let addr = from_enet_addr(addr);
    warn!("enet_socket_connect{}", addr);

    let tls = take_client_tls_options();

    match sock.connect(addr, tls) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_address_set_host_ip(
    address: *mut ENetAddress,
    _host_name: *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    warn!("enet_address_set_host_ip not fully implemented");
    (unsafe { *address }).host = Ipv4Addr::new(127, 0, 0, 0).to_bits();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_address_set_host(
    address: *mut ENetAddress,
    _host_name: *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {
    warn!("enet_address_set_host not fully implemented");
    (unsafe { *address }).host = Ipv4Addr::new(127, 0, 0, 0).to_bits();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_set_option(
    _: ENetSocket,
    _: ENetSocketOption,
    _: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    // fuck off, we are always non-blocking
    0
}

// intentionally unimplemented functions

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_listen(
    _: ENetSocket,
    _: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    todo!("enet_socket_listen");
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_accept(_: ENetSocket, _: *mut ENetAddress) -> ENetSocket {
    todo!("enet_socket_accept");
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_get_option(
    _: ENetSocket,
    _: ENetSocketOption,
    _: *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {
    warn!("enet_socket_get_option");
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_wait(
    sock: ENetSocket,
    _: *mut enet_uint32,
    _: enet_uint32,
) -> ::std::os::raw::c_int {
    // todo poll instead of busy looping
    // warn!("enet_socket_wait");
    let sock = unsafe { &mut *(sock as *mut EnetPacketSocketWrapper) };
    match sock.poll(){
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_shutdown(
    _: ENetSocket,
    _: ENetSocketShutdown,
) -> ::std::os::raw::c_int {
    warn!("enet_socket_shutdown");
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socket_destroy(_: ENetSocket) {
    warn!("enet_socket_destroy");
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_socketset_select(
    _: ENetSocket,
    _: *mut ENetSocketSet,
    _: *mut ENetSocketSet,
    _: enet_uint32,
) -> ::std::os::raw::c_int {
    warn!("enet_socketset_select");
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_address_get_host_ip(
    _: *const ENetAddress,
    _: *mut ::std::os::raw::c_char,
    _: usize,
) -> ::std::os::raw::c_int {
    warn!("enet_address_get_host_ip");
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn enet_address_get_host(
    _: *const ENetAddress,
    _: *mut ::std::os::raw::c_char,
    _: usize,
) -> ::std::os::raw::c_int {
    warn!("enet_address_get_host");
    -1
}
