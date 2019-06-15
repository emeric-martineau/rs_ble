//! This lib is use to allow test
//!
#[cfg(test)]
pub mod tests;

use libc::{
    socket, ioctl, bind, connect, fcntl, setsockopt, write, close, read,
    c_int, sockaddr, socklen_t, c_void, size_t
};
use super::error::{Result, handle_error};

//const AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, PF_BLUETOOTH, SOCK_SEQPACKET, F_SETFL, O_NONBLOCK,

pub trait Libc {
    fn socket(&self, domain: c_int, ty: c_int, protocol: c_int) -> Result<c_int>;
    fn ioctl(&self, fd: c_int, request: usize, args: *mut c_void) -> Result<c_int>;
    fn bind(&self, socket: c_int, address: *const sockaddr, address_len: socklen_t) -> Result<c_int>;
    fn connect(&self, socket: c_int, address: *const sockaddr, len: socklen_t) -> Result<c_int>;
    fn fcntl(&self, fd: c_int, cmd: c_int, args: c_int) -> c_int;
    fn setsockopt(&self, socket: c_int, level: c_int, name: c_int, value: *const c_void, option_len: socklen_t) -> Result<c_int>;
    fn write(&self, fd: c_int, buf: *const c_void, count: size_t) -> Result<c_int>;
    fn close(&self, fd: c_int) -> Result<c_int>;
    fn read(&self, fd: c_int, buf: *mut c_void, count: size_t) -> Result<c_int>;
}

pub struct DefaultLibc;

impl Libc for DefaultLibc {
    fn socket(&self, domain: libc::c_int, ty: c_int, protocol: c_int) -> Result<c_int> {
        handle_error(unsafe {
            socket(domain, ty, protocol)
        })
    }

    fn ioctl(&self, fd: c_int, request: usize, args: *mut c_void) -> Result<c_int> {
        handle_error(unsafe {
            ioctl(fd, request as u64, args)
        })
    }

    fn bind(&self, socket: c_int, address: *const sockaddr, address_len: socklen_t) -> Result<c_int> {
        handle_error(unsafe {
            bind(socket, address, address_len)
        })
    }

    fn connect(&self, socket: c_int, address: *const sockaddr, len: socklen_t) -> Result<c_int> {
        handle_error(unsafe {
            connect(socket, address, len)
        })
    }

    fn fcntl(&self, fd: c_int, cmd: c_int, args: c_int) -> c_int {
        unsafe {
            fcntl(fd, cmd, args)
        }
    }

    fn setsockopt(&self, socket: c_int, level: c_int, name: c_int, value: *const c_void, option_len: socklen_t) -> Result<c_int> {
        handle_error(unsafe {
            setsockopt(socket, level, name, value, option_len)
        })
    }

    fn write(&self, fd: c_int, buf: *const c_void, count: size_t) -> Result<c_int> {
        handle_error(unsafe {
            write(fd, buf, count) as c_int
        })
    }

    fn close(&self, fd: c_int) -> Result<c_int> {
        handle_error(unsafe {
            close(fd)
        })
    }

    fn read(&self, fd: c_int, buf: *mut c_void, count: size_t) -> Result<c_int> {
        handle_error(unsafe {
            read(fd, buf, count) as c_int
        })
    }
}