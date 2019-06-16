use super::Libc;

use libc::{
    c_int, sockaddr, socklen_t, c_void, size_t
};

pub struct TestLibc;

impl Libc for TestLibc {
    fn socket(&self, domain: libc::c_int, ty: c_int, protocol: c_int) -> Result<c_int> {

    }

    fn ioctl(&self, fd: c_int, request: usize, args: *mut c_void) -> Result<c_int> {

    }

    fn bind(&self, socket: c_int, address: *const sockaddr, address_len: socklen_t) -> Result<c_int> {

    }

    fn connect(&self, socket: c_int, address: *const sockaddr, len: socklen_t) -> Result<c_int> {

    }

    fn fcntl(&self, fd: c_int, cmd: c_int, args: c_int) -> c_int {

    }

    fn setsockopt(&self, socket: c_int, level: c_int, name: c_int, value: *const c_void, option_len: socklen_t) -> Result<c_int> {

    }

    fn write(&self, fd: c_int, buf: *const c_void, count: size_t) -> Result<c_int> {

    }

    fn close(&self, fd: c_int) -> Result<c_int> {

    }

    fn read(&self, fd: c_int, buf: *mut c_void, count: size_t) -> Result<c_int> {

    }
}