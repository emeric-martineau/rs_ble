//! This lib is use to allow test
//!
#[cfg(test)]
pub mod tests;

use bytes::BytesMut;
use libc::{
    socket, ioctl, bind, connect, fcntl, setsockopt, write, close, read,
    c_int, sockaddr, c_void,
    AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, PF_BLUETOOTH, SOCK_SEQPACKET, F_SETFL, O_NONBLOCK
};
use PollBuffer;
use hci_socket::error::{Result, handle_error};
use hci_socket::hci::bluetooth::hci::{
    sockaddr_hci, hci_dev_info, hci_dev_list_req,
    HCI_GET_DEV_INFO_MAGIC, HCI_GET_DEV_LIST_MAGIC, HCI_FILTER
};
use hci_socket::hci::bluetooth::l2cap::sockaddr_l2;
use hci_socket::hci::bluetooth::{BTPROTO_HCI, BTPROTO_L2CAP, SOL_HCI};

pub trait Libc {
    fn socket_hci(&self) -> Result<c_int>;
    fn socket_l2cap(&self) -> Result<c_int>;
    fn ioctl_hci_dev_info(&self, fd: c_int, device_information: &mut hci_dev_info) -> Result<c_int>;
    fn ioctl_hci_dev_list_req(&self, fd: c_int, device_list: &mut hci_dev_list_req) -> Result<c_int>;
    fn bind_sockaddr_hci(&self, socket: c_int, address: &sockaddr_hci) -> Result<c_int>;
    fn bind_sockaddr_l2(&self, socket: c_int, address: &sockaddr_l2) -> Result<c_int>;
    fn connect(&self, socket: c_int, address: &sockaddr_l2) -> Result<c_int>;
    fn fcntl_non_block(&self, fd: c_int) -> c_int;
    fn setsockopt_filter(&self, socket: c_int, filter: &mut BytesMut) -> Result<c_int>;
    fn write(&self, fd: c_int, buf: &mut BytesMut) -> Result<c_int>;
    fn close(&self, fd: c_int) -> Result<c_int>;
    fn read(&self, fd: c_int, buf: &mut PollBuffer) -> Result<c_int>;
}

pub struct DefaultLibc;

impl Libc for DefaultLibc {
    fn socket_hci(&self) -> Result<c_int> {
        handle_error(unsafe {
            socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI)
        })
    }

    fn socket_l2cap(&self) -> Result<c_int> {
        handle_error(unsafe {
            socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)
        })
    }

    fn ioctl_hci_dev_info(&self, fd: c_int, device_information: &mut hci_dev_info)  -> Result<c_int> {
        handle_error(unsafe {
            ioctl(
                fd,
                HCI_GET_DEV_INFO_MAGIC as u64,
                device_information as *mut hci_dev_info as *mut c_void)
        })
    }

    fn ioctl_hci_dev_list_req(&self, fd: c_int, device_list: &mut hci_dev_list_req) -> Result<c_int> {
        handle_error(unsafe {
            ioctl(
                fd,
                HCI_GET_DEV_LIST_MAGIC as u64,
                device_list as *mut hci_dev_list_req as *mut c_void)
        })
    }

    fn bind_sockaddr_hci(&self, socket: c_int, address: &sockaddr_hci) -> Result<c_int> {
        handle_error(unsafe {
            bind(
                socket,
                address as *const sockaddr_hci as *const sockaddr,
                std::mem::size_of::<sockaddr_hci>() as u32)
        })
    }

    fn bind_sockaddr_l2(&self, socket: c_int, address: &sockaddr_l2) -> Result<c_int> {
        handle_error(unsafe {
            bind(
                socket,
                address as *const sockaddr_l2 as *const sockaddr,
                std::mem::size_of::<sockaddr_l2>() as u32)
        })
    }

    fn connect(&self, socket: c_int, address: &sockaddr_l2) -> Result<c_int> {
        handle_error(unsafe {
            connect(
                socket,
                address as *const sockaddr_l2 as *const sockaddr,
                std::mem::size_of::<sockaddr_l2>() as u32)
        })
    }

    fn fcntl_non_block(&self, fd: c_int) -> c_int {
        unsafe {
            fcntl(fd, F_SETFL, O_NONBLOCK)
        }
    }

    fn setsockopt_filter(&self, socket: c_int, filter: &mut BytesMut) -> Result<c_int> {
        handle_error(unsafe {
            setsockopt(
                socket,
                SOL_HCI,
                HCI_FILTER,
                filter.as_mut_ptr() as *mut _ as *mut c_void,
                filter.len() as u32)
        })
    }

    fn write(&self, fd: c_int, buf: &mut BytesMut) -> Result<c_int> {
        handle_error(unsafe {
            write(
                fd,
                buf.as_mut_ptr() as *mut _ as *mut c_void,
                buf.len()) as c_int
        })
    }

    fn close(&self, fd: c_int) -> Result<c_int> {
        handle_error(unsafe {
            close(fd)
        })
    }

    fn read(&self, fd: c_int, buf: &mut PollBuffer) -> Result<c_int> {
        handle_error(unsafe {
            read(
                fd,
                buf.as_mut_ptr() as *mut _ as *mut c_void,
                buf.len()) as c_int
        })
    }
}