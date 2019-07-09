use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Cursor;
use std::io::Read;
use bytes::BytesMut;
use libc::c_int;
use hci_socket::hci::bluetooth::hci::{
    sockaddr_hci, hci_dev_info, hci_dev_list_req
};
use hci_socket::hci::bluetooth::l2cap::sockaddr_l2;
use hci_socket::error::{Result, Error};
use PollBuffer;
use super::Libc;

/// Structure of call `ioctl_hci_dev_info()`.
pub struct IoctlHciDevInfo {
    pub fd: c_int,
    pub device_information: hci_dev_info
}

/// Structure of call `ioctl_hci_dev_list_req()`.
pub struct IoctlHciDevListReq {
    pub fd: c_int,
    pub device_information: hci_dev_list_req
}

/// Structure when write data
pub struct WriteData {
    pub fd: c_int,
    pub buf: BytesMut
}

/// Structure for Network data.
pub struct NetworkPacket {
    data: Vec<Cursor<Vec<u8>>>
}

impl NetworkPacket {
    pub fn new() -> NetworkPacket {
        NetworkPacket {
            data: Vec::new()
        }
    }

    pub fn push(&mut self, data: Vec<u8>) {
        self.data.push(Cursor::new(data));
    }

    pub fn pop(&mut self) -> Cursor<Vec<u8>> {
        if self.data.len() > 0 {
            self.data.remove(0)
        } else {
            Cursor::new(Vec::new())
        }
    }
}

pub struct TestLibc {
    /// File descriptor counter.
    fd: Cell<c_int>,
    /// Allow call of `is_socket_hci()` method or return `PermissionDenied`.
    pub is_socker_hci: bool,
    /// Counter of call of `is_socket_hci()`.
    pub is_socker_hci_call: Cell<u16>,
    /// Allow call of `is_socket_l2cap()` method or return `PermissionDenied`.
    pub is_socker_l2cap: bool,
    /// Counter of call of is_socket_l2cap().
    pub is_socker_l2cap_call: Cell<u16>,
    /// Value of call `ioctl_hci_dev_info()` method.
    pub ioctl_hci_dev_info_call: RefCell<Vec<IoctlHciDevInfo>>,
    /// Allow call of `ioctl_hci_dev_info()` method or return `PermissionDenied`. If not found,
    /// don't throw error.
    pub ioctl_hci_dev_info_call_error: HashMap<c_int, bool>,
    /// Value return when call `ioctl_hci_dev_list_req` method. If not set, return `PermissionDenied`.
    pub hci_dev_list_req: HashMap<c_int, hci_dev_list_req>,
    /// Value return when call `bind_sockaddr_hci` method. If not set, return `PermissionDenied`.
    pub bind_sockaddr_hci: HashMap<c_int, sockaddr_hci>,
    /// Value return when call `read()` method. `Vec<u8>` can contain more data than `PollBuffer`.
    /// If no more data available return Error:Other("Stop test").
    pub read_data: RefCell<HashMap<c_int, NetworkPacket>>,
    /// Data of `write()` call.
    pub write_data: RefCell<Vec<WriteData>>
}

impl TestLibc {
    pub fn new(
            is_socker_hci: bool,
            is_socker_l2cap: bool,
            ioctl_hci_dev_info_call_error: HashMap<c_int, bool>,
            hci_dev_list_req: HashMap<c_int, hci_dev_list_req>,
            bind_sockaddr_hci: HashMap<i32, sockaddr_hci>,
            read_data: HashMap<c_int, NetworkPacket>) -> TestLibc {
        TestLibc {
            fd: Cell::new(0),
            is_socker_hci,
            is_socker_hci_call: Cell::new(0),
            is_socker_l2cap,
            is_socker_l2cap_call: Cell::new(0),
            ioctl_hci_dev_info_call: RefCell::new(Vec::new()),
            ioctl_hci_dev_info_call_error,
            hci_dev_list_req,
            bind_sockaddr_hci,
            read_data: RefCell::new(read_data),
            write_data: RefCell::new(Vec::new())
        }
    }
}

impl Libc for TestLibc {
    fn socket_hci(&self) -> Result<c_int> {
        self.is_socker_hci_call.set(
            self.is_socker_hci_call.get() + 1
        );

        if self.is_socker_hci {
            let fd = self.fd.get();
            self.fd.set(fd + 1);

            Ok(fd)
        } else {
            println!("> Libc.socket_hci() : return PermissionDenied");
            Err(Error::PermissionDenied)
        }
    }

    fn socket_l2cap(&self) -> Result<c_int> {
        self.is_socker_l2cap_call.set(
            self.is_socker_l2cap_call.get() + 1
        );

        if self.is_socker_l2cap {
            let fd = self.fd.get();
            self.fd.set(fd + 1);

            Ok(fd)
        } else {
            println!("> Libc.socket_l2cap() : return PermissionDenied");
            Err(Error::PermissionDenied)
        }
    }

    fn ioctl_hci_dev_info(&self, fd: c_int, device_information: &mut hci_dev_info)  -> Result<c_int> {
        let data = IoctlHciDevInfo {
            fd,
            device_information: device_information.clone()
        };

        self.ioctl_hci_dev_info_call.borrow_mut().push(data);

        let is_ok = match self.ioctl_hci_dev_info_call_error.get(&fd) {
            Some(v) => v.clone(),
            None => true
        };

        if is_ok {
            Ok(0)
        } else {
            println!("> Libc.ioctl_hci_dev_info() : return PermissionDenied");
            Err(Error::PermissionDenied)
        }
    }

    fn ioctl_hci_dev_list_req(&self, fd: c_int, device_list: &mut hci_dev_list_req) -> Result<c_int> {
        match self.hci_dev_list_req.get(&fd) {
            Some(list) => {
                //Ok(list)
                device_list.dev_num = list.dev_num.clone();
                device_list.dev_req = list.dev_req.clone();
                Ok(0)
            },
            None => {
                println!("> Libc.ioctl_hci_dev_list_req() : return PermissionDenied");
                Err(Error::PermissionDenied)
            }
        }
    }

    fn bind_sockaddr_hci(&self, socket: c_int, address: &sockaddr_hci) -> Result<c_int> {
        match self.bind_sockaddr_hci.get(&socket) {
            Some(item) => {
                assert_eq!(item.hci_channel, address.hci_channel);
                assert_eq!(item.hci_dev, address.hci_dev);
                assert_eq!(item.hci_family, address.hci_family);
                Ok(0)
            },
            None => {
                println!("> Libc.bind_sockaddr_hci() : return PermissionDenied");
                Err(Error::PermissionDenied)
            }
        }
    }

    fn bind_sockaddr_l2(&self, _socket: c_int, _address: &sockaddr_l2) -> Result<c_int> {
        println!("> Libc.bind_sockaddr_l2() : return PermissionDenied (TODO)");
        Err(Error::PermissionDenied)
    }

    fn connect(&self, _socket: c_int, _address: &sockaddr_l2) -> Result<c_int> {
        println!("> Libc.connect() : return PermissionDenied (TODO)");
        Err(Error::PermissionDenied)
    }

    fn fcntl_non_block(&self, _fd: c_int) -> c_int {
        -1
    }

    fn setsockopt_filter(&self, _socket: c_int, _filter: &mut BytesMut) -> Result<c_int> {
        println!("> Libc.setsockopt_filter() : return PermissionDenied (TODO)");
        Err(Error::PermissionDenied)
    }

    fn write(&self, fd: c_int, buf: &mut BytesMut) -> Result<c_int> {
        self.write_data.borrow_mut().push(WriteData {
            fd: fd.clone(),
            buf: buf.clone()
        });

        Ok(0)
    }

    fn close(&self, _fd: c_int) -> Result<c_int> {
        println!("> Libc.close() : return PermissionDenied (TODO)");
        Err(Error::PermissionDenied)
    }

    fn read(&self, fd: c_int, buf: &mut PollBuffer) -> Result<c_int> {
        match self.read_data.borrow_mut().get_mut(&fd) {
            Some(item) => {
                let mut data = item.pop();

                match data.read(buf) {
                    Ok(size) => {
                        match size {
                            0 => Err(Error::Other(String::from("Stop test"))),
                            size => Ok(size as c_int)
                        }
                    },
                    Err(e) => {
                        Err(Error::Other(e.to_string()))
                    }
                }

            },
            None => {
                println!("> Libc.read() : return PermissionDenied");
                Err(Error::PermissionDenied)
            }
        }
    }
}