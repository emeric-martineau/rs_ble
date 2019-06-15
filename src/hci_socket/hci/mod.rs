//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
pub mod bluetooth;
pub mod error;

use std::collections::HashMap;
use std::clone::Clone;

use bytes::{Bytes, BytesMut};
use libc::{
    AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, PF_BLUETOOTH, SOCK_SEQPACKET, F_SETFL, O_NONBLOCK,
    socket, ioctl, bind, connect, fcntl, setsockopt, write, close, read
};
use self::error::{Result, handle_error, Error};
use self::bluetooth::{BTPROTO_HCI, BTPROTO_L2CAP, SOL_HCI};
use self::bluetooth::hci::{
    sockaddr_hci, hci_dev_list_req, hci_dev_info, HCI_CHANNEL_USER, HCI_GET_DEV_LIST_MAGIC, HCI_UP,
    HCI_CHANNEL_RAW, HCI_GET_DEV_INFO_MAGIC, HCI_FILTER
};
use self::bluetooth::l2cap::sockaddr_l2;

/// In Noble, buffer is 1024 but maybe shortest
const POLL_BUFFER_SIZE: usize = 2048;
type PollBuffer = [u8; POLL_BUFFER_SIZE];

/// Device information type
const DEVICE_INFORMATION_WEIRD_TYPE:  u8 = 3;
const DEVICE_INFORMATION_PUBLIC_TYPE: u8 = 1;

/// From C preprocessor
pub const LITTLE_ENDIAN: u32 = 1234;
pub const BIG_ENDIAN: u32 = 4321;
pub const BYTE_ORDER: u32 = 1234;
/// ???
pub const ATT_CID: u16 = 4;

/// Structure for BT HCI Socket.
#[derive(Debug)]
pub struct BluetoothHciSocket {
    /// HCI mode
    mode: u16,
    /// Socket network
    socket: i32,
    /// Device Id
    dev_id: u16,
    /// Device MAC address
    address: [u8; 6usize],
    /// Device address type
    address_type: u8,
    /// Map of handler and socket
    l2sockets: HashMap<u16, i32>
}

// TODO close socket
impl BluetoothHciSocket {
    /// Bind a device.
    /// Param `dev_id` is device if you know device, else None.
    pub fn bind_user(dev_id: Option<u16>) -> Result<BluetoothHciSocket> {
        let socket = handle_error(unsafe {
            socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI)
        })?;

        let hci_dev = BluetoothHciSocket::dev_id_for(dev_id, false, socket);

        if let Err(e) = hci_dev {
            return Err(e);
        }

        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: hci_dev.unwrap(),
            hci_channel: HCI_CHANNEL_USER
        };

        handle_error(unsafe {
            bind(socket, &addr as *const sockaddr_hci as *const libc::sockaddr,
                       std::mem::size_of::<sockaddr_hci>() as u32)
        })?;

        // If no data avaible, fcntl return EAGAIN error. We don't care about that.
        unsafe {
            fcntl(socket, F_SETFL, O_NONBLOCK)
        };

        Ok(BluetoothHciSocket {
            mode: HCI_CHANNEL_USER,
            socket,
            dev_id:  addr.hci_dev,
            address: [0, 0, 0, 0, 0, 0],
            address_type: 0,
            l2sockets: HashMap::new()
        })
    }

    /// Bind a device.
    /// Param `dev_id` is device if you know device, else None.
    pub fn bind_raw(dev_id: Option<u16>) -> Result<BluetoothHciSocket> {
        let socket = handle_error(unsafe {
            socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI)
        })?;

        let hci_dev = BluetoothHciSocket::dev_id_for(dev_id, true, socket);

        if let Err(e) = hci_dev {
            return Err(e);
        }

        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: hci_dev.unwrap(),
            hci_channel: HCI_CHANNEL_RAW
        };

        handle_error(unsafe {
            bind(socket, &addr as *const sockaddr_hci as *const libc::sockaddr,
                       std::mem::size_of::<sockaddr_hci>() as u32)
        })?;

        // If no data avaible, fcntl return EAGAIN error. We don't care about that.
        unsafe {
            fcntl(socket, F_SETFL, O_NONBLOCK)
        };

        let mut device_information = hci_dev_info::new(dev_id);

        let ioctl_res = handle_error(unsafe {
            ioctl(socket, HCI_GET_DEV_INFO_MAGIC as u64, &mut device_information)
        });

        if let Err(e) = ioctl_res {
            return Err(e);
        }

        let address_type = if device_information.type_ == DEVICE_INFORMATION_WEIRD_TYPE {
            // 3 is a weird type, use 1 (public) instead
            DEVICE_INFORMATION_PUBLIC_TYPE
        } else {
            device_information.type_
        };

        Ok(BluetoothHciSocket {
            mode: HCI_CHANNEL_RAW,
            socket,
            dev_id:  addr.hci_dev,
            address: device_information.bdaddr.b,
            address_type,
            l2sockets: HashMap::new()
        })
    }

    /*
    No usage found in Noble
    pub fn bind_control(&self) -> Result<()> {
        let addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: HCI_DEV_NONE,
            hci_channel: HCI_CHANNEL_CONTROL
        };

        self.mode = HCI_CHANNEL_CONTROL;

        handle_error(unsafe {
            bind(socket, &addr as *const sockaddr_hci as *const libc::sockaddr,
                 std::mem::size_of::<sockaddr_hci>() as u32)
        })?;

        Ok(())
    }*/

    /// Check if device is up.
    pub fn is_dev_up(&mut self) -> Result<bool> {
        let mut device_information = hci_dev_info::new(Some(self.dev_id.clone()));

        let ioctl_res = handle_error(unsafe {
            ioctl(self.socket, HCI_GET_DEV_INFO_MAGIC as u64, &mut device_information)
        })?;

        let result = if ioctl_res > -1 {
            (device_information.flags & (1 << HCI_UP)) > 0
        } else {
            false
        };

        Ok(result)
    }

    /// Set filter on BT socket.
    pub fn set_filter(&mut self, filter: &BytesMut) -> Result<()> {
        let mut filter = filter.clone();

        handle_error(unsafe {
            setsockopt(self.socket, SOL_HCI, HCI_FILTER,
                             filter.as_mut_ptr() as *mut _ as *mut libc::c_void,
                             filter.len() as u32)
        })?;
        Ok(())
    }

    /// Write BT socket.
    pub fn write(&mut self, data: &BytesMut) -> Result<()> {
        let mut data = data.clone();

        handle_error(unsafe {
            write(self.socket, data.as_mut_ptr() as *mut _ as *mut libc::c_void,
                             data.len()) as i32
        })?;
        Ok(())
    }

    /// Return current device id
    pub fn device_id(&self) -> u16 {
        self.dev_id.clone()
    }

    /// Pool data.
    /// Blocking call.
    pub fn poll(&mut self) -> Result<Bytes> {
        let mut data : PollBuffer = [0u8; POLL_BUFFER_SIZE];

        let result = handle_error(unsafe {
            read(self.socket, data.as_mut_ptr() as *mut _ as *mut libc::c_void, data.len()) as i32
        });

        let length: usize;

        match result {
            Ok(l) => length = l as usize,
            Err(e) => match e {
                Error::TryAgain => length = 0,
                e => return Err(e)
            }
        };

        if length > 0 {
            if self.mode == HCI_CHANNEL_RAW {
                if let Err(e) = self.kernel_disconnect_work_arounds(&data, length) {
                    println!("error in kernel_disconnect_work_arounds(): {:?}", e);
                    return Err(e);
                }
            }
        }

        Ok(Bytes::from(&data[0..length]))
    }

    /// Disconnect socket if need, by looking data.
    fn kernel_disconnect_work_arounds(&mut self, data : &PollBuffer, length: usize) -> Result<()>{
        // HCI Event - LE Meta Event - LE Connection Complete => manually create L2CAP socket to force kernel to book keep
        // HCI Event - Disconn Complete =======================> close socket from above
        if length == 22 && data[0] == 0x04 && data[1] == 0x3e && data[2] == 0x13
            && data[3] == 0x01 && data[4] == 0x00 {

            let l2cid: u16;
            let handle: u16 = data[5] as u16;

            if BYTE_ORDER == LITTLE_ENDIAN {
                l2cid = ATT_CID;
            } else {
                // l2cid = bswap_16(ATT_CID);
                l2cid = u16::from_be(ATT_CID);
            }

            let l2socket = handle_error(unsafe {
                socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)
            })?;

            let l2a = sockaddr_l2::new(AF_BLUETOOTH, l2cid, self.address_type, self.address.clone());

            handle_error(unsafe {
                bind(l2socket, &l2a as *const sockaddr_l2 as *const libc::sockaddr,
                     std::mem::size_of::<sockaddr_l2>() as u32)
            })?;

            // BDADDR_LE_PUBLIC (0x01), BDADDR_LE_RANDOM (0x02)
            let addr_type = data[8].clone() + 1;

            let mut address = [0u8; 6usize];
            let address_len = address.len();
            address.clone_from_slice(&data[9..(9 + address_len)]);


            let l2a = sockaddr_l2::new(AF_BLUETOOTH, l2cid, addr_type, address);

            handle_error(unsafe {
                connect(l2socket, &l2a as *const sockaddr_l2 as *const libc::sockaddr,
                     std::mem::size_of::<sockaddr_l2>() as u32)
            })?;

            self.l2sockets.insert(handle, l2socket);
        } else {
            let handle:u16 = ((data[4] as u16) << 8)  + (data[5] as u16);

            if self.l2sockets.contains_key(&handle) {
                handle_error(unsafe {
                    close(self.l2sockets.get(&handle).unwrap().to_owned())
                }).unwrap_or(0) as usize;

                self.l2sockets.remove(&handle);
            }
        }

        Ok(())
    }

    /// Search device by id.
    ///
    /// dev_id: is the device id if know, or None
    /// is_up: select only up device
    /// socket: hci socket
    fn dev_id_for(dev_id: Option<u16>, is_up: bool, socket: i32) -> Result<u16> {
        if dev_id.is_none() {
            let mut dev_list = hci_dev_list_req::new();

            let ioctl_res = handle_error(unsafe {
                ioctl(socket, HCI_GET_DEV_LIST_MAGIC as u64, &mut dev_list)
            });

            if let Err(e) = ioctl_res {
                return Err(e);
            }

            let dev_num = dev_list.dev_num as usize;

            for i in 0..dev_num  {
                let dev_up = (dev_list.dev_req[i].dev_opt & (1 << HCI_UP)) > 0;

                if is_up && dev_up || !is_up && !dev_up {
                    // choose the first device that is match
                    // later on, it would be good to also HCIGETDEVINFO and check the HCI_RAW flag
                    return Ok(dev_list.dev_req[i].dev_id);
                }
            }

            return Err(Error::NoDeviceFound);
        }

        return Ok(dev_id.unwrap());
    }
}
