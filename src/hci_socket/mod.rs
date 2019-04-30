//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
pub mod bluetooth;
pub mod error;

use libc::{AF_BLUETOOTH, SOCK_CLOEXEC, SOCK_RAW, socket, ioctl, bind};
use self::error::{Result, handle_error, Error};
use self::bluetooth::{BTPROTO_HCI};
use self::bluetooth::hci::{sockaddr_hci, hci_dev_list_req, hci_dev_info, HCI_CHANNEL_USER, HCI_GET_DEV_LIST_MAGIC, HCI_UP, HCI_CHANNEL_RAW, HCI_GET_DEV_MAGIC};

pub struct BluetoothHciSocket {
    /// HCI mode
    mode: u16,
    /// Socket network
    socket: i32,
    /// Device Id. It never use ?!?
    dev_id: Option<u16>,
    /// Device MAC address
    address: [u8; 6usize],
    /// Device address type
    address_type: u8
}

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

        let mut addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: hci_dev.unwrap(),
            hci_channel: HCI_CHANNEL_USER
        };

        handle_error(unsafe {
            bind(socket, &addr as *const sockaddr_hci as *const libc::sockaddr,
                       std::mem::size_of::<sockaddr_hci>() as u32)
        })?;

        Ok(BluetoothHciSocket {
            mode: HCI_CHANNEL_USER,
            socket,
            dev_id:  Some(addr.hci_dev),
            address: [0, 0, 0, 0, 0, 0],
            address_type: 0
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

        let mut addr = sockaddr_hci {
            hci_family: AF_BLUETOOTH as u16,
            hci_dev: hci_dev.unwrap(),
            hci_channel: HCI_CHANNEL_RAW
        };

        handle_error(unsafe {
            bind(socket, &addr as *const sockaddr_hci as *const libc::sockaddr,
                       std::mem::size_of::<sockaddr_hci>() as u32)
        })?;

        let mut device_information = hci_dev_info::new(dev_id);

        let ioctl_res = handle_error(unsafe {
            ioctl(socket, HCI_GET_DEV_MAGIC as u64, &mut device_information)
        });

        if let Err(e) = ioctl_res {
            return Err(e);
        }

        let address_type = if device_information.type_ == 3 {
            // 3 is a weird type, use 1 (public) instead
            1
        } else {
            device_information.type_
        };

        Ok(BluetoothHciSocket {
            mode: HCI_CHANNEL_RAW,
            socket,
            dev_id:  Some(addr.hci_dev),
            address: device_information.bdaddr.b,
            address_type
        })
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
