use hci_socket::unix_libc::tests::TestLibc;
use libc::{c_int, AF_BLUETOOTH};
use std::collections::HashMap;
use hci_socket::log::ConsoleLogger;
use hci_socket::Hci;
use self::callback::TestHciCallback;
use hci_socket::hci::bluetooth::hci::{hci_dev_list_req, hci_dev_req, HCI_UP, HCI_MAX_DEV, sockaddr_hci, HCI_CHANNEL_RAW};
use hci_socket::error::Error;

mod callback;

/// Create list of bluetooth device.
fn init_device_list_request(fd: c_int, dev_id: u16, is_up: bool) -> HashMap<c_int, hci_dev_list_req> {
    let mut my_device_list: HashMap<c_int, hci_dev_list_req> = HashMap::new();

    let mut list_device = [hci_dev_req {
        dev_id: 0,
        dev_opt: 0
    }; HCI_MAX_DEV];

    if is_up {
        list_device[0] = hci_dev_req {
            dev_id,
            dev_opt: (1 << HCI_UP)
        };
    } else {
        list_device[0] = hci_dev_req {
            dev_id,
            dev_opt: 0
        };
    }

    let list_device_request = hci_dev_list_req {
        dev_num: 1,
        dev_req: list_device
    };

    my_device_list.insert(0, list_device_request);

    my_device_list
}

/// Init socket.
fn init_hci_user(socket: c_int, dev_id: u16) -> HashMap<c_int, sockaddr_hci> {
    let mut bind_sockaddr_hci: HashMap<c_int, sockaddr_hci> = HashMap::new();

    let addr = sockaddr_hci {
        hci_family: AF_BLUETOOTH as u16,
        hci_dev: dev_id,
        hci_channel: HCI_CHANNEL_RAW
    };

    bind_sockaddr_hci.insert(socket, addr);

    bind_sockaddr_hci
}

#[test]
pub fn bind_user_hci_chanel_raw() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request(0, 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);

    let libc = TestLibc::new(
        is_socker_hci,
        is_socker_l2cap,
        ioctl_hci_dev_info_call_error,
        my_device_list,
        bind_sockaddr_hci);

    let callback = TestHciCallback {};
    let log = ConsoleLogger {
        debug_level: true
    };

    match Hci::new(None, false, &callback, &log, &libc) {
        Ok(mut hci) => println!("{:?}", hci.init()),
        Err(e) =>  panic!("Hci new {:?}", e)
    }
}

#[test]
pub fn bind_user_hci_chanel_raw_device_not_found() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();

    let mut my_device_list: HashMap<c_int, hci_dev_list_req> = HashMap::new();

    let list_device_request = hci_dev_list_req {
        dev_num: 0,
        dev_req: [hci_dev_req {
            dev_id: 0,
            dev_opt: 0
        }; HCI_MAX_DEV]
    };

    my_device_list.insert(0, list_device_request);

    let bind_sockaddr_hci = init_hci_user(0,1);

    let libc = TestLibc::new(
        is_socker_hci,
        is_socker_l2cap,
        ioctl_hci_dev_info_call_error,
        my_device_list,
        bind_sockaddr_hci);

    let callback = TestHciCallback {};
    let log = ConsoleLogger {
        debug_level: true
    };

    match Hci::new(None, false, &callback, &log, &libc) {
        Ok(mut hci) => panic!("No error raised!"),
        Err(e) =>  match e {
            Error::NoDeviceFound => println!("Ok"),
            _ => panic!("Error must be Error::NoDeviceFound")
        }
    }
}

// TODO : hci_chanel_user