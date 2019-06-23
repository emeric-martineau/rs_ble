use hci_socket::unix_libc::tests::TestLibc;
use libc::{c_int, AF_BLUETOOTH};
use std::collections::HashMap;
use std::io::Cursor;
use hci_socket::log::ConsoleLogger;
use hci_socket::Hci;
use hci_socket::hci::bluetooth::hci::{hci_dev_list_req, hci_dev_req, HCI_UP, HCI_MAX_DEV, sockaddr_hci, HCI_CHANNEL_RAW};
use hci_socket::error::Error;
use hci_socket::{BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback};

mod event_pkt_evt_disconn_complete;

pub struct TestHciCallback;

impl HciCallback for TestHciCallback {
    fn state_change(&self, state: HciState) {
    }

    fn address_change(&self, address: String) {
    }

    fn le_conn_complete(&self, status: u8, data: Option<BtLeConnectionComplete>) {
    }

    fn le_conn_update_complete(&self, status: u8, handle: u16, interval: f64, latency: u16, supervision_timeout: u16) {
    }

    fn rssi_read(&self, handle: u16, rssi: i8) {
    }

    fn disconn_complete(&self, handle: u16, reason: u8) {
    }

    fn encrypt_change(&self, handle: u16, encrypt: u8) {
    }

    fn acl_data_pkt(&self, handle: u16, cid: u16, data: Vec<u8>) {
    }

    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: i8, manufacturer: u16, lmp_sub_ver: u16) {
    }

    fn le_scan_parameters_set(&self) {
    }

    fn le_scan_enable_set(&self, state: HciState) {
    }

    fn le_scan_enable_set_cmd(&self, enable: bool, filter_duplicates: bool) {
    }

    fn error(&self, msg: String) {
    }

    fn le_advertising_report(&self, status: u8, typ: u8, address: String, address_type: BtLeAddressType, eir: Vec<u8>, rssi: i8) {
    }
}

/// Create list of bluetooth device.
pub fn init_device_list_request(fd: c_int, dev_id: u16, is_up: bool) -> HashMap<c_int, hci_dev_list_req> {
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
pub fn init_hci_user(socket: c_int, dev_id: u16) -> HashMap<c_int, sockaddr_hci> {
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
    let read_data: HashMap<c_int, Cursor<Vec<u8>>> = HashMap::new();

    let libc = TestLibc::new(
        is_socker_hci,
        is_socker_l2cap,
        ioctl_hci_dev_info_call_error,
        my_device_list,
        bind_sockaddr_hci,
        read_data);

    let callback = TestHciCallback {};
    let log = ConsoleLogger {
        debug_level: true
    };

    match Hci::new(None, false, &callback, &log, &libc) {
        Ok(mut hci) => println!("{:?}", hci.init()),
        Err(e) =>  panic!("Hci new() {:?}", e)
    }
}

#[test]
pub fn bind_user_hci_chanel_raw_device_not_found() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let read_data: HashMap<c_int, Cursor<Vec<u8>>> = HashMap::new();

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
        bind_sockaddr_hci,
        read_data);

    let callback = TestHciCallback {};
    let log = ConsoleLogger {
        debug_level: true
    };

    match Hci::new(None, false, &callback, &log, &libc) {
        Ok(hci) => panic!("No error raised!"),
        Err(e) =>  match e {
            Error::NoDeviceFound => println!("Ok"),
            e => panic!("Error must be Error::NoDeviceFound; Found {:?}", e)
        }
    }
}

#[test]
pub fn bind_user_hci_chanel_raw_socket_error() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request(0, 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let read_data: HashMap<c_int, Cursor<Vec<u8>>> = HashMap::new();

    let libc = TestLibc::new(
        is_socker_hci,
        is_socker_l2cap,
        ioctl_hci_dev_info_call_error,
        my_device_list,
        bind_sockaddr_hci,
        read_data);

    let callback = TestHciCallback {};
    let log = ConsoleLogger {
        debug_level: true
    };

    match Hci::new(None, false, &callback, &log, &libc) {
        Ok(mut hci) => match hci.init() {
            Ok(_) => panic!("Hci init() must be return error"),
            Err(e) => match e {
                Error::PermissionDenied => println!("Ok"),
                e => panic!("Error must be Error::PermissionDenied; Found {:?}", e)
            }
        },
        Err(e) =>  panic!("Hci new() {:?}", e)
    }
}


// TODO : hci_chanel_user