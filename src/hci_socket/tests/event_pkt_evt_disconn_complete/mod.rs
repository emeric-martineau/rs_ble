use libc::c_int;
use std::collections::HashMap;
use std::io::Cursor;
use hci_socket::log::ConsoleLogger;
use hci_socket::{Hci, EVT_DISCONN_COMPLETE, BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback};
use super::{init_device_list_request, init_hci_user};
use hci_socket::unix_libc::tests::TestLibc;
use std::cell::{Cell, RefCell};
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use hci_socket::error::Error;

pub struct TestHciEvtDisconnCompleteCallback {
    pub is_called: Cell<bool>
}

impl HciCallback for TestHciEvtDisconnCompleteCallback  {
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
        self.is_called.replace(true);

        assert_eq!(0x0201, handle);
        assert_eq!(0x03, reason);
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

#[test]
pub fn bind_user_hci_chanel_raw_hci_event_pkt_evt_disconn_complete() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request(0, 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data: Vec<u8> = Vec::new();

    read_data.push(EVT_DISCONN_COMPLETE);
    // Handle 0x0201
    read_data.push(0x01);
    read_data.push(0x02);
    // Reason
    read_data.push(0x03);

    let mut read_data_map = HashMap::new();
    read_data_map.insert(0, Cursor::new(read_data));

    let libc = TestLibc::new(
        is_socker_hci,
        is_socker_l2cap,
        ioctl_hci_dev_info_call_error,
        my_device_list,
        bind_sockaddr_hci,
        read_data_map);

    let log = ConsoleLogger {
        debug_level: true
    };

    let callback = TestHciEvtDisconnCompleteCallback {
        is_called: Cell::new(false)
    };

    let hci_result = Hci::new(None, false, &callback, &log, &libc);

    if let Err(e) = hci_result {
        panic!("Hci new() {:?}", e);
    }

    let mut hci = hci_result.unwrap();

    match hci.init() {
        Ok(_) => {
            panic!("Hci init() must be return error");
        },
        Err(e) => match e {
            Error::Other(reason) => assert_eq!(reason, "Stop test"),
            e => panic!("Hci inti() {:?}", e)
        }
    }
}