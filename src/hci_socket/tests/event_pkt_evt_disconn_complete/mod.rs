use libc::c_int;
use std::collections::HashMap;
use std::io::Cursor;
use hci_socket::log::ConsoleLogger;
use hci_socket::{Hci, EVT_DISCONN_COMPLETE, BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback, HCI_EVENT_PKT};
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
    fn state_change(&self, _state: HciState) -> bool {
        false
    }

    fn address_change(&self, _address: String) -> bool {
        false
    }

    fn le_conn_complete(&self, _status: u8, _data: Option<BtLeConnectionComplete>) -> bool {
        false
    }

    fn le_conn_update_complete(&self, _status: u8, _handle: u16, _interval: f64, _latency: u16, _supervision_timeout: u16) -> bool {
        false
    }

    fn rssi_read(&self, _handle: u16, _rssi: i8) -> bool {
        false
    }

    fn disconn_complete(&self, handle: u16, reason: u8) -> bool {
        self.is_called.replace(true);

        assert_eq!(0x0201, handle);
        assert_eq!(0x03, reason);

        true
    }

    fn encrypt_change(&self, _handle: u16, _encrypt: u8) -> bool {
        false
    }

    fn acl_data_pkt(&self, _handle: u16, _cid: u16, _data: Vec<u8>) -> bool {
        false
    }

    fn read_local_version(&self, _hci_ver: u8, _hci_rev: u16, _lmp_ver: i8, _manufacturer: u16, _lmp_sub_ver: u16) -> bool {
        false
    }

    fn le_scan_parameters_set(&self) -> bool {
        false
    }

    fn le_scan_enable_set(&self, _state: HciState) -> bool {
        false
    }

    fn le_scan_enable_set_cmd(&self, _enable: bool, _filter_duplicates: bool) -> bool {
        false
    }

    fn error(&self, _msg: String) -> bool {
        false
    }

    fn le_advertising_report(&self, _status: u8, _typ: u8, _address: String, _address_type: BtLeAddressType, _eir: Vec<u8>, _rssi: i8) -> bool {
        false
    }
}

#[test]
pub fn bind_user_hci_chanel_raw_hci_event_pkt_evt_disconn_complete() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data: Vec<u8> = Vec::new();

    read_data.push(HCI_EVENT_PKT);
    read_data.push(EVT_DISCONN_COMPLETE);
    read_data.push(0x00);
    read_data.push(0x00);
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

    match Hci::new(None, false, &log, &libc) {
        Ok(mut hci) => match hci.init(Some(&callback)) {
            Ok(_) => println!("Ok"),
            Err(e) => panic!("Hci init() {:?}", e)
        },
        Err(e) =>  panic!("Hci new() {:?}", e)
    }
}