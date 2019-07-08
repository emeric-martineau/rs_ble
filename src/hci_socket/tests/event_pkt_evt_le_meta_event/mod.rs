use libc::c_int;
use std::collections::HashMap;
use std::io::Cursor;
use hci_socket::log::ConsoleLogger;
use hci_socket::{Hci, EVT_CMD_STATUS, BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback, HCI_EVENT_PKT, EVT_LE_META_EVENT, EVT_LE_CONN_COMPLETE};
use super::{init_device_list_request, init_hci_user};
use hci_socket::unix_libc::tests::TestLibc;
use std::cell::{Cell, RefCell};
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use hci_socket::error::Error;
use bytes::BufMut;

pub struct TestHciEvtLeMetaEventCallback {
    pub is_called: Cell<bool>
}

impl HciCallback for TestHciEvtLeMetaEventCallback  {
    fn state_change(&self, _state: HciState) -> bool {
        false
    }

    fn address_change(&self, _address: String) -> bool {
        false
    }

    fn le_conn_complete(&self, status: u8, data: Option<BtLeConnectionComplete>) -> bool {
        let data = data.unwrap();

        assert_eq!(0x01, status);
        assert_eq!(0x0203, data.handle);
        assert_eq!(0x04, data.role);
        assert_eq!(super::BtLeAddressType::Random, data.address_type);
        assert_eq!("05:06:07:08:09:0a", data.address);
        assert_eq!(0x0B as f64 * 1.25 as f64, data.interval);
        assert_eq!(0x0C, data.latency);
        assert_eq!(0x0D * 10, data.supervision_timeout);
        assert_eq!(0x0E, data.master_clock_accuracy);

        self.is_called.replace(true);

        true
    }

    fn le_conn_update_complete(&self, _status: u8, _handle: u16, _interval: f64, _latency: u16, _supervision_timeout: u16) -> bool {
        false
    }

    fn rssi_read(&self, _handle: u16, _rssi: i8) -> bool {
        false
    }

    fn disconn_complete(&self, _handle: u16, _reason: u8) -> bool {
        false
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
pub fn bind_user_hci_chanel_raw_hci_event_pkt_evt_le_meta_event_evt_le_conn_complete() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data: Vec<u8> = Vec::new();

    read_data.push(HCI_EVENT_PKT);
    read_data.push(EVT_LE_META_EVENT);
    // Event type
    read_data.push(EVT_LE_CONN_COMPLETE);
    // Event status
    read_data.push(0x01);
    // Data
    // Handle
    read_data.put_u16_le(0x0203);
    // Role
    read_data.push(0x04);
    // Random
    read_data.push(0x01);
    // Mac address
    read_data.push(0x0A);
    read_data.push(0x09);
    read_data.push(0x08);
    read_data.push(0x07);
    read_data.push(0x06);
    read_data.push(0x05);
    // Interval
    read_data.put_u16_le(0x0B);
    // Latency
    read_data.put_u16_le(0x0C);
    // Supervision timeout
    read_data.put_u16_le(0x0D);
    // Master clock accuracy
    read_data.push(0x0E);

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

    let callback = TestHciEvtLeMetaEventCallback {
        is_called: Cell::new(false)
    };

    match Hci::new(None, false, &log, &libc) {
        Ok(mut hci) => match hci.init(Some(&callback)) {
            Ok(_) => assert_eq!(true, callback.is_called.get()),
            Err(e) => panic!("Hci init() {:?}", e)
        },
        Err(e) =>  panic!("Hci new() {:?}", e)
    }
}

// TODO EVT_LE_ADVERTISING_REPORT
// TODO EVT_LE_CONN_UPDATE_COMPLETE