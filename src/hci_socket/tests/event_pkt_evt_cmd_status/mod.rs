use libc::c_int;
use std::collections::HashMap;
use hci_socket::log::ConsoleLogger;
use hci_socket::{Hci, EVT_CMD_STATUS, BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback, HCI_EVENT_PKT, LE_CREATE_CONN_CMD};
use super::{init_device_list_request, init_hci_user};
use hci_socket::unix_libc::tests::{TestLibc, NetworkPacket};
use std::cell::Cell;
use hci_socket::error::Error;
use bytes::BufMut;

pub struct TestHciEvtCmdStatusCallback {
    pub is_called: Cell<bool>
}

impl HciCallback for TestHciEvtCmdStatusCallback  {
    fn state_change(&self, _state: HciState) -> bool {
        false
    }

    fn address_change(&self, _address: String) -> bool {
        false
    }

    fn le_conn_complete(&self, status: u8, data: Option<BtLeConnectionComplete>) -> bool {
        self.is_called.replace(true);

        assert_eq!(0x01, status);
        assert_eq!(None, data);

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
pub fn bind_user_hci_channel_raw_hci_event_pkt_evt_cmd_status_not_zero() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data = NetworkPacket::new();
    
    let mut packet: Vec<u8> = Vec::new();

    packet.push(HCI_EVENT_PKT);
    packet.push(EVT_CMD_STATUS);
    // Status
    packet.push(0x01);
    // Cmd
    packet.put_u16_le(LE_CREATE_CONN_CMD);

    read_data.push(packet);

    let mut read_data_map = HashMap::new();
    read_data_map.insert(0, read_data);

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

    let callback = TestHciEvtCmdStatusCallback {
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

#[test]
pub fn bind_user_hci_channel_raw_hci_event_pkt_evt_cmd_status_zero() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data = NetworkPacket::new();
    
    let mut packet: Vec<u8> = Vec::new();

    packet.push(HCI_EVENT_PKT);
    packet.push(EVT_CMD_STATUS);
    // Status
    packet.push(0x00);
    // Cmd
    packet.put_u16_le(LE_CREATE_CONN_CMD);

    read_data.push(packet);

    let mut read_data_map = HashMap::new();
    read_data_map.insert(0, read_data);

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

    let callback = TestHciEvtCmdStatusCallback {
        is_called: Cell::new(false)
    };

    match Hci::new(None, false, &log, &libc) {
        Ok(mut hci) => match hci.init(Some(&callback)) {
            Ok(_) => assert_eq!(false, callback.is_called.get()),
            Err(e) => {
                assert_eq!(false, callback.is_called.get());

                match e {
                    Error::Other(s) => assert_eq!("Stop test", s),
                    e => panic!("Hci init() {:?}", e)
                }
            }
        },
        Err(e) =>  panic!("Hci new() {:?}", e)
    }
}

#[test]
pub fn bind_user_hci_channel_raw_hci_event_pkt_evt_cmd_status_none() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data = NetworkPacket::new();
    
    let mut packet: Vec<u8> = Vec::new();

    packet.push(HCI_EVENT_PKT);
    packet.push(EVT_CMD_STATUS);
    // Status
    packet.push(0x01);
    // Cmd
    packet.put_u16_le(0x00);

    read_data.push(packet);

    let mut read_data_map = HashMap::new();
    read_data_map.insert(0, read_data);

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

    let callback = TestHciEvtCmdStatusCallback {
        is_called: Cell::new(false)
    };

    match Hci::new(None, false, &log, &libc) {
        Ok(mut hci) => match hci.init(Some(&callback)) {
            Ok(_) => assert_eq!(false, callback.is_called.get()),
            Err(e) => {
                assert_eq!(false, callback.is_called.get());

                match e {
                    Error::Other(s) => assert_eq!("Stop test", s),
                    e => panic!("Hci init() {:?}", e)
                }
            }
        },
        Err(e) =>  panic!("Hci new() {:?}", e)
    }
}