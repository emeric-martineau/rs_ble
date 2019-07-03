use libc::c_int;
use std::collections::HashMap;
use std::io::Cursor;
use hci_socket::log::ConsoleLogger;
use hci_socket::{Hci, EVT_CMD_COMPLETE, BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback, HCI_EVENT_PKT, READ_LOCAL_VERSION_CMD, HCI_COMMAND_PKT, LE_SET_SCAN_ENABLE_CMD, LE_SET_SCAN_PARAMETERS_CMD};
use super::{init_device_list_request, init_hci_user};
use hci_socket::unix_libc::tests::{TestLibc, WriteData};
use std::cell::{Cell, RefCell};
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::thread;
use hci_socket::error::Error;
use bytes::{BufMut, BytesMut};

pub struct TestHciEvtDisconnCompleteCallback {
    pub is_called: Cell<bool>,
    pub state: Cell<HciState>
}

impl HciCallback for TestHciEvtDisconnCompleteCallback  {
    fn state_change(&self, state: HciState) -> bool {
        let s = self.state.get();

        // First call is Unsuported, second is PowerOff
        match state {
            HciState::Unsupported => {
                if s == HciState::Unauthorized {
                    self.state.replace(state);
                } else {
                    panic!("State must be Unsupported, found {:?}!", s);
                }
            },
            HciState::PoweredOff => {
                if s != HciState::Unsupported {
                    panic!("Previous state must be Unsupported!")
                }

                self.is_called.replace(true);
            },
            s => panic!(format!("State {:?} not allowed !", s))
        }

        true
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

    fn disconn_complete(&self, _handle: u16, _reason: u8) -> bool {
        false
    }

    fn encrypt_change(&self, handle: u16, encrypt: u8) -> bool {
        false
    }

    fn acl_data_pkt(&self, _handle: u16, _cid: u16, _data: Vec<u8>) -> bool {
        false
    }

    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: i8, manufacturer: u16, lmp_sub_ver: u16) -> bool {
        if self.state.get() == HciState::Unsupported {
            assert_eq!(hci_ver, 0x04);
        } else {
            assert_eq!(hci_ver, 0x06);
        }

        assert_eq!(hci_rev, 0x0605);
        assert_eq!(lmp_ver, 0x07);
        assert_eq!(manufacturer, 0x0908);
        assert_eq!(lmp_sub_ver, 0x0B0A);

        true
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
pub fn bind_user_hci_chanel_raw_hci_event_pkt_evt_cmd_complete_read_local_version_cmd_unsupported() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data: Vec<u8> = Vec::new();

    read_data.push(HCI_EVENT_PKT);
    read_data.push(EVT_CMD_COMPLETE);
    read_data.push(0x00);
    read_data.push(0x00);
    // cmd READ_LOCAL_VERSION_CMD
    read_data.put_u16_le(READ_LOCAL_VERSION_CMD);
    // status
    read_data.push(0x03);
    // Hci ver
    read_data.push(0x04);
    // Hci rev
    read_data.push(0x05);
    read_data.push(0x06);
    // Lmp ver
    read_data.push(0x07);
    // Manufacturer
    read_data.push(0x08);
    read_data.push(0x09);
    // Lmp sub ver
    read_data.push(0x0A);
    read_data.push(0x0B);

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
        is_called: Cell::new(false),
        state: Cell::new(HciState::Unauthorized)
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
pub fn bind_user_hci_chanel_raw_hci_event_pkt_evt_cmd_complete_read_local_version_cmd() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);
    let mut read_data: Vec<u8> = Vec::new();

    read_data.push(HCI_EVENT_PKT);
    read_data.push(EVT_CMD_COMPLETE);
    read_data.push(0x00);
    read_data.push(0x00);
    // cmd READ_LOCAL_VERSION_CMD
    read_data.put_u16_le(READ_LOCAL_VERSION_CMD);
    // status
    read_data.push(0x03);
    // Hci ver
    read_data.push(0x06);
    // Hci rev
    read_data.push(0x05);
    read_data.push(0x06);
    // Lmp ver
    read_data.push(0x07);
    // Manufacturer
    read_data.push(0x08);
    read_data.push(0x09);
    // Lmp sub ver
    read_data.push(0x0A);
    read_data.push(0x0B);

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
        is_called: Cell::new(false),
        state: Cell::new(HciState::Unauthorized)
    };

    match Hci::new(None, false, &log, &libc) {
        Ok(mut hci) => match hci.init(Some(&callback)) {
            Ok(_) => {
                let write_data = libc.write_data.borrow();

                assert_eq!(2, write_data.len());

                check_set_scan_enabled(write_data.get(0).unwrap());

                check_set_scan_parameters(write_data.get(1).unwrap());

            },
            Err(e) => panic!("Hci init() {:?}", e)
        },
        Err(e) =>  panic!("Hci new() {:?}", e)
    }

    fn check_set_scan_enabled(data: &WriteData) {
        assert_eq!(6, data.buf.len());

        let mut bytes = BytesMut::with_capacity(6);

        bytes.put_u8(HCI_COMMAND_PKT);
        bytes.put_u16_le(LE_SET_SCAN_ENABLE_CMD);
        bytes.put_u8(0x02);
        bytes.put_u8(0x00);
        bytes.put_u8(0x01);

        assert_eq!(bytes, data.buf);
    }

    fn check_set_scan_parameters(data: &WriteData) {
        assert_eq!(11, data.buf.len());

        let mut bytes = BytesMut::with_capacity(11);

        bytes.put_u8(HCI_COMMAND_PKT);
        bytes.put_u16_le(LE_SET_SCAN_PARAMETERS_CMD);
        bytes.put_u8(0x07);
        bytes.put_u8(0x01);
        bytes.put_u16_le(0x10);
        bytes.put_u16_le(0x10);
        bytes.put_u8(0x00);
        bytes.put_u8(0x00);
    }
}