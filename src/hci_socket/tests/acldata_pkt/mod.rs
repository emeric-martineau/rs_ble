use libc::c_int;
use std::collections::HashMap;
use hci_socket::log::ConsoleLogger;
use hci_socket::{Hci, BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback, HCI_ACLDATA_PKT, ACL_START, ACL_CONT};
use super::{init_device_list_request, init_hci_user};
use hci_socket::unix_libc::tests::{TestLibc, NetworkPacket};
use std::cell::Cell;
use bytes::BufMut;
use hci_socket::error::Error;

pub struct TestHciCommandPktAclStartOnePaquetCallback {
    pub is_called: Cell<bool>
}

impl HciCallback for TestHciCommandPktAclStartOnePaquetCallback  {
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

    fn disconn_complete(&self, _handle: u16, _reason: u8) -> bool {
        false
    }

    fn encrypt_change(&self, _handle: u16, _encrypt: u8) -> bool {
        false
    }

    fn acl_data_pkt(&self, handle: u16, cid: u16, data: Vec<u8>) -> bool {
        assert_eq!(0x111, handle);
        assert_eq!(0x0102, cid);
        assert_eq!(vec![0x01], data);

        self.is_called.replace(true);

        true
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
pub fn bind_user_hci_channel_raw_hci_acldata_pkt_acl_start_one_paquet() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);

    let mut read_data = NetworkPacket::new();

    let mut packet: Vec<u8> = Vec::new();

    let acl_start_and_handler = ACL_START << 12 | 0x111;

    packet.push(HCI_ACLDATA_PKT);
    packet.put_u16_le(acl_start_and_handler);
    // Filling
    packet.push(0x00);
    packet.push(0x00);
    // Length
    packet.put_u16_le(0x01);
    // Cid
    packet.put_u16_le(0x0102);
    // Data
    packet.push(0x01);

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

    let callback = TestHciCommandPktAclStartOnePaquetCallback {
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

pub struct TestHciCommandPktAclStartTwoPaquetCallback {
    pub is_called: Cell<bool>
}

impl HciCallback for TestHciCommandPktAclStartTwoPaquetCallback  {
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

    fn disconn_complete(&self, _handle: u16, _reason: u8) -> bool {
        false
    }

    fn encrypt_change(&self, _handle: u16, _encrypt: u8) -> bool {
        false
    }

    fn acl_data_pkt(&self, handle: u16, cid: u16, data: Vec<u8>) -> bool {
        assert_eq!(0x111, handle);
        assert_eq!(0x0102, cid);
        assert_eq!(vec![0x01, 0x02, 0x03], data);

        self.is_called.replace(true);

        true
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
pub fn bind_user_hci_channel_raw_hci_acldata_pkt_acl_start_two_paquet() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);

    let mut read_data = NetworkPacket::new();

    let mut packet1: Vec<u8> = Vec::new();

    let acl_start_and_handler = ACL_START << 12 | 0x111;

    packet1.push(HCI_ACLDATA_PKT);
    packet1.put_u16_le(acl_start_and_handler);
    // Filling
    packet1.push(0x00);
    packet1.push(0x00);
    // Length
    packet1.put_u16_le(0x03);
    // Cid
    packet1.put_u16_le(0x0102);
    // Data
    packet1.push(0x01);

    read_data.push(packet1);


    let mut packet2: Vec<u8> = Vec::new();

    let acl_cont_and_handler = ACL_CONT << 12 | 0x111;

    packet2.push(HCI_ACLDATA_PKT);
    packet2.put_u16_le(acl_cont_and_handler);
    // Filling
    packet2.push(0x00);
    packet2.push(0x00);
    // Data
    packet2.push(0x02);
    packet2.push(0x03);

    read_data.push(packet2);

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

    let callback = TestHciCommandPktAclStartTwoPaquetCallback {
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
pub fn bind_user_hci_channel_raw_hci_acldata_pkt_acl_start_cont_paquet_without_start() {
    let is_socker_hci = true;
    let is_socker_l2cap = true;
    let ioctl_hci_dev_info_call_error: HashMap<c_int, bool> = HashMap::new();
    let my_device_list = init_device_list_request( 1, true);
    let bind_sockaddr_hci = init_hci_user(0,1);

    let mut read_data = NetworkPacket::new();

    let mut packet2: Vec<u8> = Vec::new();

    let acl_cont_and_handler = ACL_CONT << 12 | 0x111;

    packet2.push(HCI_ACLDATA_PKT);
    packet2.put_u16_le(acl_cont_and_handler);
    // Filling
    packet2.push(0x00);
    packet2.push(0x00);
    // Data
    packet2.push(0x02);
    packet2.push(0x03);

    read_data.push(packet2);

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

    let callback = TestHciCommandPktAclStartTwoPaquetCallback {
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
