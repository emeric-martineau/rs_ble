use hci_socket::{BtLeAddressType, HciState, BtLeConnectionComplete, HciCallback};


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
        println!("le_scan_parameters_set");
    }

    fn le_scan_enable_set(&self, state: HciState) {
    }

    fn le_scan_enable_set_cmd(&self, enable: bool, filter_duplicates: bool) {
    }

    fn error(&self, msg: String) {
        eprintln!("{}", msg);
    }

    fn le_advertising_report(&self, status: u8, typ: u8, address: String, address_type: BtLeAddressType, eir: Vec<u8>, rssi: i8) {
    }
}