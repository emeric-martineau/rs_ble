extern crate rs_ble;

use rs_ble::hci_socket::{Hci, HciCallback, HciState, BtLeConnectionComplete, BtLeAddressType};
use rs_ble::hci_socket::log::ConsoleLogger;

struct Callback {}

impl HciCallback for Callback {
    fn state_change(&self, state: HciState) {
        println!("State change: {:?}", state);
    }

    fn address_change(&self, address: String) {
        println!("Address change: {:?}", address);
    }

    fn le_conn_complete(&self, status: u8, data: Option<BtLeConnectionComplete>) {
        match data {
            Some(a) => println!("Status complete: {} data: {:?}", status, a),
            None => println!("Status complete: {}", status)
        };
    }

    fn le_conn_update_complete(&self, status: u8, handle: u16, interval: f64, latency: u16, supervision_timeout: u16) {
        println!("Connection update status: {}, handle: {}, interval: {}, latency: {}, supervision_timeout: {}", status, handle, interval, latency, supervision_timeout)
    }

    fn rssi_read(&self, handle: u16, rssi: i8) {
        println!("Rssi read, handle: {}, rssi: {}", handle, rssi);
    }

    fn disconn_complete(&self, handle: u16, reason: u8) {
        println!("disconn_complete -> handle: {:?}, reason: {:?}", handle, reason);
    }

    fn encrypt_change(&self, handle: u16, encrypt: u8) {
        println!("encrypt_change -> handle: {:?}, encrypt: {:?}", handle, encrypt);
    }

    fn acl_data_pkt(&self, handle: u16, cid: u16, data: Vec<u8>) {
        println!("acl_data_pkt -> handle: {}, cid: {}, data: {:?}", handle, cid, data);
    }

    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: i8, manufacturer: u16, lmp_sub_ver: u16) {
        println!("read local version -> hci_ver: {:?} hci_rev: {:?} lmp_ver: {:?} manufacturer: {:?} lmp_sub_ver: {:?}", hci_ver, hci_rev, lmp_ver, manufacturer, lmp_sub_ver)
    }

    fn le_scan_parameters_set(&self) {
        println!("le_scan_parameters_set");
    }

    fn le_scan_enable_set(&self, state: HciState) {
        println!("le_scan_enable_set -> state: {:?}", state);
    }

    fn le_scan_enable_set_cmd(&self, enable: bool, filter_duplicates: bool) {
        println!("le_scan_enable_set_cmd -> enable: {}, filter_duplicates: {}", enable, filter_duplicates);
    }

    fn error(&self, msg: String) {
        eprintln!("{}", msg);
    }

    fn le_advertising_report(&self, status: u8, typ: u8, address: String, address_type: BtLeAddressType, eir: Vec<u8>, rssi: i8) {
        println!("le_advertising_report status -> status: {} type: {} address: {} address type: {:?} eir: {:?} rssi: {}", status, typ, address, address_type, eir, rssi);
    }
}

fn main() {
    let callback = Callback {};
    let log = ConsoleLogger {
        debug_level: true
    };

    match Hci::new(None, false, &callback, &log) {
        Ok(mut hci) => println!("{:?}", hci.init()),
        Err(e) => println!("Fail {:?}", e)
    }

    println!("Hello, world!");
}
