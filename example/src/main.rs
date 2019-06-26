extern crate rs_ble;

use rs_ble::hci_socket::{Hci, HciCallback, HciState, BtLeConnectionComplete, BtLeAddressType};
use rs_ble::hci_socket::log::ConsoleLogger;
use rs_ble::hci_socket::unix_libc::DefaultLibc;

struct Callback {}

impl HciCallback for Callback {
    fn state_change(&self, state: HciState) -> bool {
        println!("State change: {:?}", state);
        false
    }

    fn address_change(&self, address: String) -> bool {
        println!("Address change: {:?}", address);
        false
    }

    fn le_conn_complete(&self, status: u8, data: Option<BtLeConnectionComplete>) -> bool {
        match data {
            Some(a) => println!("Status complete: {} data: {:?}", status, a),
            None => println!("Status complete: {}", status)
        };
        false
    }

    fn le_conn_update_complete(&self, status: u8, handle: u16, interval: f64, latency: u16, supervision_timeout: u16) -> bool {
        println!("Connection update status: {}, handle: {}, interval: {}, latency: {}, supervision_timeout: {}", status, handle, interval, latency, supervision_timeout);
        false
    }

    fn rssi_read(&self, handle: u16, rssi: i8) -> bool {
        println!("Rssi read, handle: {}, rssi: {}", handle, rssi);
        false
    }

    fn disconn_complete(&self, handle: u16, reason: u8) -> bool {
        println!("disconn_complete -> handle: {:?}, reason: {:?}", handle, reason);
        false
    }

    fn encrypt_change(&self, handle: u16, encrypt: u8) -> bool {
        println!("encrypt_change -> handle: {:?}, encrypt: {:?}", handle, encrypt);
        false
    }

    fn acl_data_pkt(&self, handle: u16, cid: u16, data: Vec<u8>) -> bool {
        println!("acl_data_pkt -> handle: {}, cid: {}, data: {:?}", handle, cid, data);
        false
    }

    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: i8, manufacturer: u16, lmp_sub_ver: u16) -> bool {
        println!("read local version -> hci_ver: {:?} hci_rev: {:?} lmp_ver: {:?} manufacturer: {:?} lmp_sub_ver: {:?}", hci_ver, hci_rev, lmp_ver, manufacturer, lmp_sub_ver);
        false
    }

    fn le_scan_parameters_set(&self) -> bool {
        println!("le_scan_parameters_set");
        false
    }

    fn le_scan_enable_set(&self, state: HciState) -> bool {
        println!("le_scan_enable_set -> state: {:?}", state);
        false
    }

    fn le_scan_enable_set_cmd(&self, enable: bool, filter_duplicates: bool) -> bool {
        println!("le_scan_enable_set_cmd -> enable: {}, filter_duplicates: {}", enable, filter_duplicates);
        false
    }

    fn error(&self, msg: String) -> bool {
        eprintln!("{}", msg);
        false
    }

    fn le_advertising_report(&self, status: u8, typ: u8, address: String, address_type: BtLeAddressType, eir: Vec<u8>, rssi: i8) -> bool {
        println!("le_advertising_report status -> status: {} type: {} address: {} address type: {:?} eir: {:?} rssi: {}", status, typ, address, address_type, eir, rssi);
        false
    }
}

fn main() {
    let callback = Callback {};
    let log = ConsoleLogger {
        debug_level: true
    };
    let libc = DefaultLibc{};

    match Hci::new(None, false, &log, &libc) {
        Ok(mut hci) => println!("{:?}", hci.init(Some(&callback))),
        Err(e) => println!("Fail {:?}", e)
    }

    println!("Hello, world!");
}
