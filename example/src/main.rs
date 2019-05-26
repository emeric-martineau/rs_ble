extern crate rs_ble;

use rs_ble::hci_socket::{Hci, HciCallback, HciState, HciLogger};

struct Callback {}

impl HciCallback for Callback {
    fn state_change(&self, state: HciState) {
        println!("State change: {:?}", state);
    }
    fn address_change(&self, address: String) {
        println!("Address change: {:?}", address);
    }

    fn le_conn_complete(&self) {}
    fn le_conn_update_complete(&self) {}
    fn rssi_read(&self) {}

    fn disconn_complete(&self, handle: u16, reason: u8) {
        println!("EVT_DISCONN_COMPLETE");
        println!("handle: {:?}, reason: {:?}", handle, reason);
    }

    fn encrypt_change(&self, handle: u16, encrypt: u8) {
        println!("EVT_ENCRYPT_CHANGE");
        println!("handle: {:?}, encrypt: {:?}", handle, encrypt);
    }

    fn acl_data_pkt(&self) {}

    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: u8, manufacturer: u16, lmp_sub_ver: u16) {
        println!("read local version: hci_ver: {:?} hci_rev: {:?} lmp_ver: {:?} manufacturer: {:?} lmp_sub_ver: {:?}", hci_ver, hci_rev, lmp_ver, manufacturer, lmp_sub_ver)
    }
}

pub struct MyLogger;

impl HciLogger for MyLogger {
    fn is_debug_enable(&self) -> bool {
        true
    }

    fn debug(&self, expr: &str) {
        println!("{}", expr);
    }
}

fn main() {
    let callback = Callback {};
    let log = MyLogger {};

    match Hci::new_with_logger(None, false, &callback, Some(&log)) {
        Ok(mut hci) => println!("{:?}", hci.init()),
        Err(e) => println!("Fail {:?}", e)
    }

    println!("Hello, world!");
}
