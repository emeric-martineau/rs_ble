extern crate rs_ble;

use rs_ble::hci_socket::{Hci, HciCallback, HciState};

struct Callback {}

impl HciCallback for Callback {
    fn state_change(&self, state: HciState) {
        println!("State change: {:?}", state);
    }
    fn address_change(&self) {}
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

fn main() {
    let callback = Callback {};

    match Hci::new(None, false, &callback) {
        Ok(mut hci) => println!("{:?}", hci.init()),
        Err(e) => println!("Fail {:?}", e)
    }

    println!("Hello, world!");
}
