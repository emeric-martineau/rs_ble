extern crate rs_ble;

use rs_ble::hci_socket::BluetoothHciSocket;

fn main() {
    match BluetoothHciSocket::bind_raw(None) {
        Ok(a) => {
            println!("OK");
        },
        Err(e) => println!("Fail {:?}", e)
    };
    println!("Hello, world!");
}
