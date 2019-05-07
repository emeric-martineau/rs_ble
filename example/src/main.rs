extern crate rs_ble;

use rs_ble::hci_socket::Hci;



fn main() {
    match Hci::new(None, false) {
        Ok(mut hci) => println!("{:?}", hci.init()),
        Err(e) => println!("Fail {:?}", e)
    }

    println!("Hello, world!");
}
