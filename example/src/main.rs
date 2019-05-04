extern crate rs_ble;

use rs_ble::hci_socket::{BluetoothHciSocket, BtHciSocketCallback};
use std::{thread, time};



fn main() {
    let callback: BtHciSocketCallback = |bhs, message| {
        println!("{:?}", message);
    };

    match BluetoothHciSocket::bind_raw(None) {
        Ok(mut a) => {
            println!("OK");
            //let b = a.poll();
            //println!("Data: {:?}", b);
            a.start(callback);

            let ten_millis = time::Duration::from_millis(5000);
            thread::sleep(ten_millis);

            a.stop();

            thread::sleep(ten_millis);

        },
        Err(e) => println!("Fail {:?}", e)
    };
    println!("Hello, world!");
}
