//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
use hci_socket::hci::Hci;
use hci_socket::log::NullLogger;
use hci_socket::unix_libc::DefaultLibc;
use std::collections::HashMap;

pub mod hci;
pub mod debug;
pub mod log;
pub mod error;
pub mod unix_libc;

#[cfg(test)]
pub mod tests;

pub struct RsbleBindings<'a>  {
    state: u8,
    addresses: HashMap<String, String>,
    addresseTypes: HashMap<String, String>,
    connectable: HashMap<String, String>,
    pendingConnectionUuid: String,
    connectionQueue: Vec<String>,

    handles: HashMap<String, String>,
    gatts: HashMap<String, String>,
    aclStreams: HashMap<String, String>,
    signalings: HashMap<String, String>,

    hci: Hci<'a>,
    //gap: Gap
}

impl<'a>  RsbleBindings<'a>  {
    fn new(dev_id: Option<u16>, is_hci_channel_user: bool) -> Self {
        RsbleBindings {
            state: 0,
            addresses: HashMap::new(),
            addresseTypes: HashMap::new(),
            connectable: HashMap::new(),
            pendingConnectionUuid: String::new(),
            connectionQueue: Vec::new(),
            handles: HashMap::new(),
            gatts: HashMap::new(),
            aclStreams: HashMap::new(),
            signalings: HashMap::new(),
            hci: Hci::new(dev_id, is_hci_channel_user, &NullLogger{}, &DefaultLibc{}).unwrap()
        }
    }
}