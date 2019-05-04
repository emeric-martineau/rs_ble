//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
pub mod hci;

use self::hci::BluetoothHciSocket;
/*
var Hci = function() {
  this._socket = new BluetoothHciSocket();
  this._isDevUp = null;
  this._state = null;
  this._deviceId = null;

  this._handleBuffers = {};

  this.on('stateChange', this.onStateChange.bind(this));
};
*/
/// Hci structure.
#[derive(Debug)]
pub struct Hci {
    socket: BluetoothHciSocket,
    is_dev_up: bool,
    state: str,
    device_id: str,
    handle_buffers: str
}

impl Hci {
    pub fn init(dev_id: Option<u16>) -> Hci {
/*
  this._socket.on('data', this.onSocketData.bind(this));
  this._socket.on('error', this.onSocketError.bind(this));

  var deviceId = process.env.NOBLE_HCI_DEVICE_ID ? parseInt(process.env.NOBLE_HCI_DEVICE_ID, 10) : undefined;

  if (process.env.HCI_CHANNEL_USER) {
    this._deviceId = this._socket.bindUser(deviceId);
    this._socket.start();

    this.reset();
  } else {
    this._deviceId = this._socket.bindRaw(deviceId);
    this._socket.start();

    this.pollIsDevUp();
  }
*/

    }
}