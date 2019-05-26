//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
pub mod hci;
pub mod debug;

use std::{thread, time};
use std::io::Cursor;

use self::hci::{BluetoothHciSocket};
use self::hci::error::{Result, Error};
use self::debug::HciSocketDebug;

use bytes::{BytesMut, BufMut, Bytes, Buf};

/// Internal state of Hci
#[derive(Debug)]
enum HciStructState {
    Created,
    CreatedHciChannelUser,
    RunningPollDevUp,
    Running,
    Stopping
}

/// State of Hci interface.
#[derive(Debug, Clone, PartialEq)]
pub enum HciState {
    PoweredOff,
    PoweredOn,
    Unauthorized,
    Unsupported
}

const HCI_COMMAND_PKT: u8 = 0x01;
const HCI_ACLDATA_PKT: u8 = 0x02;
const HCI_EVENT_PKT: u8 = 0x04;

const OGF_HOST_CTL: u16 = 0x03;
const OGF_INFO_PARAM: u16 = 0x04;
const OGF_STATUS_PARAM: u16 = 0x05;
const OGF_LE_CTL: u16 = 0x08;

const EVT_DISCONN_COMPLETE: u8 = 0x05;
const EVT_ENCRYPT_CHANGE: u8 = 0x08;
const EVT_CMD_COMPLETE: u8 = 0x0e;
const EVT_CMD_STATUS: u8 = 0x0f;
const EVT_LE_META_EVENT: u8 = 0x3e;

const OCF_RESET: u16 = 0x0003;
const OCF_READ_LOCAL_VERSION: u16 = 0x0001;
const OCF_WRITE_LE_HOST_SUPPORTED: u16 = 0x006D;
const OCF_SET_EVENT_MASK: u16 = 0x0001;
const OCF_READ_LE_HOST_SUPPORTED: u16 = 0x006C;
const OCF_READ_BD_ADDR: u16 = 0x0009;
const OCF_READ_RSSI: u16 = 0x0005;
const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000b;
const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000c;

const SET_EVENT_MASK_CMD: u16 = OCF_SET_EVENT_MASK | OGF_HOST_CTL << 10;
const READ_LOCAL_VERSION_CMD: u16 = OCF_READ_LOCAL_VERSION | (OGF_INFO_PARAM << 10);
const WRITE_LE_HOST_SUPPORTED_CMD: u16 = OCF_WRITE_LE_HOST_SUPPORTED | OGF_HOST_CTL << 10;
const READ_LE_HOST_SUPPORTED_CMD: u16 = OCF_READ_LE_HOST_SUPPORTED | OGF_HOST_CTL << 10;
const READ_BD_ADDR_CMD: u16 = OCF_READ_BD_ADDR | (OGF_INFO_PARAM << 10);
const RESET_CMD:u16 = OCF_RESET | OGF_HOST_CTL << 10;
const READ_RSSI_CMD: u16 = OCF_READ_RSSI | OGF_STATUS_PARAM << 10;
const LE_SET_SCAN_ENABLE_CMD: u16 = OCF_LE_SET_SCAN_ENABLE | OGF_LE_CTL << 10;

const LE_SET_SCAN_PARAMETERS_CMD: u16 = OCF_LE_SET_SCAN_PARAMETERS | OGF_LE_CTL << 10;

const HCI_VERSION_6: u8 = 0x06;

/// Callback when receive data.
pub trait HciCallback {
    /// Call when change state.
    fn state_change(&self, state: HciState);
    fn address_change(&self);
    fn le_conn_complete(&self);
    fn le_conn_update_complete(&self);
    fn rssi_read(&self);
    /// Call when BT peripheral disconnect.
    fn disconn_complete(&self, handle: u16, reason: u8);
    /// Call when BT encrypt change.
    fn encrypt_change(&self, handle: u16, encrypt: u8);
    fn acl_data_pkt(&self);
    /// Call when get version.
    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: u8, manufacturer: u16, lmp_sub_ver: u16);
}

pub trait HciLogger {
    fn is_debug_enable(&self) -> bool;
    fn debug(&self, expr: &str);
}

pub struct NoneLogger;

impl HciLogger for NoneLogger {
    fn is_debug_enable(&self) -> bool {
        false
    }

    fn debug(&self, _expr: &str) {}
}

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
pub struct Hci<'a> {
    socket: BluetoothHciSocket,
    /*
    state: str,
    device_id: str,
    handle_buffers: str,*/
    /// Local dev up
    is_dev_up: bool,
    /// Send stop to pool
    stop_pool: bool,
    /// Internal state of struct Hci
    struct_state: HciStructState,
    /// Callback
    callback: &'a HciCallback,
    /// State of Hci
    state: HciState,
    /// Logger.
    logger: Option<&'a HciLogger>
}

impl<'a> Hci<'a> {
    /// Create Hci interface.
    pub fn new(dev_id: Option<u16>, is_hci_channel_user: bool, callback: &'a HciCallback) -> Result<Self> {
        Hci::new_with_logger(dev_id, is_hci_channel_user, callback, None)
    }

    pub fn new_with_logger(dev_id: Option<u16>, is_hci_channel_user: bool, callback: &'a HciCallback, logger: Option<&'a HciLogger>) -> Result<Self> {
        let socket;
        let hci;

        if is_hci_channel_user {
            match BluetoothHciSocket::bind_user(dev_id) {
                Ok(s) => socket = s,
                Err(e) => return Err(e)
            };

            hci = Hci {
                socket,
                is_dev_up: false,
                stop_pool: false,
                struct_state: HciStructState::CreatedHciChannelUser,
                callback,
                state: HciState::PoweredOff,
                logger
            };
        } else {
            match BluetoothHciSocket::bind_raw(dev_id) {
                Ok(s) => socket = s,
                Err(e) => return Err(e)
            };

            hci = Hci {
                socket,
                is_dev_up: false,
                stop_pool: false,
                struct_state: HciStructState::Created,
                callback,
                state: HciState::PoweredOff,
                logger
            };
        }

        Ok(hci)
    }

    /// State of Hci.
    pub fn state(&mut self) -> HciState {
        self.state.clone()
    }

    /// Print debug
    pub fn debug(&mut self, expr: &str) {
        if let Some(log) = self.logger {
            if log.is_debug_enable() {
                log.debug(expr);
            }
        }
    }

    /// Run init bluetooth adapter and poll data.
    pub fn init(&mut self) -> Result<()> {
        let wait_time = time::Duration::from_millis(1000);

        loop {
            match self.socket.poll() {
                Ok(data) => {
                    if data.len() > 0 {
                        let mut cursor = Cursor::new(data);
                        self.on_socket_data(&mut cursor)?;
                    }
                },
                Err(e) => return Err(e)
            }

            match self.struct_state {
                HciStructState::CreatedHciChannelUser => {
                    self.reset()?;
                    self.struct_state = HciStructState::Running
                },
                HciStructState::Created => {
                    self.poll_is_dev_up()?;
                    self.struct_state = HciStructState::RunningPollDevUp
                },
                HciStructState::RunningPollDevUp => self.poll_is_dev_up()?,
                ref e => return Err(Error::Other(format!("Invalid state {:?}", e)))
            }

            thread::sleep(wait_time);

            if self.stop_pool {
                self.struct_state = HciStructState::Stopping;
                break;
            }
        }

        Ok(())
    }

    /// Reset bluetooth adapter.
    fn reset(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(OCF_RESET as u16 | ((OGF_HOST_CTL as u16) << 10) as u16);
        cmd.put_u8(0x00);

        self.debug(&format!("reset - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Check if device is up.
    fn poll_is_dev_up(&mut self) -> Result<()> {
        let is_dev_up ;

        match self.socket.is_dev_up() {
            Ok(b) => is_dev_up = b,
            Err(_) => is_dev_up = false
        };

        if self.is_dev_up != is_dev_up {
            if is_dev_up {
                self.set_socket_filter()?;
                self.set_event_mask()?;
                self.set_le_event_mask()?;
                self.read_local_version()?;
                self.write_le_host_supported()?;
                self.read_le_host_supported()?;
                self.read_bd_addr()?;
            }
        } else {
            self.callback.state_change(HciState::PoweredOff)
        }

        self.is_dev_up = is_dev_up;

        // In original code of Noble :
        // setTimeout(this.pollIsDevUp.bind(this), 1000);
        // But here, whe do this in init() method

        Ok(())
    }

    /// Set filter of socket.
    fn set_socket_filter(&mut self) -> Result<()> {
        let mut filter = BytesMut::with_capacity(14);

        let type_mask= (1 << HCI_COMMAND_PKT) as u32 | (1 << HCI_EVENT_PKT) | (1 << HCI_ACLDATA_PKT);
        let event_mask_1= (1 << EVT_DISCONN_COMPLETE) as u32 | (1 << EVT_ENCRYPT_CHANGE) | (1 << EVT_CMD_COMPLETE) | (1 << EVT_CMD_STATUS);
        let event_mask_2 = (1 << (EVT_LE_META_EVENT - 32)) as u32;
        let opcode: u16 = 0;

        filter.put_u32_le(type_mask);
        filter.put_u32_le(event_mask_1);
        filter.put_u32_le(event_mask_2);
        filter.put_u16_le(opcode);

        self.debug(&format!("setting filter to: {:?}", HciSocketDebug(&filter)));

        self.socket.set_filter(&filter)?;

        Ok(())
    }

    /// Set type event.
    fn set_event_mask(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(12);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(SET_EVENT_MASK_CMD as u16);

        // Event mask length
        cmd.put_u8(8);

        // Event mask new Buffer('fffffbff07f8bf3d', 'hex');
        cmd.put_u8(0xff);
        cmd.put_u8(0xff);
        cmd.put_u8(0xfb);
        cmd.put_u8(0xff);
        cmd.put_u8(0x07);
        cmd.put_u8(0xf8);
        cmd.put_u8(0xbf);
        cmd.put_u8(0x3d);

        self.debug(&format!("set event mask - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Set type of event for Low-Energy bluetooth.
    fn set_le_event_mask(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(12);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(SET_EVENT_MASK_CMD as u16);

        // Event mask length
        cmd.put_u8(8);

        // Event mask new Buffer('1f00000000000000', 'hex');
        cmd.put_u8(0x1f);
        cmd.put_u8(0x00);
        cmd.put_u8(0x00);
        cmd.put_u8(0x00);
        cmd.put_u8(0x00);
        cmd.put_u8(0x00);
        cmd.put_u8(0x00);
        cmd.put_u8(0x00);

        self.debug(&format!("set le event mask - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Read version of bluetooth supported by local adapter.
    fn read_local_version(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_LOCAL_VERSION_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("read local version - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Set Low-Energie Host mode for local adapter.
    fn write_le_host_supported(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(WRITE_LE_HOST_SUPPORTED_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("write LE host supported - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Read Low-Energie Host mode for local adapter.
    fn read_le_host_supported(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_LE_HOST_SUPPORTED_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("read LE host supported - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Read address.
    fn read_bd_addr(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_BD_ADDR_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("read bd addr - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Enable scan.
    fn set_scan_enabled(&mut self, enabled: bool, filter_duplicates: bool) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(6);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(LE_SET_SCAN_ENABLE_CMD as u16);

        // Length
        cmd.put_u8(0x02);

        // enable: 0 -> disabled, 1 -> enabled
        if enabled {
            cmd.put_u8(0x01);
        } else {
            cmd.put_u8(0x00);
        }

        // duplicates: 0 -> duplicates, 1 -> non duplicates
        if filter_duplicates {
            cmd.put_u8(0x01);
        } else {
            cmd.put_u8(0x00);
        }

        self.debug(&format!("set scan enabled - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Set scan.
    fn set_scan_parameters(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(11);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(LE_SET_SCAN_PARAMETERS_CMD as u16);

        // Length
        cmd.put_u8(0x07);

        // data
        cmd.put_u8(0x01); // type: 0 -> passive, 1 -> active
        cmd.put_u16_le(0x0010); // internal, ms * 1.6
        cmd.put_u16_le(0x0010); // window, ms * 1.6
        cmd.put_u8(0x00); // own address type: 0 -> public, 1 -> random
        cmd.put_u8(0x00); // filter: 0 -> all event types

        self.debug(&format!("set scan parameters - writing: {:?}", HciSocketDebug(&cmd)));

        self.socket.write(&cmd)?;

        Ok(())
    }

    /// Manage response from bluetooth.
    fn on_socket_data(&mut self, data: &mut Cursor<Bytes>) -> Result<()> {
        self.debug(&format!("on_socket_data: {:?}", data));

        // data[0]
        let event_type = data.get_u8();

        self.debug(&format!("\tevent type = {}", event_type));

        match event_type {
            HCI_EVENT_PKT => self.manage_hci_event_pkt(data),
            HCI_ACLDATA_PKT => println!("HCI_EVENT_PKT"), // TODO
            HCI_COMMAND_PKT => println!("HCI_EVENT_PKT"), // TODO
            e => {
                // TODO send error to caller
                println!("Unknown event type from bluetooth: {}", e)
            }
        }

        Ok(())
    }

    /// Manage response type hci event pkt from bluetooth.
    fn manage_hci_event_pkt(&mut self, data: &mut Cursor<Bytes>) {
        // data[1]
        let sub_event_type = data.get_u8();

        self.debug(&format!("\tsub event type = {}", sub_event_type));

        match sub_event_type {
            EVT_DISCONN_COMPLETE => self.manage_hci_event_pkt_disconnect(data),
            EVT_ENCRYPT_CHANGE=> self.manage_hci_event_pkt_encrypt_change(data),
            EVT_CMD_COMPLETE=> self.manage_hci_event_pkt_cmd(data),
            EVT_CMD_STATUS=>self.manage_hci_event_pkt_cmd_status(data),
            EVT_LE_META_EVENT=> self.manage_hci_event_pkt_le_meta(data),
            e => {
                // TODO send error to caller
                println!("Unknown event type from bluetooth: {}", e)
            }
        }
    }

    /// Manage event disconnect.
    fn manage_hci_event_pkt_disconnect(&mut self, data: &mut Cursor<Bytes>) {
        data.set_position(4);
        let handle = data.get_u16_le();
        let reason = data.get_u8();

        self.debug(&format!("EVT_DISCONN_COMPLETE -> handle: 0x{:02x}, reason: 0x{:02x}", handle, reason));

        self.callback.disconn_complete(handle, reason);
    }

    /// Manage event complete.
    fn manage_hci_event_pkt_cmd(&mut self, data: &mut Cursor<Bytes>) {
        data.set_position(4);
        let cmd = data.get_u16_le();
        let status = data.get_u8();

        let position = data.position() as usize;
        let result = &data.get_ref()[position..];
        let mut result = Cursor::new(Bytes::from(result));

        self.debug(&format!("EVT_CMD_COMPLETE -> cmd: 0x{:02x}, status: 0x{:02x}, result: {:?}", cmd, status, result));

        self.process_cmd_complete_event(cmd, status, &mut result);
    }

    /// Manage event encryt change.
    fn manage_hci_event_pkt_encrypt_change(&mut self, data: &mut Cursor<Bytes>) {
        data.set_position(4);
        let handle = data.get_u16_le();
        let encrypt = data.get_u8();

        self.debug(&format!("EVT_ENCRYPT_CHANGE -> handle: 0x{:02x}, encrypt: 0x{:02x}", handle, encrypt));

        self.callback.encrypt_change(handle, encrypt);
    }

    /// Manage event command status.
    fn manage_hci_event_pkt_cmd_status(&mut self, data: &mut Cursor<Bytes>) {
        let status = data.get_u8();
        data.set_position(5);
        let cmd = data.get_u16_le();

        self.debug(&format!("EVT_CMD_COMPLETE -> cmd: 0x{:02x}, status: 0x{:02x}", cmd, status));

        // TODO this.processCmdStatusEvent(cmd, status);
    }

    /// Manage event le meta.
    fn manage_hci_event_pkt_le_meta(&mut self, data: &mut Cursor<Bytes>) {
        let le_meta_event_type = data.get_u8();
        let le_meta_event_status = data.get_u8();

        let position = data.position() as usize;
        let le_meta_event_data = &data.get_ref()[position..];

        // TODO this.processLeMetaEvent(leMetaEventType, leMetaEventStatus, leMetaEventData);
    }

    /// Call when receive from BT adapter cmd complete.
    fn process_cmd_complete_event(&mut self, cmd: u16, status: u8, result: &mut Cursor<Bytes>) {
        match cmd {
            RESET_CMD => {
                // TODO catch error
                self.set_event_mask();
                self.set_le_event_mask();
                self.read_local_version();
                self.read_bd_addr();
            },
            READ_LE_HOST_SUPPORTED_CMD => {
                if status == 0 {
                    let le = result.get_u8();
                    let simul = result.get_u8();

                    self.debug(&format!("\t\t\tle = 0x{:02x}", le));
                    self.debug(&format!("\t\t\ttsimul = 0x{:02x}", simul));
                }
            }
            READ_LOCAL_VERSION_CMD => {
                let hci_ver = result.get_u8();
                let hci_rev = result.get_u16_le();
                let lmp_ver = result.get_u8();
                let manufacturer = result.get_u16_le();
                let lmp_sub_ver = result.get_u16_le();

                if hci_ver < 0x06 {
                    self.state = HciState::Unsupported;
                    self.callback.state_change(self.state.clone());
                } else if self.state != HciState::PoweredOn {
                    // TODO catch error
                    self.set_scan_enabled(false, true);
                    self.set_scan_parameters();
                }

                self.callback.read_local_version(hci_ver, hci_rev, lmp_ver, manufacturer, lmp_sub_ver);
            },
            READ_BD_ADDR_CMD=> {},
            LE_SET_SCAN_PARAMETERS_CMD => {},
            READ_RSSI_CMD => {},
            e => {
                // TODO send error to caller
                println!("Unknown cmd complete event from bluetooth: 0x{:02x}", e)
            },
        }
/*

  } else if (cmd === READ_BD_ADDR_CMD) {
    this.addressType = 'public';
    this.address = result.toString('hex').match(/.{1,2}/g).reverse().join(':');

    debug('address = ' + this.address);

    this.emit('addressChange', this.address);
  } else if (cmd === LE_SET_SCAN_PARAMETERS_CMD) {
    this.emit('stateChange', 'poweredOn');

    this.emit('leScanParametersSet');
  } else if (cmd === LE_SET_SCAN_ENABLE_CMD) {
    this.emit('leScanEnableSet', status);
  } else if (cmd === READ_RSSI_CMD) {
    var handle = result.readUInt16LE(0);
    var rssi = result.readInt8(2);

    debug('\t\t\thandle = ' + handle);
    debug('\t\t\trssi = ' + rssi);

    this.emit('rssiRead', handle, rssi);
  }
*/
    }
}