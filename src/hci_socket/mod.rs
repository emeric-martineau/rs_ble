//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
pub mod hci;
pub mod debug;
pub mod log;
pub mod error;
pub mod unix_libc;

#[cfg(test)]
pub mod tests;

use std::{thread, time};
use std::io::Cursor;
use std::collections::HashMap;

use self::hci::{BluetoothHciSocket};
use self::error::{Result, Error};
use self::unix_libc::Libc;
use self::debug::HciSocketDebug;
use self::log::HciLogger;

use bytes::{BytesMut, BufMut, Bytes, Buf};

/// State of Hci interface.
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum HciState {
    PoweredOff,
    PoweredOn,
    Unauthorized,
    Unsupported
}

/// State of Hci interface.
#[derive(Debug, Clone, PartialEq)]
pub enum BtLeAddressType {
    Public,
    Random,
    Unknown
}

#[derive(Debug, Clone)]
/// Data of callback for method le_conn_complete().
pub struct BtLeConnectionComplete {
    /// Handle.
    handle: u16,
    /// Role.
    role: u8,
    /// Address type (public, random).
    address_type: BtLeAddressType,
    /// Mac address
    address: String,
    /// Interval of what ?
    interval: f64,
    /// Latency.
    latency: u16,
    /// Ok if you want.
    supervision_timeout: u16,
    /// hum...
    master_clock_accuracy: u8
}

/// Callback when receive data.
/// Each method return true to stop polling data.
pub trait HciCallback {
    /// Call when change state.
    fn state_change(&self, state: HciState) -> bool;
    /// Address of adaptor.
    fn address_change(&self, address: String) -> bool;
    /// Status on connection.
    fn le_conn_complete(&self, status: u8, data: Option<BtLeConnectionComplete>) -> bool;
    /// When update connection complete.
    fn le_conn_update_complete(&self, status: u8, handle: u16, interval: f64, latency: u16, supervision_timeout: u16) -> bool;
    /// Rssi.
    fn rssi_read(&self, handle: u16, rssi: i8) -> bool;
    /// Call when BT peripheral disconnect.
    fn disconn_complete(&self, handle: u16, reason: u8) -> bool;
    /// Call when BT encrypt change.
    fn encrypt_change(&self, handle: u16, encrypt: u8) -> bool;
    /// Asynchronous Connection-Less Data receive.
    fn acl_data_pkt(&self, handle: u16, cid: u16, data: Vec<u8>) -> bool;
    /// Call when get version.
    fn read_local_version(&self, hci_ver: u8, hci_rev: u16, lmp_ver: i8, manufacturer: u16, lmp_sub_ver: u16) -> bool;
    /// When receive LE scan parameters.
    fn le_scan_parameters_set(&self) -> bool;
    /// When receive LE scan enable.
    fn le_scan_enable_set(&self, state: HciState) -> bool;
    /// When receive LE scan enable command.
    fn le_scan_enable_set_cmd(&self, enable: bool, filter_duplicates: bool) -> bool;
    /// On error.
    fn error(&self, msg: String) -> bool;
    /// When receive... I don't known.
    fn le_advertising_report(&self, status: u8, typ: u8, address: String, address_type: BtLeAddressType, eir: Vec<u8>, rssi: i8) -> bool;
}

/// Internal state of Hci
#[derive(Debug)]
enum HciStructState {
    Created,
    CreatedHciChannelUser,
    RunningPollDevUp,
    Running,
    Stopping
}

/// Internal Asynchronous Connection-Less Data Handler
struct AclDataHandler {
    /// Size of data.
    length: usize,
    /// CID.
    cid: u16,
    /// Data receive.
    data: Vec<u8>
}

pub const ACL_CONT: u16  = 0x01;
pub const ACL_START: u16 = 0x02;

pub const HCI_COMMAND_PKT: u8 = 0x01;
pub const HCI_ACLDATA_PKT: u8 = 0x02;
pub const HCI_EVENT_PKT: u8 = 0x04;
pub const HCI_VERSION_6: u8 = 0x06;
pub const HCI_ADDRESS_TYPE_RANDOM: u8 = 0x01;

pub const OGF_HOST_CTL: u16 = 0x03;
pub const OGF_INFO_PARAM: u16 = 0x04;
pub const OGF_STATUS_PARAM: u16 = 0x05;
pub const OGF_LE_CTL: u16 = 0x08;

pub const EVT_DISCONN_COMPLETE: u8 = 0x05;
pub const EVT_ENCRYPT_CHANGE: u8 = 0x08;
pub const EVT_CMD_COMPLETE: u8 = 0x0e;
pub const EVT_CMD_STATUS: u8 = 0x0f;
pub const EVT_LE_META_EVENT: u8 = 0x3e;
pub const EVT_LE_CONN_COMPLETE: u8 = 0x01;
pub const EVT_LE_ADVERTISING_REPORT: u8 = 0x02;
pub const EVT_LE_CONN_UPDATE_COMPLETE: u8 = 0x03;

pub const OCF_RESET: u16 = 0x0003;
pub const OCF_READ_LOCAL_VERSION: u16 = 0x0001;
pub const OCF_WRITE_LE_HOST_SUPPORTED: u16 = 0x006D;
pub const OCF_SET_EVENT_MASK: u16 = 0x0001;
pub const OCF_READ_LE_HOST_SUPPORTED: u16 = 0x006C;
pub const OCF_READ_BD_ADDR: u16 = 0x0009;
pub const OCF_READ_RSSI: u16 = 0x0005;
pub const OCF_LE_SET_SCAN_PARAMETERS: u16 = 0x000b;
pub const OCF_LE_SET_SCAN_ENABLE: u16 = 0x000c;
pub const OCF_LE_CREATE_CONN: u16 = 0x000d;

pub const SET_EVENT_MASK_CMD: u16 = OCF_SET_EVENT_MASK | OGF_HOST_CTL << 10;
pub const READ_LOCAL_VERSION_CMD: u16 = OCF_READ_LOCAL_VERSION | (OGF_INFO_PARAM << 10);
pub const WRITE_LE_HOST_SUPPORTED_CMD: u16 = OCF_WRITE_LE_HOST_SUPPORTED | OGF_HOST_CTL << 10;
pub const READ_LE_HOST_SUPPORTED_CMD: u16 = OCF_READ_LE_HOST_SUPPORTED | OGF_HOST_CTL << 10;
pub const READ_BD_ADDR_CMD: u16 = OCF_READ_BD_ADDR | (OGF_INFO_PARAM << 10);
pub const RESET_CMD:u16 = OCF_RESET | OGF_HOST_CTL << 10;
pub const READ_RSSI_CMD: u16 = OCF_READ_RSSI | OGF_STATUS_PARAM << 10;

pub const LE_SET_SCAN_ENABLE_CMD: u16 = OCF_LE_SET_SCAN_ENABLE | OGF_LE_CTL << 10;
pub const LE_SET_SCAN_PARAMETERS_CMD: u16 = OCF_LE_SET_SCAN_PARAMETERS | OGF_LE_CTL << 10;
pub const LE_CREATE_CONN_CMD: u16 = OCF_LE_CREATE_CONN | OGF_LE_CTL << 10;

const HANDLE_MASK: u16 = 0x0fff;
const FLAGS_SHIFT: u16 = 12;
pub const ENABLE: u8 = 0x01;

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

pub struct EmptyHciCallback;

impl HciCallback for EmptyHciCallback {
    fn state_change(&self, _state: HciState) -> bool {
        false
    }

    fn address_change(&self, _address: String) -> bool {
        false
    }

    fn le_conn_complete(&self, _status: u8, _data: Option<BtLeConnectionComplete>) -> bool {
        false
    }

    fn le_conn_update_complete(&self, _status: u8, _handle: u16, _interval: f64, _latency: u16, _supervision_timeout: u16) -> bool {
        false
    }

    fn rssi_read(&self, _handle: u16, _rssi: i8) -> bool {
        false
    }

    fn disconn_complete(&self, _handle: u16, _reason: u8) -> bool {
        false
    }

    fn encrypt_change(&self, _handle: u16, _encrypt: u8) -> bool {
        false
    }

    fn acl_data_pkt(&self, _handle: u16, _cid: u16, _data: Vec<u8>) -> bool {
        false
    }

    fn read_local_version(&self, _hci_ver: u8, _hci_rev: u16, _lmp_ver: i8, _manufacturer: u16, _lmp_sub_ver: u16) -> bool {
        false
    }

    fn le_scan_parameters_set(&self) -> bool {
        false
    }

    fn le_scan_enable_set(&self, _state: HciState) -> bool {
        false
    }

    fn le_scan_enable_set_cmd(&self, _enable: bool, _filter_duplicates: bool) -> bool {
        false
    }

    fn error(&self, _msg: String) -> bool {
        false
    }

    fn le_advertising_report(&self, _status: u8, _typ: u8, _address: String, _address_type: BtLeAddressType, _eir: Vec<u8>, _rssi: i8) -> bool {
        false
    }
}

/// Hci structure.
pub struct Hci<'a> {
    socket: BluetoothHciSocket<'a>,
    libc: &'a Libc,
    // TODO need device_id: str ?
    /// Handle for Asynchronous Connection-Less
    handle_buffers: HashMap<u16, AclDataHandler>,
    /// Local dev up
    is_dev_up: bool,
    /// Send stop to pool
    stop_polling: bool,
    /// Internal state of struct Hci
    struct_state: HciStructState,
    /// Callback
    callback: &'a HciCallback,
    /// State of Hci
    state: HciState,
    /// Logger.
    logger: &'a HciLogger,
    /// BT LE address type.
    address_type: BtLeAddressType,
    /// Current BT address.
    address: String
}

impl<'a> Hci<'a> {
    /// Create Hci interface.
    pub fn new(dev_id: Option<u16>, is_hci_channel_user: bool, logger: &'a HciLogger, libc: &'a Libc) -> Result<Self> {
        let socket;
        let hci;

        if is_hci_channel_user {
            match BluetoothHciSocket::bind_user(dev_id, libc) {
                Ok(s) => socket = s,
                Err(e) => return Err(e)
            };

            hci = Hci {
                libc,
                socket,
                handle_buffers: HashMap::new(),
                is_dev_up: false,
                stop_polling: false,
                struct_state: HciStructState::CreatedHciChannelUser,
                callback: &EmptyHciCallback{},
                state: HciState::PoweredOff,
                logger,
                address_type: BtLeAddressType::Unknown,
                address: String::new()
            };
        } else {
            match BluetoothHciSocket::bind_raw(dev_id, libc) {
                Ok(s) => socket = s,
                Err(e) => return Err(e)
            };

            hci = Hci {
                libc,
                socket,
                handle_buffers: HashMap::new(),
                is_dev_up: false,
                stop_polling: false,
                struct_state: HciStructState::Created,
                callback: &EmptyHciCallback{},
                state: HciState::PoweredOff,
                logger,
                address_type: BtLeAddressType::Unknown,
                address: String::new()
            };
        }

        Ok(hci)
    }

    /// State of Hci.
    pub fn state(&mut self) -> HciState {
        self.state.clone()
    }

    /// Address type.
    pub fn address_type(&mut self) -> BtLeAddressType {
        self.address_type.clone()
    }

    /// Address of adaptor.
    pub fn address(&mut self) -> String {
        self.address.clone()
    }

    /// Run init bluetooth adapter and poll data.
    pub fn init(&mut self, callback: Option<&'a HciCallback>) -> Result<()> {
        if callback.is_some() {
            self.callback = callback.unwrap();
        }

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
                    self.reset();
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

            if self.stop_polling {
                self.struct_state = HciStructState::Stopping;
                return Ok(())
            }
        }
    }

    /// Print debug.
    fn debug(&mut self, expr: &str) {
        self.logger.debug(expr);
    }

    /// Stop polling.
    fn stop(&mut self) {
        self.stop_polling = true;
    }

    /// Write data on BT socket.
    fn write(&mut self, cmd: &BytesMut) {
        if let Err(err) = self.socket.write(&cmd) {
            self.stop_polling = self.callback.error(format!("Error when write data: {:?}", err));
        }
    }

    /// Reset bluetooth adapter.
    fn reset(&mut self) {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(OCF_RESET as u16 | ((OGF_HOST_CTL as u16) << 10) as u16);
        cmd.put_u8(0x00);

        self.debug(&format!("reset - writing: {:?}", HciSocketDebug(&cmd)));

        self.write(&cmd);
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
                self.set_event_mask();
                self.set_le_event_mask();
                self.read_local_version();
                self.write_le_host_supported();
                self.read_le_host_supported();
                self.read_bd_addr();
            }
        } else if self.state != HciState::PoweredOff {
            self.state = HciState::PoweredOff;
            self.stop_polling = self.callback.state_change(HciState::PoweredOff)
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
    fn set_event_mask(&mut self) {
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

        self.write(&cmd);
    }

    /// Set type of event for Low-Energy bluetooth.
    fn set_le_event_mask(&mut self) {
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

        self.write(&cmd);
    }

    /// Read version of bluetooth supported by local adapter.
    fn read_local_version(&mut self) {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_LOCAL_VERSION_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("read local version - writing: {:?}", HciSocketDebug(&cmd)));

        self.write(&cmd);
    }

    /// Set Low-Energie Host mode for local adapter.
    fn write_le_host_supported(&mut self) {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(WRITE_LE_HOST_SUPPORTED_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("write LE host supported - writing: {:?}", HciSocketDebug(&cmd)));

        self.write(&cmd);
    }

    /// Read Low-Energie Host mode for local adapter.
    fn read_le_host_supported(&mut self) {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_LE_HOST_SUPPORTED_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("read LE host supported - writing: {:?}", HciSocketDebug(&cmd)));

        self.write(&cmd);
    }

    /// Read address.
    fn read_bd_addr(&mut self) {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_BD_ADDR_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.debug(&format!("read bd addr - writing: {:?}", HciSocketDebug(&cmd)));

        self.write(&cmd);
    }

    /// Enable scan.
    fn set_scan_enabled(&mut self, enabled: bool, filter_duplicates: bool) {
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

        self.write(&cmd);
    }

    /// Set scan.
    fn set_scan_parameters(&mut self) {
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

        self.write(&cmd);
    }

    /// Manage response from bluetooth.
    fn on_socket_data(&mut self, data: &mut Cursor<Bytes>) -> Result<()> {
        self.debug(&format!("on_socket_data: {:?}", HciSocketDebug(data.get_ref())));

        // data[0]
        let event_type = data.get_u8();

        self.debug(&format!("\tevent type = {}", event_type));

        match event_type {
            HCI_EVENT_PKT => self.manage_hci_event_pkt(data),
            HCI_ACLDATA_PKT => self.manage_acl_data_pkt(data),
            HCI_COMMAND_PKT => self.manage_hci_command_pkt(data),
            e => self.stop_polling = self.callback.error(format!("Unknown event type from bluetooth: {}", e))
        }

        Ok(())
    }

    /// Manage response type hci command pkt from bluetooth.
    fn manage_hci_command_pkt(&mut self, data: &mut Cursor<Bytes>) {
        let cmd = data.get_u16_le();
        let len = data.get_u8();

        self.debug(&format!("\t\tcmd = {}", cmd));
        self.debug(&format!("\t\tdata len = {}", len));

        if cmd == LE_SET_SCAN_ENABLE_CMD {
            let enable = data.get_u8() == ENABLE;
            let filter_duplicates = data.get_u8() == ENABLE;

            self.debug("\t\t\tLE enable scan command");
            self.debug(&format!("\t\t\tenable scanning = {}", enable));
            self.debug(&format!("\t\t\tfilter duplicates = {}", filter_duplicates));

            self.stop_polling = self.callback.le_scan_enable_set_cmd(enable, filter_duplicates);
        }
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
            e => self.stop_polling = self.callback.error(format!("Unknown event sub-type from bluetooth: {}", e))
        }
    }

    /// Manage event disconnect.
    fn manage_hci_event_pkt_disconnect(&mut self, data: &mut Cursor<Bytes>) {
        data.set_position(4);
        let handle = data.get_u16_le();
        let reason = data.get_u8();

        self.debug(&format!("\t\thandle = {}", handle));
        self.debug(&format!("\t\treason = {}", reason));

        self.stop_polling = self.callback.disconn_complete(handle, reason);
    }

    /// Manage event complete.
    fn manage_hci_event_pkt_cmd(&mut self, data: &mut Cursor<Bytes>) {
        data.set_position(4);
        let cmd = data.get_u16_le();
        let status = data.get_u8();

        let position = data.position() as usize;
        let result = &data.get_ref()[position..];
        let mut result = Cursor::new(Bytes::from(result));

        self.debug(&format!("\t\tcmd = {}", cmd));
        self.debug(&format!("\t\tstatus = {}", status));
        self.debug(&format!("\t\tresult = {:?}", HciSocketDebug(result.get_ref())));

        self.process_cmd_complete_event(cmd, status, &mut result);
    }

    /// Manage event encryt change.
    fn manage_hci_event_pkt_encrypt_change(&mut self, data: &mut Cursor<Bytes>) {
        data.set_position(4);
        let handle = data.get_u16_le();
        let encrypt = data.get_u8();

        self.debug(&format!("\t\thandle = {}", handle));
        self.debug(&format!("\t\tencrypt = {}", encrypt));

        self.stop_polling = self.callback.encrypt_change(handle, encrypt);
    }

    /// Manage event command status.
    fn manage_hci_event_pkt_cmd_status(&mut self, data: &mut Cursor<Bytes>) {
        let status = data.get_u8();
        data.set_position(5);
        let cmd = data.get_u16_le();

        self.debug(&format!("\t\tcmd = {}", cmd));
        self.debug(&format!("\t\tstatus = {}", status));

        self.process_cmd_status_event(cmd, status);
    }

    /// Process status event
    fn process_cmd_status_event(&mut self, cmd: u16, status: u8) {
        if cmd == LE_CREATE_CONN_CMD {
            if status != 0 {
                self.stop_polling = self.callback.le_conn_complete(status, None);
            }
        }
    }

    /// Manage event le meta.
    fn manage_hci_event_pkt_le_meta(&mut self, data: &mut Cursor<Bytes>) {
        let le_meta_event_type = data.get_u8();
        let le_meta_event_status = data.get_u8();

        let position = data.position() as usize;
        let le_meta_event_data = &data.get_ref()[position..];

        self.debug(&format!("\t\tLE meta event type = {}", le_meta_event_type));
        self.debug(&format!("\t\tLE meta event status = {}", le_meta_event_status));
        self.debug(&format!("\t\tLE meta event data = {:?}", HciSocketDebug(le_meta_event_data)));

        let mut le_meta_event_data = Cursor::new(Bytes::from(le_meta_event_data));

        self.process_le_meta_event(le_meta_event_type, le_meta_event_status, &mut le_meta_event_data);
    }

    /// Process le meta event.
    fn process_le_meta_event(&mut self, event_type: u8, status: u8, data: &mut Cursor<Bytes>) {
        match event_type {
            EVT_LE_CONN_COMPLETE => self.process_le_conn_complete(status, data),
            EVT_LE_ADVERTISING_REPORT=> self.process_le_advertising_report(status, data),
            EVT_LE_CONN_UPDATE_COMPLETE => self.process_le_conn_update_complete(status, data),
            e => self.stop_polling = self.callback.error(format!("Unknown le meta event from bluetooth: {}", e))
        }
    }

    /// Process LE connection complete.
    fn process_le_conn_complete(&mut self, status: u8, data: &mut Cursor<Bytes>) {
        let handle = data.get_u16_le();
        let role = data.get_u8();

        let address_type = match data.get_u8() {
            HCI_ADDRESS_TYPE_RANDOM=> BtLeAddressType::Random,
            _ => BtLeAddressType::Public
        };

        let address = self.read_mac_address(data);

        let interval = (data.get_u16_le() as f64)* 1.25;
        let latency = data.get_u16_le(); // TODO: multiplier?
        let supervision_timeout = data.get_u16_le() * 10;
        let master_clock_accuracy = data.get_u8(); // TODO: multiplier?

        self.debug(&format!("\t\t\thandle = {}", handle));
        self.debug(&format!("\t\t\trole = {}", role));
        self.debug(&format!("\t\t\taddress type = {:?}", address_type));
        self.debug(&format!("\t\t\taddress = {}", address));
        self.debug(&format!("\t\t\tinterval = {}", interval));
        self.debug(&format!("\t\t\tlatency = {}", latency));
        self.debug(&format!("\t\t\tsupervision timeout = {}", supervision_timeout));
        self.debug(&format!("\t\t\tmaster clock accuracy = {}", master_clock_accuracy));

        let result = BtLeConnectionComplete {
            handle,
            role,
            address_type,
            address,
            interval,
            latency,
            supervision_timeout,
            master_clock_accuracy
        };

        self.stop_polling = self.callback.le_conn_complete(status, Some(result));
    }

    fn process_le_advertising_report(&mut self, count: u8, data: &mut Cursor<Bytes>) {
        for _ in 0..count {
            let typ = data.get_u8();

            let address_type = match data.get_u8() {
                HCI_ADDRESS_TYPE_RANDOM=> BtLeAddressType::Random,
                _ => BtLeAddressType::Public
            };

            let address = self.read_mac_address(data);

            let eir_length= data.get_u8();

            let position = data.position() as usize;
            let position_end = position + (eir_length as usize);

            let mut eir = vec![0, eir_length];

            eir.clone_from_slice(&data.get_ref()[position..position_end]);

            //let eir = &data.get_ref()[position..position_end];

            data.set_position(position_end as u64);

            let rssi = data.get_i8();

            self.debug(&format!("\t\t\ttype = {}", typ));
            self.debug(&format!("\t\t\taddress = {}", address));
            self.debug(&format!("\t\t\taddress type = {:?}", address_type));
            self.debug(&format!("\t\t\teir = {:?}", HciSocketDebug(eir.as_slice())));
            self.debug(&format!("\t\t\trssi = {}", rssi));

            self.stop_polling = self.callback.le_advertising_report(0, typ, address, address_type, eir, rssi);
        }
    }

    /// Process le connection update complete.
    fn process_le_conn_update_complete(&mut self, status: u8, data: &mut Cursor<Bytes>) {
        let handle = data.get_u16_le();
        let interval = (data.get_u16_le() as f64) * 1.25;
        let latency = data.get_u16_le(); // TODO: multiplier?
        let supervision_timeout = data.get_u16_le() * 10;

        self.debug(&format!("\t\t\thandle = {}", handle));
        self.debug(&format!("\t\t\tinterval = {}", interval));
        self.debug(&format!("\t\t\tlatency = {}", latency));
        self.debug(&format!("\t\t\tsupervision timeout = {}", supervision_timeout));

        self.stop_polling = self.callback.le_conn_update_complete(status, handle, interval, latency, supervision_timeout);
    }

    /// Reset adaptor.
    fn reset_cmd(&mut self) {
        self.set_event_mask();
        self.set_le_event_mask();
        self.read_local_version();
        self.read_bd_addr();
    }

    /// Read low-energy command.
    fn read_le_host_supported_cmd(&mut self, status: u8, result: &mut Cursor<Bytes>) {
        if status == 0 {
            let le = result.get_u8();
            let simul = result.get_u8();

            self.debug(&format!("\t\t\tle = 0x{:02x}", le));
            self.debug(&format!("\t\t\ttsimul = 0x{:02x}", simul));
        }
    }

    /// Read local version command.
    fn read_local_version_cmd(&mut self, result: &mut Cursor<Bytes>) {
        let hci_ver = result.get_u8();
        let hci_rev = result.get_u16_le();
        let lmp_ver = result.get_i8();
        let manufacturer = result.get_u16_le();
        let lmp_sub_ver = result.get_u16_le();

        if hci_ver < HCI_VERSION_6 {
            self.state = HciState::Unsupported;
            self.stop_polling = self.callback.state_change(self.state.clone());
        } else if self.state != HciState::PoweredOn {
            self.set_scan_enabled(false, true);
            self.set_scan_parameters();
        }

        if ! self.stop_polling {
            self.stop_polling = self.callback.read_local_version(hci_ver, hci_rev, lmp_ver,
                                                                 manufacturer, lmp_sub_ver);
        }
    }

    /// Read a MAC address in data.
    fn read_mac_address(&mut self, data: &mut Cursor<Bytes>) -> String {
        let a1 = data.get_u8();
        let a2 = data.get_u8();
        let a3 = data.get_u8();
        let a4 = data.get_u8();
        let a5 = data.get_u8();
        let a6 = data.get_u8();

        String::from(format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", a6, a5, a4, a3, a2, a1))
    }

    /// Read address command.
    fn read_bd_addr_cmd(&mut self, result: &mut Cursor<Bytes>) {
        self.address_type = BtLeAddressType::Public;

        let addr = self.read_mac_address(result);

        self.address = addr.clone();

        self.debug(&format!("address = {}", &addr));

        self.stop_polling = self.callback.address_change(addr)
    }

    fn read_rssi_cmd(&mut self, result: &mut Cursor<Bytes>) {
        let handle = result.get_u16_le();
        let rssi = result.get_i8();

        self.debug(&format!("\t\t\thandle = {}", &handle));
        self.debug(&format!("\t\t\trssi = {}", &rssi));

        self.stop_polling = self.callback.rssi_read(handle, rssi);
    }

    /// Call when receive from BT adapter cmd complete.
    fn process_cmd_complete_event(&mut self, cmd: u16, status: u8, result: &mut Cursor<Bytes>) {
        match cmd {
            RESET_CMD => self.reset_cmd(),
            READ_LE_HOST_SUPPORTED_CMD => self.read_le_host_supported_cmd(status, result),
            READ_LOCAL_VERSION_CMD => self.read_local_version_cmd(result),
            READ_BD_ADDR_CMD=> self.read_bd_addr_cmd(result),
            LE_SET_SCAN_PARAMETERS_CMD => {
                self.stop_polling = self.callback.state_change(HciState::PoweredOn);

                if ! self.stop_polling {
                    self.stop_polling = self.callback.le_scan_parameters_set();
                }
            },
            LE_SET_SCAN_ENABLE_CMD=> self.stop_polling = self.callback.le_scan_enable_set(self.state.clone()),
            READ_RSSI_CMD => self.read_rssi_cmd(result),
            e => self.stop_polling = self.callback.error(format!("Unknown cmd complete event from bluetooth: {}", e))
        }
    }

    /// Manage response acl data.
    fn manage_acl_data_pkt(&mut self, data: &mut Cursor<Bytes>) {
        let d = data.get_u16_le();
        let flags = d >> FLAGS_SHIFT;
        let handle = d & HANDLE_MASK;

        match flags {
            ACL_START => self.manage_acl_data_start(handle, data),
            ACL_CONT => self.manage_acl_data_continue(handle, data),
            _ => self.stop_polling = self.callback.error(format!("Unkown flag {} for acl data !", flags))
        }
    }

    /// Manage start flag of Asynchronous Connection-Less data.
    fn manage_acl_data_start(&mut self, handle: u16, data: &mut Cursor<Bytes>) {
        data.set_position(5);

        let length = data.get_u16_le() as usize;
        let cid = data.get_u16_le();

        let position = data.position() as usize;
        let stream_len = data.get_ref().len();
        let position_end = position + stream_len;

        let mut pkt_data = Vec::with_capacity(length);
        pkt_data.extend_from_slice(&data.get_ref()[position..position_end]);

        if length == pkt_data.len() {
            self.debug(&format!("\t\thandle = {}", handle));
            self.debug(&format!("\t\tdata = {:?}", HciSocketDebug(&pkt_data)));

            self.stop_polling = self.callback.acl_data_pkt(handle, cid, pkt_data);
        } else {
            self.handle_buffers.insert(handle, AclDataHandler {
                length,
                cid,
                data: pkt_data
            });
        }
    }

    /// Manage continue flag of Asynchronous Connection-Less data.
    fn manage_acl_data_continue(&mut self, handle: u16, data: &mut Cursor<Bytes>) {
        let mut remove = false;
        if let Some(acl_data_handle) = self.handle_buffers.get_mut(&handle) {
            acl_data_handle.data.extend_from_slice(&data.get_ref()[5..]);

            if acl_data_handle.length == acl_data_handle.data.len() {
                // Nice, data complete
                self.stop_polling = self.callback.acl_data_pkt(handle, acl_data_handle.cid, acl_data_handle.data.clone());

                remove = true;
            }
        }

        if remove {
            self.handle_buffers.remove(&handle);
        }
    }
}
