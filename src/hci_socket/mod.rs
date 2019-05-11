//! Bluetooth Hci Socket for Linux.
//!
//! TODO comment
pub mod hci;

use std::{thread, time};

use self::hci::{BluetoothHciSocket, BluetoothHciSocketMessage};
use self::hci::error::Result;
use bytes::{BytesMut, BufMut};

/// Internal state of Hci
enum HciState {
    Created,
    Initialized,
    Running,
    Stopping
}

enum HciSubState {
    None,
    //IsDevUpSocketFilter,
    IsDevUpEventMask,
    IsDevUpLeEventMask,
    IsDevUpReadLocalVersion,
    IsDevUpWriteLeHostSupported,
    IsDevUpReadLeHostSupported,
    IsDevUpReadBdAddr
}

const HCI_COMMAND_PKT: u8 = 0x01;
const HCI_ACLDATA_PKT: u8 = 0x02;
const HCI_EVENT_PKT: u8 = 0x04;

const OGF_HOST_CTL: u16 = 0x03;
const OCF_RESET: u16 = 0x0003;
const OCF_READ_LOCAL_VERSION: u16 = 0x0001;
const OCF_WRITE_LE_HOST_SUPPORTED: u16 = 0x006D;
const OGF_INFO_PARAM: u16 = 0x04;

const EVT_DISCONN_COMPLETE: u8 = 0x05;
const EVT_ENCRYPT_CHANGE: u8 = 0x08;
const EVT_CMD_COMPLETE: u8 = 0x0e;
const EVT_CMD_STATUS: u8 = 0x0f;
const EVT_LE_META_EVENT: u8 = 0x3e;

const OCF_SET_EVENT_MASK: u16 = 0x0001;
const OCF_READ_LE_HOST_SUPPORTED: u16 = 0x006C;
const OCF_READ_BD_ADDR: u16 = 0x0009;

const SET_EVENT_MASK_CMD: u16 = OCF_SET_EVENT_MASK | OGF_HOST_CTL << 10;
const READ_LOCAL_VERSION_CMD: u16 = OCF_READ_LOCAL_VERSION | (OGF_INFO_PARAM << 10);
const WRITE_LE_HOST_SUPPORTED_CMD: u16 = OCF_WRITE_LE_HOST_SUPPORTED | OGF_HOST_CTL << 10;
const READ_LE_HOST_SUPPORTED_CMD: u16 = OCF_READ_LE_HOST_SUPPORTED | OGF_HOST_CTL << 10;
const READ_BD_ADDR_CMD: u16 = OCF_READ_BD_ADDR | (OGF_INFO_PARAM << 10);

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
pub struct Hci {
    socket: BluetoothHciSocket,
    is_hci_channel_user: bool,
    /*
    is_dev_up: bool,
    state: str,
    device_id: str,
    handle_buffers: str,*/
    /// Local dev up
    is_dev_up: bool,
    /// Send stop to pool
    stop_pool: bool,
    state: HciState,
    sub_state: HciSubState
}

impl Hci {
    /// Create Hci interface.
    pub fn new(dev_id: Option<u16>, is_hci_channel_user: bool) -> Result<Hci> {
        let socket;
        let hci;

        if is_hci_channel_user {
            match BluetoothHciSocket::bind_user(dev_id) {
                Ok(s) => socket = s,
                Err(e) => return Err(e)
            };

            hci = Hci {
                socket,
                is_hci_channel_user,
                is_dev_up: false,
                stop_pool: false,
                state: HciState::Created,
                sub_state: HciSubState::None
            };
        } else {
            match BluetoothHciSocket::bind_raw(dev_id) {
                Ok(s) => socket = s,
                Err(e) => return Err(e)
            };

            hci = Hci {
                socket,
                is_hci_channel_user,
                is_dev_up: false,
                stop_pool: false,
                state: HciState::Created,
                sub_state: HciSubState::None
            };
        }

        Ok(hci)
    }

    pub fn init(&mut self) -> Result<()> {
        let wait_time = time::Duration::from_millis(1000);

        loop {
            match self.socket.poll() {
                Ok(data) => {
                    if data.len() > 0 {
                        println!("send data: {:?}", data);
                        // TODO
                        //callback(self, BluetoothHciSocketMessage::Data { data: data.clone() })
                    }
                },
                Err(e) => println!("send data") //TODO callback(self, BluetoothHciSocketMessage::Error { error: e })
            }

            if self.is_hci_channel_user {
                self.reset()?;
            } else {
                self.poll_is_dev_up()?;
            }
/*
            match self.state {
                HciState::Created => {
                    if self.is_hci_channel_user {
                        self.reset()?;
                    } else {
                        self.poll_is_dev_up()?;
                    }
                },
                _ => println!("Ohohoho")
            }
*/
            thread::sleep(wait_time);

            if self.stop_pool {
                println!("Goodbye");
                break;
            }
        }

        Ok(())
    }

    fn reset(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(OCF_RESET as u16 | ((OGF_HOST_CTL as u16) << 10) as u16);
        cmd.put_u8(0x00);

        self.socket.write(&cmd)?;

        Ok(())
    }

    fn poll_is_dev_up(&mut self) -> Result<()> {
        let is_dev_up ;
println!("poll_is_dev_up");
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
                /*
                match  self.sub_state {
                    HciSubState::None => {
                        println!("socket filter");
                        self.set_socket_filter()?;
                        self.sub_state = HciSubState::IsDevUpEventMask;
                    },
                    HciSubState::IsDevUpEventMask => {
                        println!("envent mask");
                        self.set_event_mask()?;
                        self.sub_state = HciSubState::IsDevUpLeEventMask;
                    }
                    HciSubState::IsDevUpLeEventMask => {
                        println!("envent mask le");
                        self.set_le_event_mask()?;
                        self.sub_state = HciSubState::IsDevUpReadLocalVersion;
                    },
                    HciSubState::IsDevUpReadLocalVersion => {
                        println!("read_local_version");
                        self.read_local_version()?;
                        self.sub_state = HciSubState::IsDevUpReadLocalVersion;
                    },
                    HciSubState::IsDevUpWriteLeHostSupported => {
                        println!("write_le_host_supported");
                        self.write_le_host_supported()?;
                        self.sub_state = HciSubState::IsDevUpReadLocalVersion;
                    },
                    HciSubState::IsDevUpReadLeHostSupported => {
                        println!("read_le_host_supported");
                        self.read_le_host_supported()?;
                        self.sub_state = HciSubState::IsDevUpReadLocalVersion;
                    },
                    HciSubState::IsDevUpReadBdAddr => {
                        println!("read_bd_addr");
                        self.read_bd_addr()?;
                        self.sub_state = HciSubState::None;
                        self.state = HciState::Running;
                    },
                }*/
            }
        } else {
            // TODO
            // this.emit('stateChange', 'poweredOff');
        }

        self.is_dev_up = is_dev_up;
// TODO setTimeout(this.pollIsDevUp.bind(this), 1000);
        Ok(())
    }

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

        self.socket.set_filter(&filter)?;

        Ok(())
    }

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

        self.socket.write(&cmd)?;

        Ok(())
    }

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

        self.socket.write(&cmd)?;

        Ok(())
    }

    fn read_local_version(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_LOCAL_VERSION_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.socket.write(&cmd)?;

        Ok(())
    }

    fn write_le_host_supported(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(WRITE_LE_HOST_SUPPORTED_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.socket.write(&cmd)?;

        Ok(())
    }

    fn read_le_host_supported(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_LE_HOST_SUPPORTED_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.socket.write(&cmd)?;

        Ok(())
    }

    fn read_bd_addr(&mut self) -> Result<()> {
        let mut cmd = BytesMut::with_capacity(4);

        cmd.put_u8(HCI_COMMAND_PKT);
        cmd.put_u16_le(READ_BD_ADDR_CMD as u16);

        // Length
        cmd.put_u8(0);

        self.socket.write(&cmd)?;

        Ok(())
    }

}