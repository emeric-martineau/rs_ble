//! Contain all error and return type use by rs_ble API.
//! Inspired by rumble crate.
use std::result;
use std::time::Duration;
use nix::errno::Errno;

/// Error return by all API of rs_ble;
#[derive(Debug, Fail, Clone)]
pub enum Error {
    #[fail(display = "Permission denied")]
    PermissionDenied,

    #[fail(display = "Device not found")]
    DeviceNotFound,

    #[fail(display = "No device found")]
    NoDeviceFound,

    #[fail(display = "Not connected")]
    NotConnected,

    #[fail(display = "The operation is not supported: {}", _0)]
    NotSupported(String),

    #[fail(display = "Timed out after {:?}", _0)]
    TimedOut(Duration),

    #[fail(display = "{}", _0)]
    Other(String),
}

/// Return type of API rs_ble;
/// Inspired by Rumble Result type;
pub type Result<T> = result::Result<T, Error>;

/// Helper to convert nix::Errrno to Error of rs_ble;
pub fn errno_to_error(errno: Errno) -> Error {
    match errno {
        Errno::EPERM => Error::PermissionDenied,
        Errno::ENODEV => Error::DeviceNotFound,
        Errno::ENOTCONN => Error::NotConnected,
        _ => Error::Other(errno.to_string())
    }
}

/// Wrap unsafe call anc convert int return to rs_ble Result type.
pub fn handle_error(v: i32) -> Result<i32> {
    if v < 0 {
        //println!("{:?}", Errno::last());
        Err(errno_to_error(Errno::last()))
    } else {
        Ok(v)
    }
}