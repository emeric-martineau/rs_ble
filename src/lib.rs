extern crate failure;
#[macro_use]
extern crate failure_derive;

extern crate nix;
extern crate libc;
extern crate bytes;

pub mod hci_socket;

/// In Noble, buffer is 1024 but maybe shortest
const POLL_BUFFER_SIZE: usize = 2048;
type PollBuffer = [u8; POLL_BUFFER_SIZE];

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
