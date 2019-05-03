extern crate failure;
#[macro_use]
extern crate failure_derive;

extern crate nix;
extern crate libc;
extern crate bytes;

pub mod hci_socket;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
