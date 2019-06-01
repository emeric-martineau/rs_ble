# RS-BLE

A [Rust](https://www.rust-lang.org) BLE (Bluetooth Low Energy) central module.

This crate is port of [Noble.js](https://github.com/noble/noble) based on commit `c4cd18a7a429bb832f6c4ca793be3faf9af884e9`.

This crate don't use thread. If you want thread use crate [Rumble](https://github.com/mwylde/rumble) or [Blurz](https://github.com/szeged/blurz).

## OS supported

| OS |     |
| :------- | --- |
| Linux | Yes |
| Windows | No |
| OSX | No |
| BSD | No |


## Prerequisites

### Linux

 * Kernel version 3.6 or above
 * `libbluetooth-dev`
 * `clang`
 * `bluez`
 * Rust 1.35.0

#### Ubuntu/Debian/Raspbian

```sh
sudo apt-get install bluetooth bluez libbluetooth-dev libudev-dev clang
```

#### Fedora / Other-RPM based

```sh
sudo yum install bluez bluez-libs bluez-libs-devel clang
```

# Notes

### Maximum simultaneous connections

This limit is imposed upon by the Bluetooth adapter hardware as well as it's firmware.

| Platform |     |
| :------- | --- |
| Linux - Adapter dependent | 5 (CSR based adapter) |

## Running on Linux

### Running without root/sudo

Run the following command:

```sh
sudo setcap cap_net_raw+eip $(eval readlink -f `which node`)
```

This grants the your binary `cap_net_raw` privileges, so it can start/stop BLE advertising.

__Note:__ The above command requires `setcap` to be installed, it can be installed using the following:

 * apt: `sudo apt-get install libcap2-bin`
 * yum: `su -c \'yum install libcap2-bin\'`

### Multiple Adapters

TODO

`hci0` is used by default to override set the `NOBLE_HCI_DEVICE_ID` environment variable to the interface number.

Example, specify `hci1`:

```sh
sudo NOBLE_HCI_DEVICE_ID=1 node <your file>.js
```

## License

Copyright (C) 2019 Emeric MARTINEAU

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
