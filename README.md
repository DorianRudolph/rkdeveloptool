# rkdeveloptool

rkdeveloptool is a fastboot-like CLI tool for flashing rockchip devices. This fork is actively maintained to support the PineNote and Quartz64 as well as other Pine64 RK devices.

## Install instructions

### Deps

* libusb-1.0

### Build and install

```bash
meson build
meson compile -C build
```

To install:
```bash
meson install -C build
```

This will use PAM to elevate privileges where necessary.

## Usage

Usage: rkdeveloptool command [args]...
Reads or writes the storage of a rockchip device booted into the rockusb bootloader mode

  -h, --help      print this help text
  -v, --version   print the version of this tool

  list                  List the detected devices in rockusb mode
  list-partitions       List the GPT partition table on the storage
  read                  Read sectors from the internal storage
  read-partition        Read a partition from the internal storage
  write                 Write sectors from to internal storage
  write-partition       Write an image to a specific partition
  write-partition-table Write an image to a specific partition
  write-parameter       Not sure what this does
  erase-flash           Wipe the internal storage
  boot                  Download an image to ram and start it
  test-device           Tests the device
  upgrade-loader        Write a new rockusb loader
  reset                 Send a reset command
  reboot                Send a reboot command, alias of reset
  reboot-maskrom        Trigger reboot into maskrom mode
  shutdown              Reset without rebooting
  read-flash-id         Read the flash chip serial number
  read-flash-info       Show information about the internal storage
  read-chip-info        Show information about the SoC
  read-capability       Show the bootloader permissions
  pack                  Pack bootloader
  unpack                Unpack bootloader
  tag-spl               Tag U-Boot SPL

Some of these commands are legacy and probably not useful to us, but they're here anyway :>

Use `rkdeveloptool command -h` for command specific help.

