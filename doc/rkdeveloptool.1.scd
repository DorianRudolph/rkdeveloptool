rkdeveloptool(1) "rkdeveloptool"

# NAME

rkdeveloptool - rockusb bootloader utility

# SYNOPSIS

rkdeveloptool [OPTIONS] COMMAND [ARGS]...

COMMAND := {list | list-partitions | read | read-partition | write |
write-partition | write-partition-table | write-parameter |
erase-flash | boot | test-device | upgrade-loader | reset |
read-flash-id | read-flash-info | read-chip-info | read-capability |
pack | unpack | tag-spl }

OPTIONS := { -h | -v }

# DESCRIPTION

Reads or writes the storage of a rockchip device booted into the rockusb
bootloader mode

# OPTIONS

*-h, --help*
	Show the help message and quit

*-v, --version*
	Show the version number and quit

# COMMANDS

*list*
	Show the connected devices

*list-partitions*
	Show the GPT partition table entries if a GPT table exists on the flash

*read* START-SECTOR NUM-BYTES FILENAME
	Read the specified number of bytes from the sector offset into the specified
	file

*read-partition* PARTITION FILENAME
	Read the contents of a named partition to a file

*write* START-SECTOR FILENAME
	Write the contents of the file to the eMMC starting at a specific sector

*write-partition* PARTITION FILENAME
	Write the contents of the file into a named partition

*write-partition-table* DEFINITION-FILE
	Write a new GPT partition table block with partitions defined in a file

*write-parameter* ?
	Not sure what this does

*erase-flash*
	Wipe the internal flash storage

*boot* FILENAME
	Load an image into ram and boot it

*test-device*
	Check if there is a device attached in the ready state

*upgrade-loader* FILENAME
	Write a new rockusb bootloader to the flash

*reset* [SUBCODE]
	Reset the device. Optionally with a subcode which is a number between 0
	and 5

*read-flash-id*
	Read the eMMC flash id

*read-flash-info*
	Read the flash chip specifications

*read-chip-info*
	Read the SoC info bytes

*read-capability*
	Read the permissions of the rockusb bootloader

*pack*
	Merge a boot image

*unpack* [FILENAME]
	Unpack a boot image into the seperate files

*tag-spl* [TAG] [SPL-FILE]
	Prepend the tag to the SPL-FILE and save it as filename.tag

# EXAMPLES

Backup a partition of the device

	rkdeveloptool read-partition uboot uboot.img

Restore a partition of the device

	rkdeveloptool write-partition uboot uboot.img

Read the bootloader magic block from sector 64

	rkdeveloptool read 64 512 bootloader-magic.bin