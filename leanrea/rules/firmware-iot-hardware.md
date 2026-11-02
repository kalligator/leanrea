# Firmware, IoT & Hardware Reverse Engineering Guide

This guide details command-line procedures for unpacking firmware blobs, analyzing embedded systems, inspecting UEFI/BIOS images, capturing hardware protocols, and reading machine configuration tables.

## 1. Firmware Blobs & Embedded Linux Images (Routers, IoT)

```sh
F=./firmware.bin; X=$(mktemp -d "${TMPDIR:-/tmp}/re-fw.XXXXXX")
# Unpack with binwalk or unblob
binwalk -e -C "$X" "$F" || unblob -e "$X" "$F"

# Filesystem-specific extraction if binwalk carved raw images:
# SquashFS (common in embedded Linux)
unsquashfs -d "$X/rootfs" "$X"/*.squashfs 2>/dev/null
# JFFS2 / UBIFS (NAND flash)
jefferson -d "$X/jffs2_root" "$X"/*.jffs2 2>/dev/null
```

### Running Foreign Architecture Binaries with QEMU User Static
To execute a target binary from the extracted rootfs (e.g. MIPS or ARM on x86-64 host):
```sh
# Requires qemu-user-static package
# Run target busybox or server with rootfs as sysroot:
qemu-mips-static -L "$X/rootfs" "$X/rootfs/bin/busybox"
```

## 2. UEFI & BIOS Firmware Images

- **Vendor Update ISOs**:
  Extract bootable El Torito image: `geteltorito -o bios.img update.iso`, then mount with `losetup` or extract with `7z x bios.img`.
- **Intel Flash Image Descriptor (`ifdtool`)**:
  Inspect descriptor, regions, and permissions: `ifdtool -d bios.bin`
  Extract BIOS, ME, GbE regions: `ifdtool -x bios.bin`
- **Intel Management Engine Inspection**:
  `me_cleaner -c bios.bin` (read-only verification of ME version and partitions).
- **UEFI Volumes and Modules (`UEFIExtract`)**:
  Extract all UEFI volumes, DXE drivers, and PEI modules: `UEFIExtract bios.bin all`
  Search Setup strings: `strings -el dump_dir/Setup/body.bin | head -100`

## 3. Host System Configuration Tables (ACPI / DMI)

> [!NOTE]
> System table queries require elevated privileges (`sudo`). Do not attempt write operations to hardware registers or NVRAM.

- **DMI / SMBIOS hardware inventory**:
  `sudo dmidecode -t system,bios,baseboard,processor,memory`
- **ACPI DSDT / SSDT extraction and disassembly**:
  ```sh
  sudo acpidump > acpi.dat
  acpixtract -a acpi.dat
  iasl -d *.dat
  # Search EC (Embedded Controller) registers and hotkey _Qxx handlers:
  rg -n 'OperationRegion|Field \(ECOR|Method \(_Q' dsdt.dsl
  ```
- **PCI Hardware**: `lspci -nnk` (lists vendor/device IDs and kernel drivers bound to each device).

## 4. USB Device Protocols (USBMON + TSHARK)

```sh
# 1. Identify USB vendor and product ID
lsusb -v -d VID:PID

# 2. Enable kernel usbmon module
sudo modprobe usbmon

# 3. Capture packets on specific USB bus (e.g., bus 1)
sudo tshark -i usbmon1 -w capture.pcapng

# 4. Filter and display HID or raw endpoint data
tshark -r capture.pcapng -T fields -e usb.capdata -e usbhid.data | sort -u
```
