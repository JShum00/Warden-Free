# Warden Free

`warden-free` is the GPLv2-compatible Free edition of Warden Antivirus.

It contains:

- a Qt6 desktop GUI for ClamAV-based filesystem scans
- ClamAV definition updates
- quarantine support
- `warden-clamav-bridge`, a JSON CLI companion executable for local ClamAV scan and update requests

## Requirements

- CMake 3.16+
- C++17 compiler
- Qt6 Widgets and Concurrent
- OpenSSL
- ClamAV development files

On Ubuntu or Linux Mint:

```bash
sudo apt install build-essential cmake qt6-base-dev libssl-dev libclamav-dev clamav-freshclam
```

`freshclam` is the preferred update path at runtime. `libfreshclam` remains an optional fallback if the CLI is unavailable.

## Build

```bash
./build.sh build
```

## Run

```bash
./build.sh
```

## Package

Linux release packaging:

```bash
./package.sh deb
./package.sh appimage
```

- `.deb` output lands under `dist/`
- AppImage packaging requires `linuxdeployqt`

Windows release packaging from a Windows Qt shell:

```powershell
.\package.ps1 -Mode installer
```

- staging uses `windeployqt`
- installer generation requires NSIS (`makensis`)

## Bridge Protocol

See [docs/bridge-protocol.md](docs/bridge-protocol.md).
