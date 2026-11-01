# decLock (Gatekeeper)

**An offline app lock for Windows 10/11 with password and face unlock.**

| | |
|---|---|
| App name | Gatekeeper (repository: decLock) |
| Version | 0.1.0 |
| Owner | [saimumadi00-sketch](https://github.com/saimumadi00-sketch) |
| Repository | <https://github.com/saimumadi00-sketch/decLock> |
| Platform | Windows 10 / 11, 64-bit |
| Licence | Proprietary, all rights reserved (see [Licence and ownership](#licence-and-ownership)) |

Copyright (c) 2026 saimumadi00-sketch. All rights reserved.

Gatekeeper is a desktop app that locks other applications. When a locked app starts, Gatekeeper
freezes it and shows an unlock screen. The app resumes only after the right password is entered or
your face matches; otherwise it is closed. Gatekeeper can also block new USB storage devices and
lock the workstation when idle. Everything runs on your computer: there is no network access and
no cloud.

> Gatekeeper deters casual access. It is not protection against an administrator, Safe Mode, or
> booting from other media. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Features

- **App locking.** Pick any program (e.g. `chrome.exe`). It is suspended at launch until unlocked.
  Optional per-app schedules (for example, locked only during work hours).
- **Password protection.** bcrypt-hashed password with a brute-force lockout (5 free attempts, then
  increasing waits) that persists across restarts.
- **Face unlock (Face ID style).** On-device AI models: SCRFD face detection, ArcFace recognition,
  and MiniFASNet anti-spoofing plus a random head-movement challenge, so a photo or video of you
  does not unlock it. Face data is encrypted with Windows DPAPI.
- **Desktop dashboard.** Manage locked apps, face enrolment, USB, idle lock, logs and settings, with
  an optional tray icon. Starts minimized at logon.
- **USB storage blocking** and **idle workstation lock**.
- **Tamper-evident audit log.** Every unlock, failure and settings change is recorded in a
  hash-chained log, with CSV export.
- **Password-protected uninstall.** The uninstaller asks for the Gatekeeper password before it
  removes anything.
- **Safe dev mode** (`--dev`) that only logs what it would do.

## How it works

1. The guard watches for new processes. When a locked app starts, it is suspended immediately.
2. A full-screen unlock prompt appears (blurred background). If face unlock is on, the camera
   starts and checks that the face is live and matches; you can always type the password instead.
3. Correct password or face match: the app resumes. Cancel, timeout or too many failures: the app
   is closed. Each outcome is logged.

The face models are small ONNX files (about 19 MB in total) bundled with the app and run on the CPU
with ONNX Runtime. Their SHA-256 hashes are pinned in the code, so a swapped model is refused.

## Install

1. Download or build `GatekeeperSetup-0.1.0.exe` (see [Build](#build)).
2. Run it as an administrator.
3. Read and accept the **licence agreement**. Installation does not continue without it.
4. Open Gatekeeper and choose a password (at least 8 characters).
5. Add the apps to lock and, optionally, enrol your face.

**Uninstall:** Settings > Apps > Gatekeeper > Uninstall. You must enter the Gatekeeper password.

## Privacy

- Works fully offline; nothing is sent over the network.
- Data is stored only in `%APPDATA%\Gatekeeper` for each Windows user: the password hash, the
  encrypted face data, settings and the audit log.
- The uninstaller offers to delete this data.

## Quick start (from source)

Requires Python 3.10+.

```
pip install -r requirements.txt
python -m gatekeeper --dev init            # set a password
python -m gatekeeper --dev add notepad     # lock Notepad
python -m gatekeeper --dev run             # dev mode only LOGS what it would do
python -m pytest -q
```

Drop `--dev` to enforce for real. Start with a harmless app such as Notepad.

## Build

```
powershell -File build.ps1
```

This runs the tests, builds `dist\gatekeeper\` with PyInstaller and, if
[Inno Setup 6](https://jrsoftware.org/isinfo.php) is installed, the installer
`installer\GatekeeperSetup-0.1.0.exe` (about 80 MB).

## Documentation

- [docs/USAGE.md](docs/USAGE.md): desktop app, full command reference, install/uninstall, recovery
  steps and security design
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md): what Gatekeeper does not protect against
- [models/README.md](models/README.md): where each face model comes from and its licence

## Repository layout

```
gatekeeper/               package (docs/USAGE.md > Layout lists what each module does)
docs/                     USAGE.md, LIMITATIONS.md
models/                   SCRFD, ArcFace and MiniFASNet ONNX models (hash-pinned)
tests/                    pytest suite
tools/                    model conversion script
LICENSE.txt               licence agreement shown by the installer
THIRD_PARTY_NOTICES.txt   licences of bundled third-party components
installer.iss, gatekeeper.spec, build.ps1
```

## Licence and ownership

Gatekeeper (decLock) is owned by **saimumadi00-sketch** (<https://github.com/saimumadi00-sketch>).
It is proprietary software: all rights reserved. Personal, educational and research use is
permitted under the terms of [LICENSE.txt](LICENSE.txt); selling, redistributing or presenting it as
someone else's work is not. The installer shows this agreement and requires you to accept it.

Bundled third-party components are owned by their authors and used under their own licences; see
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt). Because the InsightFace face models are licensed
for non-commercial research use only, Gatekeeper may not be used commercially.
