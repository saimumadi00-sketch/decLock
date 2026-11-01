# Gatekeeper: usage guide

Commands below are run from the repository root.

Offline, password-gated app lock for Windows 10/11. Locked apps are suspended when they start
until you enter the password (or your face matches); otherwise they are closed. It can also
block new USB storage devices and lock the workstation when idle. No network access, no cloud.

**Read [LIMITATIONS.md](LIMITATIONS.md) first.** Gatekeeper deters casual access; it is not
protection against an administrator, Safe Mode, or booting from other media.

## Desktop app

```
python -m gatekeeper --dev gui      # try it safely: nothing is killed, blocked or locked
python -m gatekeeper gui            # the real thing
```

The first launch asks you to choose a password. After logging in you get a sidebar with:

| Page | What you can do (no commands needed) |
|---|---|
| Dashboard | Status tiles (with a "Problems (24h)" tile that opens the log filtered to problems), a 7-day chart you can switch between unlocked/denied, blocked starts and most-attempted apps (click a day to open its log), first-run checklist, pause/resume, verify the log, lock Windows |
| Locked apps | Add by name, browse for an `.exe`, pick from running programs, or add a preset (browsers, games, chat, office). Shows last attempt and denied count; set a per-app lock schedule (e.g. 22:00-06:00) |
| USB and idle lock | Block or allow USB storage, set the idle-lock minutes, lock Windows now |
| Face unlock | Enroll with a live camera preview, run the full unlock check as a test (with live match, real-face and head-pose numbers), adjust strictness and timeout, delete face data |
| Activity log | Filter by event, severity, time range, day or text; export CSV; verify the chain; remove old entries; reset the chain |
| Settings | Change password, light/dark theme, optional 60-second password memory, dashboard auto-lock, log retention, open the data folder, release frozen apps |

How it behaves:

- **The guard and the dashboard are one program.** Locked apps stay protected whether or not you are logged in
  to the window; the password only gates *managing* Gatekeeper.
- **The X button minimizes and locks the window.** Protection keeps running. To really stop Gatekeeper use
  **Quit Gatekeeper** (needs your password). Pausing protection, removing a locked app, resetting the log and deleting face data also ask for it.
- **The unlock prompt is a Face ID style overlay.** When a locked app starts, the whole screen is blurred and dimmed, and a card fades in over it with the face animation (scan, then a checkmark on success, or a shake on failure). Everything fades in and out. If the screen can't be captured it falls back to a plain dark backdrop.
- **The window locks itself** after 5 idle minutes (change it in Settings). A wrong-password lockout counts down live on the login screen.
- **Tray icon (optional).** With `pystray` and `Pillow` installed, Gatekeeper shows a tray icon (Open, Pause/Resume, Lock, Quit) and the X button hides the window to the tray.
- **Shortcuts:** Ctrl+L locks the dashboard; Ctrl+1 to Ctrl+6 switch pages.
- **A red banner** appears on every page if the audit log fails its integrity check.
- **USB changes need Administrator.** If Gatekeeper is not elevated it offers to restart itself as Administrator
  (UAC prompt). Note: elevating with a *different* Windows account would use that account's data folder, so
  do this from an account that is an administrator itself.
- **One copy only.** Starting it twice, or running `gatekeeper run` while the app is open, is refused.
- The installed copy starts minimized at logon (`gatekeeperw.exe --service gui --minimized`).

The command-line tool still works and shares the same data, so you can mix both.

## Quick start (development, safe)

```
pip install -r requirements.txt
python -m gatekeeper --dev init            # set a password
python -m gatekeeper --dev add notepad     # lock Notepad
python -m gatekeeper --dev run             # dev mode only LOGS what it would do
python -m pytest -q
```

`--dev` (or `GATEKEEPER_DEV=1`) disables process killing, USB blocking and screen locking, and uses a
separate data folder (`%APPDATA%\Gatekeeper-dev`). Dev mode is refused with `--service` and refused via
the environment variable in the installed build. Drop `--dev` to enforce for real. Start with a harmless app such as Notepad.

## Commands

| Command | What it does | Password |
|---|---|---|
| `init` | set or change the password | when changing |
| `add <exe>` / `remove <exe>` / `list` | manage locked apps (`explorer`, `cmd`, `python`... are refused) | add/remove |
| `run` | start the guard (prompt shows face check + password box) | no |
| `usb block\|allow\|status` | USB storage policy (**needs an elevated prompt**) | block/allow |
| `idle-lock <minutes>` / `lock-now` | Windows lock after N idle minutes (0 = off) | idle-lock |
| `face enroll\|clear\|status` | face samples (encrypted) | enroll/clear |
| `face test` | live match / real-face / head-pose preview for tuning | no |
| `face threshold <0.25-0.8>` / `timeout <8-45>` / `enable` / `disable` | tune face unlock | yes |
| `log export <file.csv>` / `retention <days>` / `prune` / `reset` | audit log (default retention 90 days, 0 = forever) | yes |
| `verify-log` / `status` | check the audit chain | no |
| `release` | un-freeze any locked app left suspended | only while a guard is running |

## Install

Build (needs Python 3.10+ and, for the installer, [Inno Setup 6](https://jrsoftware.org/isinfo.php)):

```
powershell -File build.ps1
```

This runs the tests, builds `dist\gatekeeper\` (`gatekeeper.exe` for the CLI, `gatekeeperw.exe` for the
windowless guard) and, if Inno Setup is installed, `installer\GatekeeperSetup-0.1.0.exe`.
Run the installer as an administrator. It installs to `Program Files`, adds a startup entry for all
users (`gatekeeperw.exe --service gui --minimized`), and offers to open Gatekeeper, which asks you to
choose a password on first launch. Add apps in the dashboard, or from the command line:

```
"C:\Program Files\Gatekeeper\gatekeeper.exe" add notepad
```

Note: "service" here means the installed autostart mode, not a Windows Service. Services run in session 0 and cannot show a prompt on your desktop.

## Uninstall

Settings > Apps > Gatekeeper > Uninstall (admin required). Before removing anything, the uninstaller
shows the Gatekeeper password prompt; cancelling, a wrong password (3 tries, same lockout as
everywhere else) or the 60-second timeout stops the uninstall. Silent uninstalls (`/SILENT`) are
checked too. If several Windows users set up Gatekeeper, any of their passwords is accepted; if no
one set a password, no prompt is shown. Both outcomes are logged (`uninstall_allowed` /
`uninstall_refused`). After the password is accepted, the uninstaller stops the guard, resumes any frozen app, re-enables USB storage, and asks
whether to delete your settings and face data (`%APPDATA%\Gatekeeper`).

## Recovery

| Problem | Fix |
|---|---|
| An app is frozen | `gatekeeper.exe release` (no password needed once the guard has stopped or crashed). |
| Forgot the Gatekeeper password | There is no backdoor. Stop the guard (Task Manager), delete `%APPDATA%\Gatekeeper`, and set up again. Face data is lost. |
| Locked out after wrong passwords | Wait (30 s, doubling to 15 min). Face unlock still works. |
| USB storage stays blocked | Elevated prompt: `reg add HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start /t REG_DWORD /d 3 /f` (or `gatekeeper.exe usb allow`). |
| Windows lock screen won't accept the Gatekeeper password | Expected: idle lock uses your **Windows** account password. |
| "Audit log failed its integrity check" | Run `log export`, look for what changed, then `log reset` to start a new chain (the old log is saved to `audit-before-reset.csv`). |
| Guard won't start in `--dev` | Dev mode is refused with `--service`; run `gatekeeper.exe` without that flag. |

## Security design

- **Passwords:** bcrypt (cost 12) over a SHA-256 pre-hash; minimum 8 characters.
- **Brute force:** 5 free failures, then 30 s doubling to 15 min, persisted across restarts; while locked even the correct password is refused. Each prompt also allows only 3 tries before the app is closed.
- **Face data:** embeddings and snapshots are Fernet-encrypted; the key is wrapped with Windows DPAPI (tied to your Windows user and this PC). Models are SHA-256 pinned (see `models/README.md` for sources and licences). Face data is biometric: use `face clear` when you stop using it, and `--no-snapshots` to store vectors only.
- **Face unlock:** every attempt must pass three checks at once.
  1. *Identity:* SCRFD finds the face, which is aligned and turned into an ArcFace vector and compared with the enrolled samples (default strictness 0.40).
  2. *Real face:* MiniFASNet (two models, averaged) checks every frame for photos, prints and screens.
  3. *Challenge:* two head movements (left / right / up / down) in a random order, chosen with the OS's secure random generator. They are measured from the face's own landmarks, so tilting a photo can't fake them, and moving the wrong way fails the attempt. The same face must stay in view throughout and must match again at the end.

  Enrolment only accepts real, front-facing samples. Samples made by the old YuNet/SFace models are not comparable: face unlock stays off until you enroll again.
- **Audit log:** SQLite, hash-chained, with a head seal (deleting it is detected too); verified at every start and every few seconds while the dashboard is open. Tampering raises a warning but never stops protection. CSV export neutralises spreadsheet formulas.
- **Renamed copies:** a locked app is recognised even when renamed or copied, by the original name in its version information and by a SHA-256 fingerprint of the file (learned when you lock it by browsing to the `.exe`, and whenever the real app runs). Programs in the Windows folder are skipped.
- **Safety:** protected system processes cannot be locked; shutting the guard down resumes frozen apps; a force-kill is recoverable with `release`.

## Layout

```
gatekeeper/   package
  cli, app, config, devmode            commands, start-up wiring, settings, dev mode
  guard, identity, runtime, schedule   process watcher, renamed-copy detection, prompt queue, lock windows
  ui, face_anim, blur                  the unlock overlay, its Face ID animation, the blurred backdrop
  auth, audit, crypto, db              passwords and lockout, hash-chained log, DPAPI key, SQLite
  faces, liveness, matcher             face models, the anti-spoof challenge, the live attempt
  enroll, face_store                   enrolment, encrypted samples
  usb, idle, winapi                    USB storage policy, idle lock, Windows API calls
  dashboard, gui_pages, gui_widgets,   the desktop app, its pages, shared widgets,
  dashdata, tray                       its Tk-free logic, and the optional tray icon
models/       SCRFD, ArcFace and MiniFASNet ONNX models (hash-pinned; see models/README.md)
tests/        pytest suite
installer.iss, gatekeeper.spec, build.ps1
```
