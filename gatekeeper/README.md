# Gatekeeper

Offline, password-gated app lock for Windows 10/11. Locked apps are suspended when they start
until you enter the password (or your face matches); otherwise they are closed. It can also
block new USB storage devices and lock the workstation when idle. No network access, no cloud.

**Read [docs/LIMITATIONS.md](docs/LIMITATIONS.md) first.** Gatekeeper deters casual access; it is not
protection against an administrator, Safe Mode, or booting from other media.

## Desktop app

```
python -m gatekeeper --dev gui      # try it safely: nothing is killed, blocked or locked
python -m gatekeeper gui            # the real thing
```

The first launch asks you to choose a password. After logging in you get a sidebar with:

| Page | What you can do (no commands needed) |
|---|---|
| Dashboard | Protection status, 7-day activity chart, recent events, pause/resume protection, verify the log, lock Windows |
| Locked apps | Add by name, browse for an `.exe`, or pick from running programs; remove with one click |
| USB and idle lock | Block or allow USB storage, set the idle-lock minutes, lock Windows now |
| Face unlock | Enroll with a live camera preview, test the score, adjust strictness and timeout, delete face data |
| Activity log | Filter by event, time range or text; export CSV; verify the chain; remove old entries; reset the chain |
| Settings | Change password, dashboard auto-lock, log retention, open the data folder, release frozen apps |

How it behaves:

- **The guard and the dashboard are one program.** Locked apps stay protected whether or not you are logged in
  to the window; the password only gates *managing* Gatekeeper.
- **The X button minimizes and locks the window.** Protection keeps running. To really stop Gatekeeper use
  **Quit Gatekeeper** (needs your password). Pausing protection and deleting face data also ask for it.
- **The window locks itself** after 5 idle minutes (change it in Settings).
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
| `face test` | live score preview for tuning | no |
| `face threshold <0.2-0.9>` / `timeout <2-30>` / `enable` / `disable` | tune face unlock | yes |
| `log export <file.csv>` / `retention <days>` / `prune` / `reset` | audit log (default retention 90 days, 0 = forever) | yes |
| `verify-log` / `status` | check the audit chain | no |
| `release` | un-freeze any locked app left suspended | no |

## Install

Build (needs Python 3.10+ and, for the installer, [Inno Setup 6](https://jrsoftware.org/isinfo.php)):

```
powershell -File build.ps1
```

This runs the tests, builds `dist\gatekeeper\` (`gatekeeper.exe` for the CLI, `gatekeeperw.exe` for the
windowless guard) and, if Inno Setup is installed, `installer\GatekeeperSetup-0.1.0.exe`.
Run the installer as an administrator. It installs to `Program Files`, adds a startup entry for all
users (`gatekeeperw.exe --service run`), and offers to set your password. Add apps afterwards:

```
"C:\Program Files\Gatekeeper\gatekeeper.exe" add notepad
```

Note: "service" here means the installed autostart mode, not a Windows Service. Services run in session 0 and cannot show a prompt on your desktop.

## Uninstall

Settings > Apps > Gatekeeper > Uninstall (admin required; it does not ask for the Gatekeeper
password). The uninstaller stops the guard, resumes any frozen app, re-enables USB storage, and asks
whether to delete your settings and face data (`%APPDATA%\Gatekeeper`).

## Recovery

| Problem | Fix |
|---|---|
| An app is frozen | `gatekeeper.exe release` (no password needed). |
| Forgot the Gatekeeper password | There is no backdoor. Stop the guard (Task Manager), delete `%APPDATA%\Gatekeeper`, and set up again. Face data is lost. |
| Locked out after wrong passwords | Wait (30 s, doubling to 15 min). Face unlock still works. |
| USB storage stays blocked | Elevated prompt: `reg add HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR /v Start /t REG_DWORD /d 3 /f` (or `gatekeeper.exe usb allow`). |
| Windows lock screen won't accept the Gatekeeper password | Expected: idle lock uses your **Windows** account password. |
| "Audit log failed its integrity check" | Run `log export`, look for what changed, then `log reset` to start a new chain (the old log is saved to `audit-before-reset.csv`). |
| Guard won't start in `--dev` | Dev mode is refused with `--service`; run `gatekeeper.exe` without that flag. |

## Security design

- **Passwords:** bcrypt (cost 12) over a SHA-256 pre-hash; minimum 8 characters.
- **Brute force:** 5 free failures, then 30 s doubling to 15 min, persisted across restarts; while locked even the correct password is refused. Each prompt also allows only 3 tries before the app is closed.
- **Face data:** embeddings and snapshots are Fernet-encrypted; the key is wrapped with Windows DPAPI (tied to your Windows user and this PC). Models (YuNet, SFace) are SHA-256 pinned. Face data is biometric: use `face clear` when you stop using it, and `--no-snapshots` to store vectors only.
- **Audit log:** SQLite, hash-chained, with a head seal; verified every start. Tampering raises a warning but never stops protection. CSV export neutralises spreadsheet formulas.
- **Safety:** protected system processes cannot be locked; shutting the guard down resumes frozen apps; a force-kill is recoverable with `release`.

## Layout

```
gatekeeper/   package (cli, guard, ui, auth, audit, usb, idle, faces, enroll, matcher, crypto, db)
models/       YuNet + SFace ONNX models (hash-pinned)
tests/        pytest suite
installer.iss, gatekeeper.spec, build.ps1
```
