# What Gatekeeper cannot prevent

Gatekeeper is a **deterrent against casual access**: someone sitting down at your unlocked PC
and opening an app you locked. It is not a security boundary against a determined person.
Read this before relying on it.

## Cannot be prevented

| Threat | Why | What helps |
|---|---|---|
| **Killing the guard** (Task Manager, `taskkill`) | The guard runs as your Windows user, so anyone in your session has the same rights over it. | Day-to-day work in a **standard (non-admin) account**. Gatekeeper logs an `unclean_shutdown` at the next start, but cannot stop it. |
| **Deleting or editing its data** (`%APPDATA%\Gatekeeper`) | Same reason: the files belong to your user. Deleting the folder no longer gives a fresh setup in the installed build (an admin-protected marker refuses it), but *editing* the database can still swap the password hash or the locked-app list. | Standard account plus BitLocker. The audit chain and head seal detect edits, but someone with your rights can rewrite both. |
| **An administrator account** | Admins can stop services, edit the registry (undo the USB block), and take ownership of files. The uninstaller asks for the Gatekeeper password, but an admin can still kill the guard and delete `C:\Program Files\Gatekeeper` and the startup shortcut by hand. | Don't use an admin account day to day. Keep a separate admin account with a different password. |
| **Safe Mode** | Windows starts without third-party startup items, so the guard never runs. | A BIOS/UEFI password and Windows account passwords on every account. |
| **Booting from external media** (USB/Linux live disk) | The disk can be read without Windows running at all. | **BitLocker** (with a TPM + PIN), a **BIOS/UEFI password**, and boot order locked to the internal disk. |
| **Starting an app faster than a scan** | Windows cannot block a process before it exists without a kernel driver. The guard suspends it within about 0.5 s. | Not preventable in user mode. |
| **Elevated or protected processes** | A non-admin guard cannot suspend them (`enforce_failed` is logged). | Run the guard elevated only if you accept the larger attack surface. |
| **Masks, deepfakes, a lookalike** | Face unlock rejects photos and screens (MiniFASNet anti-spoofing) and asks for two random head movements a still image or recording can't follow. A realistic 3D mask, or a live deepfake that can follow instructions, might still pass; so might a close relative who looks very similar. | Raise the strictness, or turn face unlock off for apps that matter. The password is the real lock. |
| **Editing a locked program's file** | Renamed or copied programs are recognised by their built-in original name and a SHA-256 fingerprint. Someone who edits the file itself (changing both its version information and its bytes) is not recognised. A program with no version information is only fingerprinted once it has run while locked, or was locked by browsing to its `.exe`. | Lock apps by browsing to their `.exe`; use a standard account. |
| **Changing the time zone (lock schedules)** | Schedules use local time, and a standard user may change the time zone, which shifts "now" out of the lock window. | Leave schedules off (always locked) for apps that matter. |
| **Changing the system clock** | The brute-force lockout timer uses wall-clock time. | Standard account (changing the clock needs admin). |
| **Already-mounted USB drives; network, cloud, email, Bluetooth** | The block disables the storage driver for new devices only. | Out of scope for this tool. |

## Folder lock

Locked folders get a "deny" permission for Everyone. Windows enforces it for every program, but
the folder's owner (you, or anyone in your unlocked session) and administrators can still change
permissions by hand, exactly as they could stop Gatekeeper. Gatekeeper puts a removed lock back
within 30 seconds while it runs. Windows can't show a password prompt when a locked folder is
opened, so folders are unlocked from the dashboard. Folders that Windows, programs or Gatekeeper
need (drive roots, Windows, Program Files, AppData, your profile and its main folders) can't be
locked; lock a folder inside them instead.

## Recommended setup

1. Install Gatekeeper from an **administrator** account, then do daily work in a **standard user** account.
2. Turn on **BitLocker** (TPM + PIN) and set a **BIOS/UEFI password**; disable booting from USB/network.
3. Give every Windows account a strong password.
4. Pick a Gatekeeper password that differs from your Windows one.

## What Gatekeeper does guarantee

- Passwords are stored only as bcrypt hashes. Face vectors and snapshots are encrypted at rest.
- Wrong passwords trigger a persistent, doubling lockout (30 s up to 15 min) that survives restarts.
- The guard never leaves processes frozen on a clean exit, and `gatekeeper release` un-freezes them
  (it asks for the password while a guard is running, so it cannot be used to skip a prompt).
- Once a Windows user has set a Gatekeeper password, deleting their data folder does not reopen first-run setup:
  a marker in `C:\ProgramData\Gatekeeper\enrolled` (users can add, never delete) refuses it until an admin clears it.
- Apps that are already open lock again when Windows locks and after the re-lock idle time (default 10 minutes).
  They are frozen and held, never closed, so unsaved work survives a wrong or unanswered prompt.
- Face unlock: models are built from the exact bytes that were hash-checked; the installed build only
  uses its bundled models; five failed face attempts pause face unlock for 15 minutes (your password
  ends the pause); strictness can't go below 0.30; and face unlock switches off while software that can
  fake a webcam is installed (DirectShow virtual cameras; newer Windows 11 virtual cameras that don't
  register that way are not detected).
- USB blocking covers USBSTOR, UASPStor (fast USB 3 drives) and the removable-storage policy (phones,
  card readers, CD/DVD; this one can need a sign-out to apply). A password-approved temporary allow
  blocks again by itself, backed by a one-shot SYSTEM scheduled task. If the block is turned off
  while Gatekeeper isn't running as Administrator it can't repair it, but the dashboard shows it in red.
- Uninstalling needs the Gatekeeper password of every Windows user who set it up.
- The activity log is checkpointed about once an hour into the add-only ProgramData folder. Rewriting
  or deleting checkpointed entries fails the log check, even if every hash is recomputed. The only
  way around it is to fake a "log reset", and resets can never be removed afterwards.
- The installed build ignores `GATEKEEPER_DATA_DIR`, so a planted environment variable cannot move the guard
  onto an empty folder (it is logged as `env_ignored`). Only `--data-dir` in the startup shortcut can.
- Every blocked/denied/unlocked event is logged in a hash-chained audit log that is verified at startup
  and every few seconds while the dashboard is open. Deleting the `audit.head` seal is detected too.

## Possible future hardening (not implemented)

A Windows service running as SYSTEM, with a small agent in the user session for the prompt, would
make the guard much harder to stop from a standard account. It is a larger redesign.
