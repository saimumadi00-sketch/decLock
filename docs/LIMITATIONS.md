# What Gatekeeper cannot prevent

Gatekeeper is a **deterrent against casual access**: someone sitting down at your unlocked PC
and opening an app you locked. It is not a security boundary against a determined person.
Read this before relying on it.

## Cannot be prevented

| Threat | Why | What helps |
|---|---|---|
| **Killing the guard** (Task Manager, `taskkill`) | The guard runs as your Windows user, so anyone in your session has the same rights over it. | Day-to-day work in a **standard (non-admin) account**. Gatekeeper logs an `unclean_shutdown` at the next start, but cannot stop it. |
| **Deleting or editing its data** (`%APPDATA%\Gatekeeper`) | Same reason: the files belong to your user. This also resets the password. | Standard account plus BitLocker. The audit chain and head seal detect edits, but someone with your rights can rewrite both. |
| **An administrator account** | Admins can stop services, edit the registry (undo the USB block), and take ownership of files. The uninstaller asks for the Gatekeeper password, but an admin can still kill the guard and delete `C:\Program Files\Gatekeeper` and the startup shortcut by hand. | Don't use an admin account day to day. Keep a separate admin account with a different password. |
| **Safe Mode** | Windows starts without third-party startup items, so the guard never runs. | A BIOS/UEFI password and Windows account passwords on every account. |
| **Booting from external media** (USB/Linux live disk) | The disk can be read without Windows running at all. | **BitLocker** (with a TPM + PIN), a **BIOS/UEFI password**, and boot order locked to the internal disk. |
| **Starting an app faster than a scan** | Windows cannot block a process before it exists without a kernel driver. The guard suspends it within about 0.5 s. | Not preventable in user mode. |
| **Elevated or protected processes** | A non-admin guard cannot suspend them (`enforce_failed` is logged). | Run the guard elevated only if you accept the larger attack surface. |
| **Masks, deepfakes, a lookalike** | Face unlock rejects photos and screens (MiniFASNet anti-spoofing) and asks for two random head movements a still image or recording can't follow. A realistic 3D mask, or a live deepfake that can follow instructions, might still pass; so might a close relative who looks very similar. | Raise the strictness, or turn face unlock off for apps that matter. The password is the real lock. |
| **Editing a locked program's file** | Renamed or copied programs are recognised by their built-in original name and a SHA-256 fingerprint. Someone who edits the file itself (changing both its version information and its bytes) is not recognised. A program with no version information is only fingerprinted once it has run while locked, or was locked by browsing to its `.exe`. | Lock apps by browsing to their `.exe`; use a standard account. |
| **Changing the time zone (lock schedules)** | Schedules use local time, and a standard user may change the time zone, which shifts "now" out of the lock window. | Leave schedules off (always locked) for apps that matter. |
| **Changing the system clock** | The brute-force lockout timer uses wall-clock time. | Standard account (changing the clock needs admin). |
| **Already-mounted USB drives; non-storage USB devices** | The block disables the storage driver for new devices only. | Out of scope for this tool. |

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
- Every blocked/denied/unlocked event is logged in a hash-chained audit log that is verified at startup
  and every few seconds while the dashboard is open. Deleting the `audit.head` seal is detected too.

## Possible future hardening (not implemented)

A Windows service running as SYSTEM, with a small agent in the user session for the prompt, would
make the guard much harder to stop from a standard account. It is a larger redesign.
