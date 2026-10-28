# What Gatekeeper cannot prevent

Gatekeeper is a **deterrent against casual access**: someone sitting down at your unlocked PC
and opening an app you locked. It is not a security boundary against a determined person.
Read this before relying on it.

## Cannot be prevented

| Threat | Why | What helps |
|---|---|---|
| **Killing the guard** (Task Manager, `taskkill`) | The guard runs as your Windows user, so anyone in your session has the same rights over it. | Day-to-day work in a **standard (non-admin) account**. Gatekeeper logs an `unclean_shutdown` at the next start, but cannot stop it. |
| **Deleting or editing its data** (`%APPDATA%\Gatekeeper`) | Same reason: the files belong to your user. This also resets the password. | Standard account plus BitLocker. The audit chain and head seal detect edits, but someone with your rights can rewrite both. |
| **An administrator account** | Admins can stop services, edit the registry (undo the USB block), uninstall the app (the uninstaller does not ask for the Gatekeeper password), and take ownership of files. | Don't use an admin account day to day. Keep a separate admin account with a different password. |
| **Safe Mode** | Windows starts without third-party startup items, so the guard never runs. | A BIOS/UEFI password and Windows account passwords on every account. |
| **Booting from external media** (USB/Linux live disk) | The disk can be read without Windows running at all. | **BitLocker** (with a TPM + PIN), a **BIOS/UEFI password**, and boot order locked to the internal disk. |
| **Starting an app faster than a scan** | Windows cannot block a process before it exists without a kernel driver. The guard suspends it within about 0.5 s. | Not preventable in user mode. |
| **Elevated or protected processes** | A non-admin guard cannot suspend them (`enforce_failed` is logged). | Run the guard elevated only if you accept the larger attack surface. |
| **Photos/video held to the camera** | Face matching has no liveness detection. | Treat face unlock as a convenience. The password is the real lock. |
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
- The guard never leaves processes frozen on a clean exit, and `gatekeeper release` un-freezes them.
- Every blocked/denied/unlocked event is logged in a hash-chained audit log that is verified at startup.

## Possible future hardening (not implemented)

A Windows service running as SYSTEM, with a small agent in the user session for the prompt, would
make the guard much harder to stop from a standard account. It is a larger redesign.
