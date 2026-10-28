import tkinter as tk
from tkinter import ttk
from typing import Callable


class UnlockPrompt:
    """Modal always-on-top password prompt. Denies on timeout, close, or too many failures."""

    def __init__(self, root: tk.Tk, app_name: str, verify: Callable[[str], bool],
                 on_done: Callable[[bool], None], timeout: int = 60, max_attempts: int = 3,
                 on_failure: Callable[[], None] = lambda: None, face=None,
                 on_face_result: Callable[[str, object], None] = lambda state, score: None,
                 lockout: Callable[[], float] = lambda: 0):
        self.verify, self.on_done, self.on_failure = verify, on_done, on_failure
        self.lockout = lockout
        self.face, self.on_face_result = face, on_face_result
        self.attempts_left, self.remaining, self.finished = max_attempts, timeout, False

        self.win = tk.Toplevel(root)
        self.win.title("Gatekeeper")
        self.win.attributes("-topmost", True)
        self.win.resizable(False, False)
        self.win.protocol("WM_DELETE_WINDOW", lambda: self._finish(False))

        frame = ttk.Frame(self.win, padding=16)
        frame.pack()
        ttk.Label(frame, text=f"{app_name} is locked", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Enter the Gatekeeper password to continue.").pack(anchor="w", pady=(4, 8))
        self.entry = ttk.Entry(frame, show="*", width=30)
        self.entry.pack(fill="x")
        self.entry.bind("<Return>", lambda _e: self._submit())
        self.face_label = ttk.Label(frame)
        self.face_label.pack(anchor="w", pady=(6, 0))
        self.message = ttk.Label(frame, foreground="#b00020")
        self.message.pack(anchor="w")
        self.countdown = ttk.Label(frame)
        self.countdown.pack(anchor="w")
        buttons = ttk.Frame(frame)
        buttons.pack(anchor="e", pady=(8, 0))
        ttk.Button(buttons, text="Cancel", command=lambda: self._finish(False)).pack(side="right")
        ttk.Button(buttons, text="Unlock", command=self._submit).pack(side="right", padx=(0, 6))

        self.win.update_idletasks()
        x = (self.win.winfo_screenwidth() - self.win.winfo_width()) // 2
        y = (self.win.winfo_screenheight() - self.win.winfo_height()) // 3
        self.win.geometry(f"+{x}+{y}")
        self.win.grab_set()
        self.win.focus_force()
        self.entry.focus_set()
        self._tick()
        if self.face:
            self.face_label.config(text="Looking for your face... (or type the password)")
            self.face.start()
            self._poll_face()

    def _poll_face(self) -> None:
        # Tk is not thread-safe: the camera thread only sets `state`; the UI thread reads it here.
        if self.finished:
            return
        state = self.face.state
        if state == "matched":
            self.on_face_result(state, self.face.best)
            self._finish(True)
        elif state in ("failed", "unavailable"):
            self.on_face_result(state, self.face.best)
            self.face_label.config(text="Face not recognized. Enter the password." if state == "failed"
                                   else "Camera unavailable. Enter the password.")
        else:
            self.win.after(100, self._poll_face)

    def _tick(self) -> None:
        if self.finished:
            return
        if self.remaining <= 0:
            self._finish(False)
            return
        self.countdown.config(text=f"Closing in {self.remaining}s")
        self.remaining -= 1
        self.win.after(1000, self._tick)

    def _submit(self) -> None:
        password = self.entry.get()
        self.entry.delete(0, "end")
        if self.lockout() > 0:
            self.message.config(text=f"Too many failures. Locked for {int(self.lockout())}s.")
            return
        if self.verify(password):
            self._finish(True)
            return
        self.on_failure()
        self.attempts_left -= 1
        if self.attempts_left <= 0 or self.lockout() > 0:
            self._finish(False)
        else:
            self.message.config(text=f"Wrong password. {self.attempts_left} attempt(s) left.")

    def _finish(self, allowed: bool) -> None:
        if self.finished:
            return
        self.finished = True
        if self.face:
            self.face.cancel()
        self.win.grab_release()
        self.win.destroy()
        self.on_done(allowed)
