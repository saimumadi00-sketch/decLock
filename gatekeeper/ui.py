"""The unlock prompt shown when a locked app starts (the app is frozen until it closes)."""

import time
import tkinter as tk
from typing import Callable

from . import blur, face_anim, winapi
from .face_anim import ease_in_out, ease_out

# Dark "system sheet" colours, independent of the dashboard theme.
CARD, CARD_EDGE, FIELD = "#1c1c1e", "#3a3a3c", "#2c2c2e"
TEXT, MUTED, ACCENT, DANGER = "#f5f5f7", "#98989f", "#0a84ff", "#ff453a"
FONT = "Segoe UI"
FADE_IN_MS, FADE_OUT_MS = 340, 260
FACE_START_MS = 80          # camera starts just after the fade begins, so opening it can't stutter the fade
PAD, RADIUS = 30, 30        # padding around the card and its corner radius, in pixels


def rounded_rect(canvas: tk.Canvas, x0, y0, x1, y1, radius, **kw):
    """A rounded rectangle: a polygon with doubled corner points, smoothed into curves by Tk."""
    pts = [x0 + radius, y0, x1 - radius, y0, x1, y0, x1, y0 + radius, x1, y1 - radius, x1, y1,
           x1 - radius, y1, x0 + radius, y1, x0, y1, x0, y1 - radius, x0, y0 + radius, x0, y0]
    return canvas.create_polygon(pts, smooth=True, **kw)


class UnlockPrompt:
    """Always-on-top password / Face ID prompt. Denies on timeout, close, or too many failures.

    With `fullscreen` (the default) the whole desktop is covered by a blurred, dimmed snapshot of the
    screen and a card fades in on top of it, like Face ID. Everything fades: the backdrop and card in,
    and out again when the prompt ends. With a face match the checkmark plays before the app resumes.
    """

    def __init__(self, root: tk.Tk, app_name: str, verify: Callable[[str], bool],
                 on_done: Callable[[bool], None], timeout: int = 60, max_attempts: int = 3,
                 on_failure: Callable[[], None] = lambda: None, face=None,
                 on_face_result: Callable[[str, object], None] = lambda state, score: None,
                 lockout: Callable[[], float] = lambda: 0, fullscreen: bool = True):
        # verify(password) -> bool; on_done(allowed) resumes or kills the app; lockout() -> seconds left
        self.verify, self.on_done, self.on_failure = verify, on_done, on_failure
        self.lockout = lockout
        self.face, self.on_face_result = face, on_face_result  # face: matcher.FaceUnlock or None
        self.attempts_left, self.remaining, self.finished = max_attempts, timeout, False
        self.closing = False  # face matched: the success animation is playing, unlock is pending
        self.anim, self._fade_job, self._backdrop = None, None, None
        self.peak = 1.0       # window opacity at rest (a bit lower when there is no blurred screenshot)

        # Capture the desktop BEFORE our own window exists, so the overlay doesn't photograph itself.
        if fullscreen:
            vx, vy, vw, vh = winapi.virtual_screen()  # spans every monitor
            data = blur.blurred_backdrop(vx, vy, vw, vh)
            self.peak = 1.0 if data else 0.86  # no screenshot: a see-through dark veil instead
        else:
            vx = vy = 0
            vw, vh = root.winfo_screenwidth(), root.winfo_screenheight()
            data = None

        self.win = tk.Toplevel(root)
        self.win.withdraw()                       # stay hidden until it is laid out
        self.win.overrideredirect(True)           # no title bar or borders
        self.win.attributes("-topmost", True)
        self.win.attributes("-alpha", 0.0)        # starts invisible, then fades in
        self.win.configure(bg="#05070d")
        self.win.protocol("WM_DELETE_WINDOW", self._cancel)  # Alt+F4
        self.win.bind("<Escape>", lambda _e: self._cancel())

        card = tk.Frame(self.win, bg=CARD)
        self._build_card(card, app_name)
        card.update_idletasks()
        cw, ch = card.winfo_reqwidth() + 2 * PAD, card.winfo_reqheight() + 2 * PAD
        if fullscreen:
            width, height, x, y = vw, vh, vx, vy
            # Centre the card on the PRIMARY monitor (canvas coordinates start at the virtual origin).
            cx, cy = root.winfo_screenwidth() / 2 - vx, root.winfo_screenheight() * 0.46 - vy
        else:
            width, height = cw, ch
            x, y = (vw - cw) // 2, (vh - ch) // 3
            cx, cy = cw / 2, ch / 2
        self.canvas = tk.Canvas(self.win, width=width, height=height, bg="#05070d", highlightthickness=0)
        self.canvas.pack()
        if data:
            # The backdrop is delivered at half size (smaller PNG); zoom(2) restores full size.
            self._backdrop = tk.PhotoImage(data=data).zoom(2)
            self.canvas.create_image(0, 0, image=self._backdrop, anchor="nw")
        rounded_rect(self.canvas, cx - cw / 2, cy - ch / 2, cx + cw / 2, cy + ch / 2, RADIUS,
                     fill=CARD, outline=CARD_EDGE, width=1)
        card.lift()
        self.canvas.create_window(cx, cy, window=card)  # place the widget card on the rounded shape

        self.win.geometry(f"{width}x{height}{x:+d}{y:+d}")
        self.win.deiconify()
        self.win.update_idletasks()
        self.win.grab_set()                       # all input goes to the prompt
        winapi.force_foreground(self.win.winfo_id())
        self.entry.focus_force()
        self._fade(0.0, self.peak, FADE_IN_MS, ease_out)
        self._tick()                              # starts the countdown to auto-deny
        if self.face:
            self.face_label.config(text="Looking for your face... (or type the password)")
            self.anim.fade_in(FADE_IN_MS)
            self.win.after(FACE_START_MS, self._start_face)

    # -- layout --------------------------------------------------------------------------------
    def _build_card(self, card: tk.Frame, app_name: str) -> None:
        if self.face:  # the Face ID animation only appears when face unlock is usable
            self.anim = face_anim.FaceIDAnimation(card, size=168, bg=CARD)
            self.anim.pack(pady=(0, 6))
        tk.Label(card, text=f"{app_name} is locked", bg=CARD, fg=TEXT, font=(FONT, 16, "bold")).pack()
        self.face_label = tk.Label(card, text=" ", bg=CARD, fg=MUTED, font=(FONT, 10))
        self.face_label.pack(pady=(4, 0))
        tk.Label(card, text="Enter the Gatekeeper password to continue.", bg=CARD, fg=MUTED,
                 font=(FONT, 10)).pack(pady=(10, 8))
        self.entry = tk.Entry(card, show="*", width=28, bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat",
                              font=(FONT, 12), highlightthickness=1, highlightbackground=CARD_EDGE,
                              highlightcolor=ACCENT)
        self.entry.pack(ipady=6)
        self.entry.bind("<Return>", lambda _e: self._submit())
        # " " instead of "" keeps each label's height reserved, so the card doesn't jump.
        self.message = tk.Label(card, text=" ", bg=CARD, fg=DANGER, font=(FONT, 10))
        self.message.pack(pady=(8, 0))
        self.countdown = tk.Label(card, text=" ", bg=CARD, fg=MUTED, font=(FONT, 9))
        self.countdown.pack()
        buttons = tk.Frame(card, bg=CARD)
        buttons.pack(pady=(10, 0))
        for text, command, bg in (("Cancel", self._cancel, FIELD), ("Unlock", self._submit, ACCENT)):
            tk.Button(buttons, text=text, command=command, bg=bg, fg="white", activebackground=bg,
                      activeforeground="white", relief="flat", bd=0, padx=22, pady=7, font=(FONT, 10, "bold"),
                      cursor="hand2").pack(side="left", padx=5)

    # -- fades ---------------------------------------------------------------------------------
    def _fade(self, start: float, end: float, ms: int, easing, then=None) -> None:
        """Animate the whole window's opacity. Time-based, so it stays smooth if frames are late."""
        if self._fade_job is not None:  # a new fade replaces one still running
            self.win.after_cancel(self._fade_job)
            self._fade_job = None
        began = time.monotonic()

        def step() -> None:
            self._fade_job = None
            if not self.win.winfo_exists():
                return
            u = (time.monotonic() - began) * 1000 / ms  # 0..1 progress (eased below)
            self.win.attributes("-alpha", start + (end - start) * easing(u))
            if u < 1:
                self._fade_job = self.win.after(8, step)
            elif then:
                then()

        step()

    # -- face ----------------------------------------------------------------------------------
    def _start_face(self) -> None:
        if self.finished:
            return
        self.anim.set_state(face_anim.SCANNING)
        self.face.start()  # opens the camera on a background thread
        self._poll_face()

    def _poll_face(self) -> None:
        # Tk is not thread-safe: the camera thread only sets `state`; the UI thread reads it here.
        if self.finished or self.closing:
            return
        state = self.face.state
        if state == "matched":
            self.on_face_result(state, self.face.best)
            # Let the checkmark play before the app is released, like Face ID does.
            self.closing = True
            self.anim.set_state(face_anim.SUCCESS)
            self.face_label.config(text="Face recognized", fg="#30d158")
            self.message.config(text=" ")
            self.win.after(int(face_anim.SUCCESS_SECONDS * 1000), lambda: self._finish(True))
        elif state in ("failed", "unavailable"):
            # Face unlock gave up; the password path stays open.
            self.on_face_result(state, self.face.best)
            self.anim.set_state(face_anim.FAILURE if state == "failed" else face_anim.UNAVAILABLE)
            self.face_label.config(text="Face not recognized. Enter the password." if state == "failed"
                                   else "Camera unavailable. Enter the password.")
        else:
            self.win.after(100, self._poll_face)  # still searching

    # -- password ------------------------------------------------------------------------------
    def _tick(self) -> None:
        """Once a second: count down, and deny when the time runs out."""
        if self.finished:
            return
        if self.closing:  # unlock already decided; just wait for the animation
            self.win.after(1000, self._tick)
            return
        if self.remaining <= 0:
            self._finish(False)
            return
        self.countdown.config(text=f"Closing in {self.remaining}s")
        self.remaining -= 1
        self.win.after(1000, self._tick)

    def _cancel(self) -> None:
        """Cancel button, Escape and Alt+F4: deny. Ignored once a face match is unlocking the app,
        so pressing Escape during the checkmark can't kill the app the user just unlocked."""
        if not self.closing:
            self._finish(False)

    def _submit(self) -> None:
        if self.closing:
            return
        password = self.entry.get()
        self.entry.delete(0, "end")
        if self.lockout() > 0:  # while locked out the password isn't even checked
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
        if self.finished:  # timeout, cancel and success can race; only the first one counts
            return
        self.finished = True
        if self.face:
            self.face.cancel()  # stops the camera thread and releases the webcam
        self.win.grab_release()
        winapi.make_click_through(self.win.winfo_id())  # the fade-out must not swallow clicks
        self.on_done(allowed)  # the app resumes (or is closed) while the overlay fades away over it
        try:
            current = float(self.win.attributes("-alpha"))
        except tk.TclError:
            return
        self._fade(current, 0.0, FADE_OUT_MS, ease_in_out, then=self.win.destroy)
