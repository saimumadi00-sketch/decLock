"""Theme and small reusable widgets for the dashboard.

Colours live in the palette dict `P`. Widgets read P when they are CREATED, which is why a theme
switch rebuilds the pages (see Dashboard.apply_theme).
"""

import base64
import threading
import time
import tkinter as tk
from tkinter import ttk

FONT = "Segoe UI"
# Two palettes with the same keys; set_theme() copies one of them into P.
LIGHT = dict(bg="#f3f4f6", card="#ffffff", border="#e5e7eb", text="#111827", muted="#6b7280",
             accent="#2563eb", accent_dark="#1d4ed8", side="#111827", side_hover="#1f2937",
             side_active="#374151", good="#16a34a", bad="#dc2626", warn="#d97706", dev="#f59e0b",
             warn_bg="#fffbeb", warn_text="#92400e", bad_bg="#fef2f2", bad_text="#991b1b",
             side_text="#d1d5db", side_muted="#9ca3af", disabled="#9ca3af")
DARK = dict(bg="#0f172a", card="#1e293b", border="#334155", text="#f1f5f9", muted="#94a3b8",
            accent="#3b82f6", accent_dark="#2563eb", side="#020617", side_hover="#0f172a",
            side_active="#1e293b", good="#22c55e", bad="#f87171", warn="#fbbf24", dev="#f59e0b",
            warn_bg="#422006", warn_text="#fde68a", bad_bg="#450a0a", bad_text="#fecaca",
            side_text="#cbd5e1", side_muted="#64748b", disabled="#475569")
THEMES = {"light": LIGHT, "dark": DARK}
P = dict(LIGHT)  # the live palette; set_theme() swaps its values in place so every importer sees them


def set_theme(name: str) -> None:
    # update() in place (not P = ...): modules did `from .gui_widgets import P`, so P must stay one object.
    P.update(THEMES.get(name, LIGHT))


def apply_style(root, theme: str = None) -> None:
    """Configure every ttk style the app uses from the current palette (optionally switching first)."""
    if theme:
        set_theme(theme)
    root.configure(bg=P["bg"])
    s = ttk.Style(root)
    try:
        s.theme_use("clam")  # "clam" honours custom colours; the native Windows theme ignores most of them
    except tk.TclError:
        pass
    s.configure(".", font=(FONT, 10), background=P["bg"], foreground=P["text"])
    s.configure("TFrame", background=P["bg"])
    s.configure("Card.TFrame", background=P["card"])
    s.configure("Side.TFrame", background=P["side"])
    s.configure("TLabel", background=P["bg"], foreground=P["text"])
    s.configure("Card.TLabel", background=P["card"], foreground=P["text"])
    s.configure("CardTitle.TLabel", background=P["card"], foreground=P["text"], font=(FONT, 11, "bold"))
    s.configure("CardMuted.TLabel", background=P["card"], foreground=P["muted"])
    s.configure("Muted.TLabel", foreground=P["muted"])
    s.configure("H1.TLabel", font=(FONT, 18, "bold"))
    s.configure("Big.TLabel", background=P["card"], foreground=P["text"], font=(FONT, 22, "bold"))
    s.configure("Warn.TLabel", background=P["warn_bg"], foreground=P["warn_text"], padding=10)
    s.configure("Banner.TLabel", background=P["bad_bg"], foreground=P["bad_text"], padding=(24, 8),
                font=(FONT, 10, "bold"))
    s.configure("Err.TLabel", background=P["card"], foreground=P["bad"])
    s.configure("Brand.TLabel", background=P["side"], foreground="white", font=(FONT, 14, "bold"))
    s.configure("SideMuted.TLabel", background=P["side"], foreground=P["side_muted"])
    s.configure("TCheckbutton", background=P["card"], foreground=P["text"])
    s.map("TCheckbutton", background=[("active", P["card"])])
    s.configure("Horizontal.TScale", background=P["card"], troughcolor=P["border"])
    s.configure("TButton", padding=(12, 6))
    s.configure("Chip.TButton", padding=(10, 3))
    s.configure("ChipOn.TButton", padding=(10, 3), background=P["accent"], foreground="white")
    s.map("ChipOn.TButton", background=[("active", P["accent_dark"])])
    s.configure("Accent.TButton", background=P["accent"], foreground="white", padding=(14, 6))
    s.map("Accent.TButton", background=[("disabled", P["disabled"]), ("active", P["accent_dark"])])
    s.configure("Danger.TButton", background=P["bad"], foreground="white", padding=(12, 6))
    s.map("Danger.TButton", background=[("disabled", P["disabled"]), ("active", "#b91c1c")])
    s.configure("Nav.TButton", background=P["side"], foreground=P["side_text"], anchor="w",
                padding=(18, 10), borderwidth=0, relief="flat")
    s.map("Nav.TButton", background=[("active", P["side_hover"])], foreground=[("active", "white")])
    s.configure("NavActive.TButton", background=P["side_active"], foreground="white", anchor="w",
                padding=(18, 10), borderwidth=0, relief="flat")
    s.map("NavActive.TButton", background=[("active", P["side_active"])])
    s.configure("TEntry", fieldbackground=P["card"], foreground=P["text"])
    s.configure("TCombobox", fieldbackground=P["card"], foreground=P["text"], background=P["card"])
    s.configure("TSpinbox", fieldbackground=P["card"], foreground=P["text"])
    s.configure("Treeview", rowheight=26, background=P["card"], fieldbackground=P["card"],
                foreground=P["text"], borderwidth=0)
    s.map("Treeview", background=[("selected", P["accent"])], foreground=[("selected", "white")])
    s.configure("Treeview.Heading", font=(FONT, 10, "bold"), padding=6, background=P["border"],
                foreground=P["text"])


def make_card(parent, title=None, pad=16):
    """Bordered card. Returns (outer, body): pack/grid `outer`, put content in `body`."""
    outer = tk.Frame(parent, bg=P["card"], highlightthickness=1, highlightbackground=P["border"],
                     highlightcolor=P["border"])
    body = ttk.Frame(outer, style="Card.TFrame", padding=pad)
    body.pack(fill="both", expand=True)
    if title:
        ttk.Label(body, text=title, style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
    return outer, body


def make_pill(parent, text="", color=None):
    """Rounded-looking status badge (e.g. PROTECTION ACTIVE); recolour it with set_pill()."""
    return tk.Label(parent, text=text, bg=color or P["good"], fg="white", padx=10, pady=2, font=(FONT, 9, "bold"))


def set_pill(pill, text: str, color: str) -> None:
    pill.configure(text=text, bg=color)


def make_dot(parent, color=None):
    """Small status dot for card headers; recolor it with dot.configure(fg=...)."""
    return tk.Label(parent, text="●", bg=P["card"], fg=color or P["muted"], font=(FONT, 11))


def password_entry(parent, variable, width=34):
    """Password Entry with a Show checkbox. Returns (frame, entry); pack/grid the frame."""
    frame = ttk.Frame(parent, style="Card.TFrame")
    entry = ttk.Entry(frame, textvariable=variable, show="*", width=width)
    entry.pack(side="left", fill="x", expand=True)
    shown = tk.BooleanVar(value=False)  # "Show" ticked: display the text instead of *****
    ttk.Checkbutton(frame, text="Show", variable=shown,
                    command=lambda: entry.configure(show="" if shown.get() else "*")).pack(side="left", padx=(6, 0))
    return frame, entry


def set_empty(tree, is_empty: bool) -> None:
    """Show/hide the 'nothing here yet' hint that make_tree() attached to `tree`."""
    hint = getattr(tree, "empty_hint", None)
    if hint is None:
        return
    if is_empty:
        hint.place(relx=0.5, rely=0.45, anchor="center")
        hint.lift()
    else:
        hint.place_forget()


def center(window, width: int, height: int) -> None:
    """Size a window and place it centred horizontally, a third of the way down the screen."""
    window.update_idletasks()
    x = max(0, (window.winfo_screenwidth() - width) // 2)
    y = max(0, (window.winfo_screenheight() - height) // 3)
    window.geometry(f"{width}x{height}+{x}+{y}")


# (key in the activity_by_day dicts, palette colour, legend text)
BAR_SERIES = (("unlocked", "good", "Unlocked"), ("denied", "bad", "Denied"))


def draw_bars(canvas: tk.Canvas, days: list, series=BAR_SERIES) -> None:
    """Grouped bars per day. `series` = [(key, palette color name, legend text)]."""
    canvas.delete("all")
    canvas.configure(bg=P["card"])
    canvas.update_idletasks()  # make winfo_width() return the real, laid-out size
    width, height = max(canvas.winfo_width(), 300), max(canvas.winfo_height(), 150)
    top, bottom, left = 18, 26, 8  # margins: value labels above, day labels below
    peak = max([1] + [d[key] for d in days for key, _c, _t in series])  # tallest bar; [1] avoids /0
    slot = (width - left * 2) / len(days)  # horizontal space per day
    bar_w = min(26, slot / (len(series) + 1))
    canvas.geometry_info = (left, slot, len(days))  # lets the page map a click to a day
    for i, d in enumerate(days):
        x0 = left + i * slot + slot / 2  # centre of this day's slot
        for n, (key, color, _text) in enumerate(series):
            offset = (n - len(series) / 2) * (bar_w + 1)  # side by side, centred on x0
            value = d[key]
            h = (height - top - bottom) * value / peak
            canvas.create_rectangle(x0 + offset, height - bottom - h, x0 + offset + bar_w, height - bottom,
                                    fill=P[color], outline="")
            if value:
                canvas.create_text(x0 + offset + bar_w / 2, height - bottom - h - 8, text=str(value),
                                   font=(FONT, 8), fill=P["muted"])
        canvas.create_text(x0, height - 10, text=d["date"].strftime("%a %d"), font=(FONT, 8), fill=P["muted"])
    canvas.create_line(left, height - bottom, width - left, height - bottom, fill=P["border"])


def day_at(canvas: tk.Canvas, x: float):
    """Index of the day column under canvas x, or None."""
    info = getattr(canvas, "geometry_info", None)
    if not info:
        return None
    left, slot, count = info
    index = int((x - left) // slot)
    return index if 0 <= index < count else None


def draw_hbars(canvas: tk.Canvas, rows: list, empty: str = "No attempts yet") -> None:
    """Horizontal bars for [(label, value)], largest first."""
    canvas.delete("all")
    canvas.configure(bg=P["card"])
    canvas.geometry_info = None  # not clickable in this mode (see day_at)
    canvas.update_idletasks()
    width, height = max(canvas.winfo_width(), 300), max(canvas.winfo_height(), 150)
    if not rows:
        canvas.create_text(width / 2, height / 2, text=empty, font=(FONT, 10), fill=P["muted"])
        return
    peak = max(v for _l, v in rows)
    label_w, row_h = 130, min(26, (height - 8) / len(rows))  # left column for names; rows fit the height
    for i, (label, value) in enumerate(rows):
        y = 6 + i * row_h
        canvas.create_text(8, y + row_h / 2, text=label, anchor="w", font=(FONT, 9), fill=P["text"])
        length = max(2, (width - label_w - 50) * value / peak)
        canvas.create_rectangle(label_w, y + 4, label_w + length, y + row_h - 4, fill=P["warn"], outline="")
        canvas.create_text(label_w + length + 6, y + row_h / 2, text=str(value), anchor="w",
                           font=(FONT, 9), fill=P["muted"])


class CameraSession:
    """Runs the webcam on a background thread.

    `process(frame) -> (status_text, done)` runs on that thread (never touch Tk in it). The UI
    thread polls `frame_if_new()` / `status` / `error`, so Tk is only ever used from its own thread.
    """

    WIDTH = 480  # preview width in pixels

    def __init__(self, process, index: int = 0):
        self.process, self.index = process, index
        self.status, self.done, self.error, self.finished = "Starting camera...", False, None, False
        self._png, self._seq, self._seen = None, 0, 0
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="camera-ui", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        import cv2
        from .faces import open_camera
        cap, failures = None, 0  # failures = consecutive frames the camera failed to deliver
        try:
            cap = open_camera(self.index)
            while not self._stop.is_set():
                ok, frame = cap.read()
                if not ok:
                    failures += 1
                    if failures > 100:
                        raise RuntimeError("The camera stopped delivering frames.")
                    time.sleep(0.02)
                    continue
                failures = 0
                self.status, self.done = self.process(frame)  # enrol / score this frame
                h, w = frame.shape[:2]
                # Shrink for the preview and mirror it, so moving left moves left on screen.
                small = cv2.flip(cv2.resize(frame, (self.WIDTH, max(1, int(h * self.WIDTH / w)))), 1)
                ok, buf = cv2.imencode(".png", small)
                if ok:
                    # Base64 PNG is what tk.PhotoImage(data=...) accepts; the Tk thread builds the image.
                    self._png = base64.b64encode(buf.tobytes()).decode("ascii")
                    self._seq += 1  # frame counter, so the UI only redraws on a new frame
                if self.done:
                    break
        except Exception as exc:
            self.error = str(exc) or exc.__class__.__name__
        finally:
            if cap is not None:
                cap.release()
            self.finished = True

    def frame_if_new(self):
        """The newest preview frame (base64 PNG) if it wasn't returned before, else None."""
        if self._seq == self._seen:
            return None
        self._seen = self._seq
        return self._png

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)  # the camera must be released before anything else opens it
