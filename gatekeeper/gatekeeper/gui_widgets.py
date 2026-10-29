"""Theme and small reusable widgets for the dashboard."""

import base64
import threading
import time
import tkinter as tk
from tkinter import ttk

FONT = "Segoe UI"
P = dict(bg="#f3f4f6", card="#ffffff", border="#e5e7eb", text="#111827", muted="#6b7280",
         accent="#2563eb", accent_dark="#1d4ed8", side="#111827", side_hover="#1f2937",
         side_active="#374151", good="#16a34a", bad="#dc2626", warn="#d97706", dev="#f59e0b")


def apply_style(root) -> None:
    root.configure(bg=P["bg"])
    s = ttk.Style(root)
    try:
        s.theme_use("clam")
    except tk.TclError:
        pass
    s.configure(".", font=(FONT, 10), background=P["bg"], foreground=P["text"])
    s.configure("TFrame", background=P["bg"])
    s.configure("Card.TFrame", background=P["card"])
    s.configure("Side.TFrame", background=P["side"])
    s.configure("TLabel", background=P["bg"], foreground=P["text"])
    s.configure("Card.TLabel", background=P["card"])
    s.configure("CardTitle.TLabel", background=P["card"], font=(FONT, 11, "bold"))
    s.configure("CardMuted.TLabel", background=P["card"], foreground=P["muted"])
    s.configure("Muted.TLabel", foreground=P["muted"])
    s.configure("H1.TLabel", font=(FONT, 18, "bold"))
    s.configure("Big.TLabel", background=P["card"], font=(FONT, 22, "bold"))
    s.configure("Warn.TLabel", background="#fffbeb", foreground="#92400e", padding=10)
    s.configure("Err.TLabel", background=P["card"], foreground=P["bad"])
    s.configure("Brand.TLabel", background=P["side"], foreground="white", font=(FONT, 14, "bold"))
    s.configure("SideMuted.TLabel", background=P["side"], foreground="#9ca3af")
    s.configure("TCheckbutton", background=P["card"])
    s.configure("Horizontal.TScale", background=P["card"], troughcolor=P["border"])
    s.configure("TButton", padding=(12, 6))
    s.configure("Accent.TButton", background=P["accent"], foreground="white", padding=(14, 6))
    s.map("Accent.TButton", background=[("disabled", "#9ca3af"), ("active", P["accent_dark"])])
    s.configure("Danger.TButton", background=P["bad"], foreground="white", padding=(12, 6))
    s.map("Danger.TButton", background=[("disabled", "#9ca3af"), ("active", "#b91c1c")])
    s.configure("Nav.TButton", background=P["side"], foreground="#d1d5db", anchor="w",
                padding=(18, 10), borderwidth=0, relief="flat")
    s.map("Nav.TButton", background=[("active", P["side_hover"])], foreground=[("active", "white")])
    s.configure("NavActive.TButton", background=P["side_active"], foreground="white", anchor="w",
                padding=(18, 10), borderwidth=0, relief="flat")
    s.map("NavActive.TButton", background=[("active", P["side_active"])])
    s.configure("Treeview", rowheight=26, background="white", fieldbackground="white", borderwidth=0)
    s.configure("Treeview.Heading", font=(FONT, 10, "bold"), padding=6)


def make_card(parent, title=None, pad=16):
    """White bordered card. Returns (outer, body): pack/grid `outer`, put content in `body`."""
    outer = tk.Frame(parent, bg=P["card"], highlightthickness=1, highlightbackground=P["border"],
                     highlightcolor=P["border"])
    body = ttk.Frame(outer, style="Card.TFrame", padding=pad)
    body.pack(fill="both", expand=True)
    if title:
        ttk.Label(body, text=title, style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
    return outer, body


def make_pill(parent, text="", color=P["good"]):
    return tk.Label(parent, text=text, bg=color, fg="white", padx=10, pady=2, font=(FONT, 9, "bold"))


def set_pill(pill, text: str, color: str) -> None:
    pill.configure(text=text, bg=color)


def center(window, width: int, height: int) -> None:
    window.update_idletasks()
    x = max(0, (window.winfo_screenwidth() - width) // 2)
    y = max(0, (window.winfo_screenheight() - height) // 3)
    window.geometry(f"{width}x{height}+{x}+{y}")


def draw_bars(canvas: tk.Canvas, days: list) -> None:
    """Grouped bars per day: unlocked (green) next to denied (red)."""
    canvas.delete("all")
    canvas.update_idletasks()
    width, height = max(canvas.winfo_width(), 300), max(canvas.winfo_height(), 150)
    top, bottom, left = 18, 26, 8
    peak = max([1] + [max(d["unlocked"], d["denied"]) for d in days])
    slot = (width - left * 2) / len(days)
    bar_w = min(26, slot / 3)
    for i, d in enumerate(days):
        x0 = left + i * slot + slot / 2
        for offset, key, color in ((-bar_w - 1, "unlocked", P["good"]), (1, "denied", P["bad"])):
            value = d[key]
            h = (height - top - bottom) * value / peak
            canvas.create_rectangle(x0 + offset, height - bottom - h, x0 + offset + bar_w, height - bottom,
                                    fill=color, outline="")
            if value:
                canvas.create_text(x0 + offset + bar_w / 2, height - bottom - h - 8, text=str(value),
                                   font=(FONT, 8), fill=P["muted"])
        canvas.create_text(x0, height - 10, text=d["date"].strftime("%a %d"), font=(FONT, 8), fill=P["muted"])
    canvas.create_line(left, height - bottom, width - left, height - bottom, fill=P["border"])


class CameraSession:
    """Runs the webcam on a background thread.

    `process(frame) -> (status_text, done)` runs on that thread (never touch Tk in it). The UI
    thread polls `frame_if_new()` / `status` / `error`, so Tk is only ever used from its own thread.
    """

    WIDTH = 480

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
        from .matcher import open_camera
        cap, failures = None, 0
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
                self.status, self.done = self.process(frame)
                h, w = frame.shape[:2]
                small = cv2.flip(cv2.resize(frame, (self.WIDTH, max(1, int(h * self.WIDTH / w)))), 1)
                ok, buf = cv2.imencode(".png", small)
                if ok:
                    self._png = base64.b64encode(buf.tobytes()).decode("ascii")
                    self._seq += 1
                if self.done:
                    break
        except Exception as exc:
            self.error = str(exc) or exc.__class__.__name__
        finally:
            if cap is not None:
                cap.release()
            self.finished = True

    def frame_if_new(self):
        if self._seq == self._seen:
            return None
        self._seen = self._seq
        return self._png

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)  # the camera must be released before anything else opens it
