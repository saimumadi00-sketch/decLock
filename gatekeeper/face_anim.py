"""Face ID style animation for the desktop, drawn on a Tk canvas.

States, modelled on Apple's Face ID:
  idle / unavailable  the corner brackets and face glyph, resting.
  scanning            the brackets breathe while a light sweeps across the glyph and a mesh of dots
                      lights up behind it.
  success             the glyph fades, the four corner brackets round off and close into a circle that
                      turns green, then a checkmark draws itself inside (with a small pop).
  failure             the glyph shakes side to side ("no") with a brief red tint, then settles.

Everything is a pure function of (state, seconds since the state began): `draw_at(seconds)` can be
called directly, which is how the tests drive it without waiting for real time.
"""

import math
import time
import tkinter as tk

IDLE, SCANNING, SUCCESS, FAILURE, UNAVAILABLE = "idle", "scanning", "success", "failure", "unavailable"

# Colours: default backdrop, the white strokes, the scan highlight, success green, failure red.
BG = "#0b1220"
WHITE = "#f8fafc"
SCAN = "#8ec5ff"
GREEN = "#30d158"
RED = "#ff453a"

SUCCESS_SECONDS = 1.0     # morph + checkmark; the unlock prompt waits this long before unlocking
FAILURE_SECONDS = 0.8
FRAME_MS = 16             # ~60 fps

# Face glyph in unit coordinates (-1..1): two eyes, a hooked nose, a smile.
_GLYPH = (
    ((-0.40, -0.34), (-0.40, -0.10)),
    ((0.40, -0.34), (0.40, -0.10)),
    ((0.04, -0.26), (0.04, 0.12), (-0.08, 0.17)),
    tuple((0.42 * math.cos(math.radians(a)), 0.28 + 0.26 * math.sin(math.radians(a)))
          for a in range(20, 161, 10)),
)
_CHECK = ((-0.30, 0.02), (-0.08, 0.26), (0.32, -0.24))  # the checkmark polyline, same unit coordinates


def _clamp(x: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, x))


def ease_in_out(x: float) -> float:
    """Smoothstep: slow start, slow end (input is clamped to 0..1)."""
    x = _clamp(x)
    return x * x * (3 - 2 * x)


def ease_out(x: float) -> float:
    """Cubic ease-out: fast start, gentle stop (input is clamped to 0..1)."""
    x = _clamp(x)
    return 1 - (1 - x) ** 3


def mix(a: str, b: str, t: float) -> str:
    """Blend two #rrggbb colors; t=0 gives a, t=1 gives b."""
    t = _clamp(t)
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(ca, cb))


def densify(points, step: float = 0.05) -> list:
    """Insert points along a polyline so a moving highlight can color it in small pieces."""
    out = [points[0]]
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        pieces = max(1, int(math.hypot(x1 - x0, y1 - y0) / step))
        out += [(x0 + (x1 - x0) * i / pieces, y0 + (y1 - y0) * i / pieces) for i in range(1, pieces + 1)]
    return out


def rounded_square(h: float, rho: float, n_arc: int = 14, n_line: int = 12) -> list:
    """Closed outline of a square (half-size h) with corner radius rho (rho == h is a circle).

    Starts at the middle of the top-left corner and runs clockwise, so the four corner midpoints sit
    at quarter-perimeter intervals. That is what lets the brackets close up into a circle.
    """
    rho = _clamp(rho, 0.001, h)
    k = h - rho
    out = []

    def arc(cx, cy, a0, a1):
        for i in range(n_arc + 1):
            a = math.radians(a0 + (a1 - a0) * i / n_arc)
            out.append((cx + rho * math.cos(a), cy + rho * math.sin(a)))

    def line(x0, y0, x1, y1):
        for i in range(1, n_line):
            out.append((x0 + (x1 - x0) * i / n_line, y0 + (y1 - y0) * i / n_line))

    arc(-k, -k, 225, 270)
    line(-k, -h, k, -h)
    arc(k, -k, 270, 360)
    line(h, -k, h, k)
    arc(k, k, 0, 90)
    line(k, h, -k, h)
    arc(-k, k, 90, 180)
    line(-h, k, -h, -k)
    arc(-k, -k, 180, 225)
    # the two half-arcs at the seam duplicate their shared point; drop one copy
    return [p for i, p in enumerate(out) if i == 0 or p != out[i - 1]]


def brackets(h: float, rho: float, coverage: float) -> list:
    """Four polylines, one centred on each corner, each covering `coverage` of a quarter perimeter."""
    pts = rounded_square(h, rho)
    cum = [0.0]
    for (x0, y0), (x1, y1) in zip(pts, pts[1:] + pts[:1]):
        cum.append(cum[-1] + math.hypot(x1 - x0, y1 - y0))
    total = cum[-1]
    quarter, half = total / 4, coverage * total / 8
    ext_pts, ext_cum = pts + pts + pts[:1], cum[:-1] + [c + total for c in cum]

    def at(s):
        lo, hi = 0, len(ext_cum) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            lo, hi = (mid, hi) if ext_cum[mid] <= s else (lo, mid)
        span = ext_cum[hi] - ext_cum[lo] or 1.0
        f = (s - ext_cum[lo]) / span
        (x0, y0), (x1, y1) = ext_pts[lo], ext_pts[hi]
        return x0 + (x1 - x0) * f, y0 + (y1 - y0) * f

    result = []
    for corner in range(4):
        centre = corner * quarter + total          # shifted by one lap so the window never wraps below 0
        start, end = centre - half, centre + half
        line = [at(start)] + [p for p, c in zip(ext_pts, ext_cum) if start < c < end] + [at(end)]
        result.append(line)
    return result


def partial(points, fraction: float) -> list:
    """The first `fraction` (by length) of a polyline."""
    lengths = [math.hypot(x1 - x0, y1 - y0) for (x0, y0), (x1, y1) in zip(points, points[1:])]
    goal, out = sum(lengths) * _clamp(fraction), [points[0]]
    for (x0, y0), (x1, y1), length in zip(points, points[1:], lengths):
        if goal >= length:
            out.append((x1, y1))
            goal -= length
        else:
            f = goal / length if length else 0
            out.append((x0 + (x1 - x0) * f, y0 + (y1 - y0) * f))
            break
    return out


class FaceIDAnimation(tk.Canvas):
    """The animated icon. Call set_state(SCANNING / SUCCESS / ...); it schedules its own frames."""

    def __init__(self, parent, size: int = 160, bg: str = BG, **kw):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0, **kw)
        self.size, self.backdrop = size, bg
        self.state, self._t0, self._job = IDLE, time.monotonic(), None
        self.opacity, self._fade = 1.0, None   # opacity < 1 blends everything toward the backdrop
        # Dot grid inside an ellipse (the "depth map" that lights up while scanning).
        self._mesh = [(x / 6, y / 6) for x in range(-4, 5) for y in range(-5, 6)
                      if (x / 6 / 0.62) ** 2 + (y / 6 / 0.82) ** 2 <= 1]
        self._glyph = [densify(line) for line in _GLYPH]  # many short segments so each can glow separately
        self.bind("<Destroy>", self._stop, add="+")  # no timers left firing on a dead widget
        self.draw_at(0)

    # -- control -------------------------------------------------------------------------------
    def set_state(self, state: str) -> None:
        """Switch state and restart its animation clock (no-op if already animating that state)."""
        if state == self.state and self._job is not None:
            return
        self.state, self._t0 = state, time.monotonic()
        self._stop()
        self._frame()

    def fade_in(self, ms: int = 350) -> None:
        """Fade the whole animation in from the backdrop colour."""
        self.opacity, self._fade = 0.0, (time.monotonic(), ms / 1000)
        if self._job is None:
            self._frame()

    def animating(self, t: float) -> bool:
        """Does this state still need frames `t` seconds in? (Idle and finished states are static.)"""
        return (self._fade is not None or self.state == SCANNING or (self.state == SUCCESS and t < SUCCESS_SECONDS + 0.3)
                or (self.state == FAILURE and t < FAILURE_SECONDS))

    def _stop(self, _event=None) -> None:
        if self._job is not None:
            try:
                self.after_cancel(self._job)
            except tk.TclError:
                pass
            self._job = None

    def _frame(self) -> None:
        """Draw one frame and schedule the next while something is moving (~60 fps)."""
        self._job = None
        if not self.winfo_exists():
            return
        now = time.monotonic()
        if self._fade is not None:
            started, length = self._fade
            progress = (now - started) / length
            self.opacity = ease_out(progress)
            if progress >= 1:
                self.opacity, self._fade = 1.0, None
        t = now - self._t0
        self.draw_at(t)
        if self.animating(t):
            self._job = self.after(FRAME_MS, self._frame)

    # -- drawing -------------------------------------------------------------------------------
    def draw_at(self, t: float) -> None:
        """Render the frame for `t` seconds after the current state began."""
        self.delete("all")
        c, h = self.size / 2, self.size * 0.36  # centre, and half-size of the bracket square
        state = self.state
        dim = mix(self.backdrop, WHITE, 0.5)
        dx, scale, tint = 0.0, 1.0, 0.0
        # Defaults (idle): rho = corner radius, coverage = how much of each corner the brackets draw.
        glyph_alpha, mesh_alpha, rho, coverage, color = 1.0, 0.0, 0.26 * h, 0.44, WHITE

        if state == SCANNING:  # brackets breathe, mesh fades in
            scale = 1 + 0.03 * math.sin(2 * math.pi * t / 1.3)
            mesh_alpha = ease_out(t / 0.3)
        elif state == FAILURE:  # damped side-to-side shake with a fading red tint
            mesh_alpha = 1 - _clamp(t / 0.25)
            u = _clamp(t / FAILURE_SECONDS)
            dx = self.size * 0.07 * math.sin(2 * math.pi * 3.5 * u) * (1 - u) ** 1.5
            tint = (1 - u) ** 2
        elif state == UNAVAILABLE:
            glyph_alpha = 0.5
        elif state == SUCCESS:  # corners round off into a green circle, then a small "pop"
            m = ease_in_out(t / 0.5)
            glyph_alpha = 1 - _clamp(t / 0.2)
            mesh_alpha = 1 - _clamp(t / 0.25)
            rho, coverage = (0.26 + 0.74 * m) * h, 0.44 + 0.56 * m
            color = mix(WHITE, GREEN, m)
            scale = 1 + 0.07 * math.sin(math.pi * _clamp((t - 0.5) / 0.35))

        fade = (lambda col: col) if self.opacity >= 1 else (lambda col: mix(self.backdrop, col, self.opacity))
        outline = fade(mix(color, RED, tint * 0.9))
        width = max(3, round(self.size / 36)) + (1 if state == SUCCESS else 0)
        for line in brackets(h * scale, rho * scale, coverage):
            self.create_line([v for x, y in line for v in (c + dx + x, c + y)], fill=outline, width=width,
                             capstyle="round", joinstyle="round")

        # x position of the light sweeping across (every 1.6 s); 3.0 = off-canvas, no highlight.
        sweep = -1.4 + 2.8 * ((t % 1.6) / 1.6) if state == SCANNING else 3.0
        unit, munit = h * 0.75 * scale, h * 0.99 * scale
        if mesh_alpha > 0:
            for x, y in self._mesh:
                glow = math.exp(-((x * 1.6 - sweep) / 0.45) ** 2)  # Gaussian: bright near the sweep line
                r = 1.1 + 1.0 * glow
                shade = fade(mix(self.backdrop, SCAN, mesh_alpha * (0.10 + 0.75 * glow)))
                self.create_oval(c + x * munit - r, c + y * munit - r,
                                 c + x * munit + r, c + y * munit + r, fill=shade, outline="")
        if glyph_alpha > 0:
            base = mix(self.backdrop, mix(dim, RED, tint * 0.9) if state != UNAVAILABLE else dim, glyph_alpha)
            bright = mix(self.backdrop, WHITE, glyph_alpha)
            for line in self._glyph:
                for (x0, y0), (x1, y1) in zip(line, line[1:]):
                    glow = math.exp(-(((x0 + x1) / 2 * 1.6 - sweep) / 0.4) ** 2)
                    if state == IDLE or state == FAILURE:
                        shade = mix(base, bright, 0.35)
                    else:
                        shade = mix(base, mix(bright, SCAN, 0.25), glow)
                    self.create_line(c + dx + x0 * unit, c + y0 * unit, c + dx + x1 * unit, c + y1 * unit,
                                     fill=fade(shade), width=width, capstyle="round")
        if state == SUCCESS:
            p = ease_out((t - 0.42) / 0.4)  # the checkmark draws itself after the circle has closed
            if p > 0:
                tick = partial([(c + x * h * 1.1, c + y * h * 1.1) for x, y in _CHECK], p)
                if len(tick) > 1:
                    self.create_line([v for pt in tick for v in pt], fill=fade(GREEN), width=width + 2,
                                     capstyle="round", joinstyle="round")
