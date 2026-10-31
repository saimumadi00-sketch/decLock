"""System tray icon (Open / Pause or Resume / Lock / Quit). Optional: needs `pystray` and
`Pillow`; without them the dashboard simply behaves as before and the X button minimizes.

pystray calls back on its own thread, so menu clicks only put a command name on a queue. The
dashboard drains that queue from the Tk thread.
"""

import logging
import queue

log = logging.getLogger("gatekeeper.tray")


def available() -> bool:
    """Are the optional tray dependencies installed?"""
    try:
        import PIL  # noqa: F401
        import pystray  # noqa: F401
    except Exception:
        return False
    return True


def _icon_image():
    """A 64x64 padlock drawn with Pillow (no image file to ship)."""
    from PIL import Image, ImageDraw
    image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((8, 28, 56, 58), radius=7, fill=(37, 99, 235, 255))  # lock body
    draw.arc((18, 6, 46, 42), 180, 360, fill=(37, 99, 235, 255), width=7)       # shackle
    draw.ellipse((28, 37, 36, 45), fill=(255, 255, 255, 255))                    # keyhole
    return image


class Tray:
    def __init__(self, is_running):
        self.commands = queue.SimpleQueue()
        self._is_running = is_running  # callable; the menu label is computed each time it opens
        self._icon = None

    def start(self) -> bool:
        if not available():
            return False
        import pystray
        put = self.commands.put
        menu = pystray.Menu(
            pystray.MenuItem("Open Gatekeeper", lambda *_: put("open"), default=True),
            pystray.MenuItem(lambda _item: "Pause protection" if self._is_running() else "Resume protection",
                             lambda *_: put("toggle")),
            pystray.MenuItem("Lock dashboard", lambda *_: put("lock")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit Gatekeeper...", lambda *_: put("quit")))
        try:
            self._icon = pystray.Icon("gatekeeper", _icon_image(), "Gatekeeper", menu)
            self._icon.run_detached()  # runs the icon on its own thread; Tk keeps the main thread
        except Exception:
            log.exception("could not start the tray icon")
            self._icon = None
            return False
        return True

    def stop(self) -> None:
        if self._icon is not None:
            try:
                self._icon.stop()
            except Exception:
                log.exception("could not stop the tray icon")
            self._icon = None
