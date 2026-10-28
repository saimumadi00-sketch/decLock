"""Live face matching for the unlock prompt.

Fail-safe by design: any problem (no enrolment, no camera, bad model, timeout) just
means "no face unlock"; the password path is never blocked by this module.

No liveness detection: a good photo or video of the owner may pass. Treat face unlock
as a convenience, not as stronger than the password.
"""

import logging
import threading
import time

from .enroll import MIN_FACE_PX
from .faces import similarity

log = logging.getLogger("gatekeeper.matcher")

DEFAULT_THRESHOLD = 0.45   # SFace's published 1:1 threshold is 0.363; stricter by default
THRESHOLD_RANGE = (0.2, 0.9)
DEFAULT_TIMEOUT = 8.0


def get_threshold(db) -> float:
    return float(db.get_setting("face_threshold", DEFAULT_THRESHOLD))


def get_timeout(db) -> float:
    return float(db.get_setting("face_timeout", DEFAULT_TIMEOUT))


def face_unlock_enabled(db) -> bool:
    return db.get_setting("face_unlock", "1") == "1"


class FaceMatcher:
    def __init__(self, engine, enrolled: list, threshold: float):
        self.engine, self.enrolled, self.threshold = engine, enrolled, threshold

    def score(self, frame):
        """Best similarity to any enrolled sample, or None unless exactly one usable face."""
        faces = self.engine.detect(frame)
        if len(faces) != 1 or min(faces[0].box[2:4]) < MIN_FACE_PX:
            return None  # several faces in view (shoulder surfing) fails closed
        embedding = self.engine.embed(frame, faces[0])
        return max(similarity(embedding, e) for e in self.enrolled)


def open_camera(index: int = 0):
    import cv2
    cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        cap.release()
        raise RuntimeError("camera unavailable")
    return cap


class LiveMatch:
    """Succeeds only when the score stays above threshold for `hold` seconds over
    at least `min_hits` frames, so one lucky frame is not enough."""

    def __init__(self, matcher: FaceMatcher, camera_factory=open_camera, timeout: float = DEFAULT_TIMEOUT,
                 hold: float = 0.5, min_hits: int = 3, clock=time.monotonic):
        self.matcher, self.camera_factory = matcher, camera_factory
        self.timeout, self.hold, self.min_hits, self.clock = timeout, hold, min_hits, clock
        self.best = None

    def run(self, cancel: threading.Event) -> bool:
        camera = self.camera_factory()
        try:
            deadline = self.clock() + self.timeout
            streak_start, hits = None, 0
            while not cancel.is_set() and self.clock() < deadline:
                ok, frame = camera.read()
                if not ok:
                    continue
                score = self.matcher.score(frame)
                if score is not None and (self.best is None or score > self.best):
                    self.best = score
                if score is not None and score >= self.matcher.threshold:
                    streak_start = streak_start if streak_start is not None else self.clock()
                    hits += 1
                    if hits >= self.min_hits and self.clock() - streak_start >= self.hold:
                        return True
                else:
                    streak_start, hits = None, 0
            return False
        finally:
            camera.release()


class FaceUnlock:
    """Runs a LiveMatch on a background thread. `state`: idle/searching/matched/failed/unavailable."""

    def __init__(self, live: LiveMatch):
        self.live, self.state = live, "idle"
        self._cancel = threading.Event()
        self._thread = None

    @property
    def best(self):
        return self.live.best

    def start(self) -> None:
        self.state = "searching"
        self._thread = threading.Thread(target=self._run, name="face", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            matched = self.live.run(self._cancel)
            self.state = "matched" if matched else "failed"
        except Exception as exc:
            log.warning("face unlock unavailable: %s", exc)
            self.state = "unavailable"

    def cancel(self) -> None:
        self._cancel.set()
        if self._thread:
            self._thread.join(timeout=3)  # make sure the camera is released


def build_face_unlock(ctx, engine_factory):
    """Return a FaceUnlock for this prompt, or None if face unlock isn't usable."""
    from .face_store import FaceStore
    if not face_unlock_enabled(ctx.db):
        return None
    try:
        enrolled = FaceStore(ctx.db, ctx.keys).embeddings()
        if not enrolled:
            return None
        matcher = FaceMatcher(engine_factory(), enrolled, get_threshold(ctx.db))
    except Exception as exc:
        log.warning("face unlock disabled: %s", exc)
        return None
    return FaceUnlock(LiveMatch(matcher, timeout=get_timeout(ctx.db)))


def run_test_window(matcher: FaceMatcher, camera_index: int = 0, seconds: float = 60) -> None:
    """Preview with live scores so the threshold can be tuned. Changes nothing."""
    import cv2
    camera = open_camera(camera_index)
    end = time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            ok, frame = camera.read()
            if not ok:
                continue
            score = matcher.score(frame)
            if score is None:
                text, color = "Need exactly one face in view", (0, 165, 255)
            else:
                hit = score >= matcher.threshold
                text = f"score {score:.2f} / threshold {matcher.threshold:.2f}  {'MATCH' if hit else 'no match'}"
                color = (0, 200, 0) if hit else (0, 0, 255)
            cv2.putText(frame, text + "  (Esc to quit)", (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.65, color, 2)
            cv2.imshow("Gatekeeper face test", frame)
            if cv2.waitKey(1) & 0xFF == 27:
                break
    finally:
        camera.release()
        cv2.destroyAllWindows()
