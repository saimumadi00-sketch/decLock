"""Live face matching for the unlock prompt.

Fail-safe by design: any problem (no enrolment, no camera, bad model, timeout, failed challenge)
just means "no face unlock"; the password path is never blocked by this module.

Every attempt needs three things at once (see liveness.py):
  identity   ArcFace similarity to the enrolled samples
  real face  MiniFASNet on every frame (photos and screens fail)
  challenge  random head movements, the same face tracked throughout
"""

import logging
import threading
import time

from .enroll import MIN_FACE_PX
from .faces import MODEL_ID, open_camera, similarity
from .liveness import Challenge, Observation, head_pose, random_challenge

log = logging.getLogger("gatekeeper.matcher")

DEFAULT_THRESHOLD = 0.40   # ArcFace cosine similarity: strangers score around 0-0.25, the same person 0.4+
THRESHOLD_RANGE = (0.25, 0.80)
WEAK_THRESHOLD = 0.30      # below this, other people start to match
DEFAULT_TIMEOUT = 20.0     # seconds for the whole attempt (the challenge takes a few)
TIMEOUT_RANGE = (8, 45)
MAX_BAD_FRAMES = 100       # consecutive failed camera reads before giving up (~2 s)


def get_threshold(db) -> float:
    return float(db.get_setting("face_threshold", DEFAULT_THRESHOLD))


def get_timeout(db) -> float:
    return float(db.get_setting("face_timeout", DEFAULT_TIMEOUT))


def face_unlock_enabled(db) -> bool:
    return db.get_setting("face_unlock", "1") == "1"


def enrolment_current(db) -> bool:
    """Were the stored samples made by the current models? Older ones can't be compared."""
    return db.get_setting("face_model") == MODEL_ID


class FaceMatcher:
    def __init__(self, engine, enrolled: list, threshold: float):
        self.engine, self.enrolled, self.threshold = engine, enrolled, threshold

    def observe(self, frame) -> Observation:
        """Everything the challenge needs to know about one frame."""
        faces = self.engine.detect(frame)
        if len(faces) != 1:
            return Observation(faces=len(faces))  # none, or several (shoulder surfing) fails closed
        face = faces[0]
        if min(face.box[2:4]) < MIN_FACE_PX:
            return Observation(faces=0)  # too far away to judge: treat like no face
        yaw, pitch = head_pose(face.kps)
        embedding = self.engine.embed(frame, face)
        return Observation(faces=1, box=face.box, yaw=yaw, pitch=pitch,
                           identity=max(similarity(embedding, e) for e in self.enrolled),
                           live=self.engine.liveness(frame, face))

    def score(self, frame):
        """Best similarity to any enrolled sample, or None unless exactly one usable face."""
        obs = self.observe(frame)
        return obs.identity if obs.faces == 1 else None


class LiveMatch:
    """Runs one Challenge against the camera until it is matched, failed, cancelled or timed out."""

    def __init__(self, matcher: FaceMatcher, camera_factory=open_camera, timeout: float = DEFAULT_TIMEOUT,
                 challenge: Challenge = None, clock=time.monotonic):
        self.matcher, self.camera_factory = matcher, camera_factory
        self.timeout, self.clock = timeout, clock
        self.challenge = challenge or Challenge(random_challenge(), matcher.threshold, clock=clock)

    @property
    def best(self):
        return self.challenge.best  # best identity score seen, for the audit log

    @property
    def instruction(self) -> str:
        return self.challenge.instruction

    @property
    def reason(self) -> str:
        return self.challenge.reason or ("timed out" if self.challenge.state != "matched" else "")

    def run(self, cancel: threading.Event) -> bool:
        camera = self.camera_factory()
        try:
            deadline = self.clock() + self.timeout
            bad_frames = 0
            while not cancel.is_set() and self.clock() < deadline:
                ok, frame = camera.read()
                if not ok:
                    # Don't spin the CPU on a camera that returns nothing; give up if it never recovers.
                    bad_frames += 1
                    if bad_frames > MAX_BAD_FRAMES:
                        raise RuntimeError("the camera stopped delivering frames")
                    time.sleep(0.02)
                    continue
                bad_frames = 0
                state = self.challenge.feed(self.matcher.observe(frame))
                if state in ("matched", "failed"):
                    return state == "matched"
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

    @property
    def instruction(self) -> str:
        """What the person should do right now (the prompt shows it)."""
        return self.live.instruction

    @property
    def reason(self) -> str:
        """Why the attempt failed, for the audit log."""
        return self.live.reason

    def start(self) -> None:
        self.state = "searching"
        self._thread = threading.Thread(target=self._run, name="face", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        # Only plain attribute writes here; the Tk thread polls `state` (see ui.UnlockPrompt).
        try:
            matched = self.live.run(self._cancel)
            self.state = "matched" if matched else "failed"
        except Exception as exc:  # no camera, model error, ...: fall back to the password
            log.warning("face unlock unavailable: %s", exc)
            self.state = "unavailable"

    def cancel(self) -> None:
        self._cancel.set()
        if self._thread:
            self._thread.join(timeout=3)  # make sure the camera is released


def build_face_unlock(ctx, engine_factory):
    """Return a FaceUnlock for this prompt, or None if face unlock isn't usable."""
    from .face_store import FaceStore
    if not face_unlock_enabled(ctx.db) or not enrolment_current(ctx.db):
        return None  # off, or enrolled with older models: the user must re-enrol
    try:
        enrolled = FaceStore(ctx.db, ctx.keys).embeddings()
        if not enrolled:
            return None
        matcher = FaceMatcher(engine_factory(), enrolled, get_threshold(ctx.db))
    except Exception as exc:  # e.g. undecryptable samples or missing models
        log.warning("face unlock disabled: %s", exc)
        return None
    return FaceUnlock(LiveMatch(matcher, timeout=get_timeout(ctx.db)))


def run_test_window(matcher: FaceMatcher, camera_index: int = 0, seconds: float = 60) -> None:
    """CLI preview with live scores so the threshold can be tuned. Changes nothing."""
    import cv2
    camera = open_camera(camera_index)
    end = time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            ok, frame = camera.read()
            if not ok:
                continue
            obs = matcher.observe(frame)
            if obs.faces != 1:
                text, color = "Need exactly one face in view", (0, 165, 255)  # BGR orange
            else:
                hit = obs.identity >= matcher.threshold
                text = (f"match {obs.identity:.2f}/{matcher.threshold:.2f} {'OK' if hit else 'no'}  "
                        f"real {obs.live:.2f}  yaw {obs.yaw:+.2f} pitch {obs.pitch:.2f}")
                color = (0, 200, 0) if hit else (0, 0, 255)
            cv2.putText(frame, text + "  (Esc)", (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)
            cv2.imshow("Gatekeeper face test", frame)
            if cv2.waitKey(1) & 0xFF == 27:  # Esc
                break
    finally:
        camera.release()
        cv2.destroyAllWindows()
