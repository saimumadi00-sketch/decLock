import threading
import time
import tkinter as tk

import numpy as np
import pytest

from gatekeeper.app import open_context
from gatekeeper.face_store import FaceStore
from gatekeeper.faces import Face
from gatekeeper.liveness import Challenge
from gatekeeper.matcher import FaceMatcher, FaceUnlock, LiveMatch, build_face_unlock
from gatekeeper.ui import UnlockPrompt

OWNER = np.ones(512, np.float32)
STRANGER = np.concatenate([np.ones(256), -np.ones(256)]).astype(np.float32)  # cosine 0 with OWNER
FRAME = np.zeros((480, 640, 3), np.uint8)
BOX = (50, 50, 160, 160)


def kps_for(yaw: float = 0.0, pitch: float = 0.5, dx: float = 0.0):
    """Landmarks for a head pose (see liveness.head_pose): eyes 60 px apart, mouth 60 px below them."""
    eyes_y, mouth_y = 100.0, 160.0
    return np.array([[100 + dx, eyes_y], [160 + dx, eyes_y],
                     [130 + dx + yaw * 60, eyes_y + pitch * (mouth_y - eyes_y)],
                     [110 + dx, mouth_y], [150 + dx, mouth_y]], np.float32)


POSES = {"left": (0.35, 0.5), "right": (-0.35, 0.5), "up": (0.0, 0.3), "down": (0.0, 0.7)}


class Person:
    """A scripted face in front of the camera. By default it follows the challenge's instructions."""

    def __init__(self, embedding=OWNER, live=0.95, faces=1, behaviour="follow"):
        self.embedding, self.live, self.faces, self.behaviour = embedding, live, faces, behaviour
        self.challenge = None  # set by make()
        self.frames = 0

    def pose(self):
        c = self.challenge
        if self.behaviour == "frozen":                   # a photo: never moves
            return 0.0, 0.5
        if self.behaviour == "sweep":                    # a video turning left, whatever was asked
            return POSES["left"] if c.state == "step" else (0.0, 0.5)
        if c.state == "step" and not c._returning:       # follow the current instruction
            return POSES[c.steps[c.step]]
        return 0.0, 0.5                                  # otherwise look straight ahead

    def detect(self, frame):
        self.frames += 1
        yaw, pitch = self.pose()
        box = BOX
        if self.behaviour == "swap" and self.challenge.state == "step":
            box = (400, 300, 160, 160)                   # a different face appears elsewhere
        return [Face(box, 0.99, kps_for(yaw, pitch))] * self.faces

    def embed(self, frame, face):
        return self.embedding

    def liveness(self, frame, face):
        return self.live


class FakeCamera:
    def __init__(self, clock, step=0.1):
        self.clock, self.step, self.released = clock, step, False

    def read(self):
        self.clock.t += self.step
        return True, FRAME

    def release(self):
        self.released = True


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def make(person=None, steps=("left", "up"), timeout=20):
    person = person or Person()
    clock = Clock()
    cam = FakeCamera(clock)
    matcher = FaceMatcher(person, [OWNER], 0.40)
    challenge = Challenge(list(steps), 0.40, clock=clock)
    person.challenge = challenge
    return LiveMatch(matcher, lambda: cam, timeout=timeout, challenge=challenge, clock=clock), cam


@pytest.mark.parametrize("steps", [("left", "up"), ("right", "down"), ("down", "left"), ("up", "right")])
def test_owner_who_follows_the_challenge_unlocks(steps):
    lm, cam = make(steps=steps)
    assert lm.run(threading.Event()) is True
    assert cam.released and lm.best == pytest.approx(1.0) and lm.challenge.state == "matched"


def test_stranger_never_gets_past_the_first_phase():
    lm, cam = make(Person(STRANGER), timeout=3)
    assert lm.run(threading.Event()) is False and lm.challenge.state == "center" and cam.released


def test_photo_is_rejected_by_anti_spoofing():
    lm, _ = make(Person(live=0.1))
    assert lm.run(threading.Event()) is False and "photo" in lm.reason


def test_frozen_face_cannot_answer_the_challenge():
    lm, _ = make(Person(behaviour="frozen"))
    assert lm.run(threading.Event()) is False and "too slow" in lm.reason


def test_moving_the_wrong_way_fails():
    lm, _ = make(Person(behaviour="sweep"), steps=("right", "up"))
    assert lm.run(threading.Event()) is False and "wrong direction" in lm.reason


def test_swapping_faces_mid_challenge_fails():
    lm, _ = make(Person(behaviour="swap"))
    assert lm.run(threading.Event()) is False and "changed" in lm.reason


def test_multiple_faces_fail_closed():
    lm, _ = make(Person(faces=2), timeout=2)
    assert lm.run(threading.Event()) is False and lm.best is None


def test_cancel_stops_and_releases_camera():
    lm, cam = make(Person(STRANGER), timeout=1000)
    cancel = threading.Event()
    cancel.set()
    assert lm.run(cancel) is False and cam.released


def test_faceunlock_states():
    lm, _ = make()
    fu = FaceUnlock(lm)
    fu.start()
    fu._thread.join(2)
    assert fu.state == "matched"

    def broken():
        raise RuntimeError("camera unavailable")

    fu2 = FaceUnlock(LiveMatch(FaceMatcher(Person(), [OWNER], .40), broken))
    fu2.start()
    fu2._thread.join(2)
    assert fu2.state == "unavailable"


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path, console=False)
    yield c
    c.db.close()


def test_build_face_unlock_is_none_without_enrolment_or_when_disabled(ctx, monkeypatch):
    # No software cameras: on a PC with e.g. OBS Virtual Camera installed, face unlock is (rightly)
    # refused, which would hide what this test checks. That refusal has its own test (test_medium_fixes).
    from gatekeeper import matcher
    monkeypatch.setattr(matcher, "software_cameras", lambda: [])
    assert build_face_unlock(ctx, Person) is None
    FaceStore(ctx.db, ctx.keys).replace_all([(OWNER, None)])
    assert build_face_unlock(ctx, Person) is not None
    ctx.db.set_setting("face_unlock", "0")
    assert build_face_unlock(ctx, Person) is None


def test_old_enrolment_needs_reenrolling(ctx):
    FaceStore(ctx.db, ctx.keys).replace_all([(OWNER, None)])
    ctx.db.set_setting("face_model", "yunet+sface")  # samples made by the previous models
    assert build_face_unlock(ctx, Person) is None


def test_build_face_unlock_survives_model_failure(ctx):
    FaceStore(ctx.db, ctx.keys).replace_all([(OWNER, None)])

    def boom():
        raise RuntimeError("bad model")

    assert build_face_unlock(ctx, boom) is None


class FakeFace:
    def __init__(self, state):
        self.state, self.best, self.started, self.cancelled = "idle", 0.9, False, False
        self._final = state

    def start(self):
        self.started, self.state = True, self._final

    def cancel(self):
        self.cancelled = True


def pump(root, seconds=0.5):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update()
        time.sleep(0.02)


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display")
    r.withdraw()
    yield r
    r.destroy()


def test_prompt_face_match_unlocks(root):
    results, face_events = [], []
    face = FakeFace("matched")
    UnlockPrompt(root, "x.exe", lambda pw: False, results.append, face=face, fullscreen=False,
                 on_face_result=lambda s, sc: face_events.append(s))
    pump(root, 1.6)  # includes the 1s success animation
    assert results == [True] and face.started and face.cancelled and face_events == ["matched"]


def test_prompt_face_failure_falls_back_to_password(root):
    results = []
    face = FakeFace("failed")
    prompt = UnlockPrompt(root, "x.exe", lambda pw: pw == "right", results.append, face=face, fullscreen=False)
    pump(root, 0.3)
    assert results == [] and "password" in prompt.face_label.cget("text").lower()
    prompt.entry.insert(0, "right")
    prompt._submit()
    assert results == [True]


def test_prompt_works_without_face(root):
    results = []
    prompt = UnlockPrompt(root, "x.exe", lambda pw: False, results.append, max_attempts=1, fullscreen=False)
    prompt.entry.insert(0, "nope")
    prompt._submit()
    assert results == [False]
