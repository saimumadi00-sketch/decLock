import threading
import time
import tkinter as tk

import numpy as np
import pytest

from gatekeeper.app import open_context
from gatekeeper.face_store import FaceStore
from gatekeeper.faces import Face
from gatekeeper.matcher import FaceMatcher, FaceUnlock, LiveMatch, build_face_unlock
from gatekeeper.ui import UnlockPrompt

OWNER = np.ones(128, np.float32)
STRANGER = np.concatenate([np.ones(64), -np.ones(64)]).astype(np.float32)  # cosine 0 with OWNER
FRAME = np.zeros((480, 640, 3), np.uint8)
GOOD_FACE = Face((50, 50, 120, 120), 0.99, np.zeros(15))


class ScriptedEngine:
    def __init__(self, embedding=OWNER, faces=None):
        self.embedding, self.faces = embedding, faces if faces is not None else [GOOD_FACE]

    def detect(self, frame):
        return self.faces

    def embed(self, frame, face):
        return self.embedding


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


def live(engine, clock=None, **kw):
    clock = clock or Clock()
    cam = FakeCamera(clock)
    matcher = FaceMatcher(engine, [OWNER], 0.45)
    return LiveMatch(matcher, lambda: cam, clock=clock, **kw), cam


def test_owner_matches_after_hold():
    lm, cam = live(ScriptedEngine())
    assert lm.run(threading.Event()) is True
    assert cam.released and lm.best == pytest.approx(1.0)


def test_stranger_times_out():
    lm, cam = live(ScriptedEngine(STRANGER), timeout=2)
    assert lm.run(threading.Event()) is False
    assert cam.released


def test_multiple_faces_fail_closed():
    lm, _ = live(ScriptedEngine(faces=[GOOD_FACE, GOOD_FACE]), timeout=2)
    assert lm.run(threading.Event()) is False and lm.best is None


def test_single_good_frame_is_not_enough():
    engine = ScriptedEngine()
    lm, cam = live(engine, timeout=3, hold=0.5)
    calls = {"n": 0}
    real_detect = engine.detect

    def flaky(frame):  # owner appears only every other frame, so the streak keeps resetting
        calls["n"] += 1
        return real_detect(frame) if calls["n"] % 2 else []

    engine.detect = flaky
    assert lm.run(threading.Event()) is False


def test_cancel_stops_and_releases_camera():
    lm, cam = live(ScriptedEngine(STRANGER), timeout=1000)
    cancel = threading.Event()
    cancel.set()
    assert lm.run(cancel) is False and cam.released


def test_faceunlock_states():
    lm, _ = live(ScriptedEngine())
    fu = FaceUnlock(lm)
    fu.start()
    fu._thread.join(2)
    assert fu.state == "matched"

    def broken():
        raise RuntimeError("camera unavailable")

    fu2 = FaceUnlock(LiveMatch(FaceMatcher(ScriptedEngine(), [OWNER], .45), broken))
    fu2.start()
    fu2._thread.join(2)
    assert fu2.state == "unavailable"


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path, console=False)
    yield c
    c.db.close()


def test_build_face_unlock_is_none_without_enrolment_or_when_disabled(ctx):
    assert build_face_unlock(ctx, ScriptedEngine) is None
    FaceStore(ctx.db, ctx.keys).replace_all([(OWNER, None)])
    assert build_face_unlock(ctx, ScriptedEngine) is not None
    ctx.db.set_setting("face_unlock", "0")
    assert build_face_unlock(ctx, ScriptedEngine) is None


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
    UnlockPrompt(root, "x.exe", lambda pw: False, results.append, face=face,
                 on_face_result=lambda s, sc: face_events.append(s))
    pump(root)
    assert results == [True] and face.started and face.cancelled and face_events == ["matched"]


def test_prompt_face_failure_falls_back_to_password(root):
    results = []
    face = FakeFace("failed")
    prompt = UnlockPrompt(root, "x.exe", lambda pw: pw == "right", results.append, face=face)
    pump(root, 0.3)
    assert results == [] and "password" in prompt.face_label.cget("text").lower()
    prompt.entry.insert(0, "right")
    prompt._submit()
    assert results == [True]


def test_prompt_works_without_face(root):
    results = []
    prompt = UnlockPrompt(root, "x.exe", lambda pw: False, results.append, max_attempts=1)
    prompt.entry.insert(0, "nope")
    prompt._submit()
    assert results == [False]
