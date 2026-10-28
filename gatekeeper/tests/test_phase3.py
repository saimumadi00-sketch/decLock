import numpy as np
import pytest

from gatekeeper.app import open_context
from gatekeeper.enroll import Enroller
from gatekeeper.face_store import FaceStore
from gatekeeper.faces import Face, FaceEngine, ModelError, similarity, verified_model


class FakeEngine:
    """Returns scripted faces/embeddings so enrolment logic is testable without a camera."""

    def __init__(self):
        self.faces = [Face((50, 50, 120, 120), 0.99, np.zeros(15))]
        self.embedding = np.ones(128, np.float32)

    def detect(self, frame):
        return self.faces

    def embed(self, frame, face):
        return self.embedding.copy()


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path, console=False)
    yield c
    c.db.close()


FRAME = np.zeros((480, 640, 3), np.uint8)


def make(ctx, engine=None, **kw):
    return Enroller(engine or FakeEngine(), FaceStore(ctx.db, ctx.keys), interval=0, **kw)


def test_enrolment_collects_and_commits(ctx):
    e = make(ctx, samples=3)
    assert [e.offer(FRAME) for _ in range(3)] == ["captured"] * 3 and e.done
    assert e.commit() == 3
    store = FaceStore(ctx.db, ctx.keys)
    assert store.count() == 3
    assert np.allclose(store.embeddings()[0], np.ones(128))
    assert store.snapshots()[0][:2] == b"\xff\xd8"  # JPEG magic, decrypted


def test_face_data_is_encrypted_at_rest(ctx):
    e = make(ctx, samples=1)
    e.offer(FRAME)
    e.commit()
    raw = ctx.db.conn.execute("SELECT embedding, snapshot FROM face_samples").fetchone()
    assert np.ones(128, np.float32).tobytes() not in raw["embedding"]
    assert b"\xff\xd8" not in raw["snapshot"][:2]


def test_no_snapshots_option(ctx):
    e = make(ctx, samples=1, snapshots=False)
    e.offer(FRAME)
    e.commit()
    assert FaceStore(ctx.db, ctx.keys).snapshots() == []


def test_rejections(ctx):
    eng = FakeEngine()
    e = make(ctx, eng, samples=2)
    eng.faces = []
    assert e.offer(FRAME) == "no_face"
    eng.faces = [Face((0, 0, 100, 100), .9, np.zeros(15))] * 2
    assert e.offer(FRAME) == "multiple_faces"
    eng.faces = [Face((0, 0, 40, 40), .9, np.zeros(15))]
    assert e.offer(FRAME) == "too_small"
    eng.faces = [Face((50, 50, 120, 120), .9, np.zeros(15))]
    assert e.offer(FRAME) == "captured"
    eng.embedding = -np.ones(128, np.float32)  # a different "person"
    assert e.offer(FRAME) == "inconsistent"
    assert e.collected == 1


def test_interval_between_samples(ctx):
    now = [0.0]
    e = Enroller(FakeEngine(), FaceStore(ctx.db, ctx.keys), samples=2, interval=1.0, clock=lambda: now[0])
    assert e.offer(FRAME) == "captured"
    assert e.offer(FRAME) == "hold_still"
    now[0] = 1.5
    assert e.offer(FRAME) == "captured"


def test_incomplete_enrolment_saves_nothing(ctx):
    e = make(ctx, samples=3)
    e.offer(FRAME)
    with pytest.raises(RuntimeError):
        e.commit()
    assert FaceStore(ctx.db, ctx.keys).count() == 0


def test_reenrol_replaces_old_data_and_clear(ctx):
    store = FaceStore(ctx.db, ctx.keys)
    for _ in range(2):
        e = make(ctx, samples=2)
        e.offer(FRAME), e.offer(FRAME)
        e.commit()
    assert store.count() == 2
    store.clear()
    assert store.count() == 0


def test_similarity():
    a = np.array([1, 0], np.float32)
    assert similarity(a, a) == pytest.approx(1.0)
    assert similarity(a, np.array([0, 1], np.float32)) == pytest.approx(0.0)


def test_real_models_load_and_find_no_face_in_blank_frame():
    engine = FaceEngine()
    assert engine.detect(FRAME) == []


def test_tampered_model_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_MODELS", str(tmp_path))
    (tmp_path / "yunet.onnx").write_bytes(b"not the real model")
    with pytest.raises(ModelError, match="pinned"):
        verified_model("yunet.onnx")
    with pytest.raises(ModelError, match="Missing"):
        verified_model("sface.onnx")
