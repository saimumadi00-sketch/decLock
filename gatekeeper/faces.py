"""Offline face pipeline, run with onnxruntime on the CPU:

  SCRFD-500M     finds faces and 5 landmarks (eyes, nose, mouth corners)      InsightFace buffalo_s
  ArcFace MBF    turns an aligned face into a 512-number identity vector     InsightFace buffalo_s
  MiniFASNet x2  anti-spoofing: probability the face is real, not a photo    Minivision (Apache-2.0)
                 or screen (two models on different crops, averaged)

Model files are SHA-256 pinned; a swapped model is refused. InsightFace's pretrained weights are
licensed for non-commercial research use only (fine for this project, not for a product).
"""

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

# Stored with every enrolment. Samples made by a different pipeline (e.g. the old YuNet/SFace one)
# are not comparable, so face unlock asks for a re-enrolment when this changes.
MODEL_ID = "scrfd500m+arcface-mbf"

# Pinned hashes: a tampered model could be made to "recognise" anyone, so it is never loaded.
MODEL_HASHES = {
    "scrfd_500m.onnx": "5e4447f50245bbd7966bd6c0fa52938c61474a04ec7def48753668a9d8b4ea3a",
    "arcface_mbf.onnx": "9cc6e4a75f0e2bf0b1aed94578f144d15175f357bdc05e815e5c4a02b319eb4f",
    "minifasnet_v2.onnx": "37fd1f3a1c4d06fe65a67db4f1ff009c22c1a3690dcb8c54e2c7a706ca7f736c",
    "minifasnet_v1se.onnx": "834506239fdb8492b1364a603390b18891e954a7a57f512d1fa95de1bb32b7e1",
}

DET_SIZE = 640                 # SCRFD input (square); frames are letterboxed into it
DET_STRIDES = (8, 16, 32)      # SCRFD predicts at three scales, 2 anchors per grid cell
NMS_THRESHOLD = 0.4
# Where ArcFace expects the 5 landmarks in its 112x112 input (InsightFace's standard template).
ARCFACE_TEMPLATE = np.array([[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366],
                             [41.5493, 92.3655], [70.7299, 92.2041]], dtype=np.float32)
# MiniFASNet models and how much context around the face each one was trained on.
SPOOF_MODELS = (("minifasnet_v2.onnx", 2.7), ("minifasnet_v1se.onnx", 4.0))
SPOOF_SIZE = 80


class ModelError(RuntimeError):
    pass


@dataclass
class Face:
    box: tuple        # x, y, w, h in pixels
    score: float      # detector confidence 0..1
    kps: np.ndarray   # (5, 2): left eye, right eye, nose, left and right mouth corner (as seen in the image)


def models_dir() -> Path:
    """Where the .onnx files live: $GATEKEEPER_MODELS, the PyInstaller bundle, or ../models."""
    env = os.environ.get("GATEKEEPER_MODELS")
    if env:
        return Path(env)  # safe to override: the files are still hash-checked
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "models"  # unpacked PyInstaller bundle
    return Path(__file__).resolve().parent.parent / "models"


def verified_model(name: str) -> str:
    """Path of a model file after checking it against its pinned SHA-256."""
    path = models_dir() / name
    if not path.is_file():
        raise ModelError(f"Missing model file: {path}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != MODEL_HASHES[name]:
        raise ModelError(f"{name} does not match its pinned SHA-256; refusing to load it.")
    return str(path)


def similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity of two identity vectors: about 0 for strangers, 0.4+ for the same person."""
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def open_camera(index: int = 0):
    """Open a webcam with DirectShow (fast to open on Windows). Raises RuntimeError if unavailable."""
    import cv2
    cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        cap.release()
        raise RuntimeError("Could not open the camera. Is it in use or blocked in Windows privacy settings?")
    return cap


def _session(name: str):
    import onnxruntime as ort
    options = ort.SessionOptions()
    options.intra_op_num_threads = 2       # leave CPU for the app being unlocked
    options.log_severity_level = 3         # errors only
    return ort.InferenceSession(verified_model(name), options, providers=["CPUExecutionProvider"])


def spoof_crop(frame, box, scale: float, size: int = SPOOF_SIZE):
    """MiniFASNet's input: the face box enlarged `scale` times (shifted to stay inside the frame), resized.

    Same geometry as Minivision's CropImage, which the models were trained with."""
    import cv2
    src_h, src_w = frame.shape[:2]
    x, y, w, h = box
    w, h = max(w, 1), max(h, 1)
    scale = min((src_h - 1) / h, (src_w - 1) / w, scale)  # never larger than the frame
    new_w, new_h = w * scale, h * scale
    cx, cy = x + w / 2, y + h / 2
    x0, y0, x1, y1 = cx - new_w / 2, cy - new_h / 2, cx + new_w / 2, cy + new_h / 2
    if x0 < 0:
        x1, x0 = x1 - x0, 0
    if y0 < 0:
        y1, y0 = y1 - y0, 0
    if x1 > src_w - 1:
        x0, x1 = x0 - (x1 - src_w + 1), src_w - 1
    if y1 > src_h - 1:
        y0, y1 = y0 - (y1 - src_h + 1), src_h - 1
    crop = frame[int(y0):int(y1) + 1, int(x0):int(x1) + 1]
    return cv2.resize(crop, (size, size))


class FaceEngine:
    def __init__(self, det_threshold: float = 0.5):
        import cv2  # imported lazily: OpenCV and onnxruntime are slow to import
        self._cv2 = cv2
        self.det_threshold = det_threshold
        self._detector = _session("scrfd_500m.onnx")
        self._det_input = self._detector.get_inputs()[0].name
        self._recognizer = _session("arcface_mbf.onnx")
        self._rec_input = self._recognizer.get_inputs()[0].name
        self._spoof = [(_session(name), scale) for name, scale in SPOOF_MODELS]
        self._anchors = {}  # (stride) -> grid of anchor centres, built once

    # -- detection (SCRFD) ----------------------------------------------------------------------
    def _anchor_centres(self, stride: int) -> np.ndarray:
        if stride not in self._anchors:
            cells = DET_SIZE // stride
            ys, xs = np.mgrid[:cells, :cells]
            centres = np.stack([xs, ys], axis=-1).reshape(-1, 2).astype(np.float32) * stride
            self._anchors[stride] = np.repeat(centres, 2, axis=0)  # 2 anchors share each centre
        return self._anchors[stride]

    def detect(self, frame) -> list:
        """All faces in a BGR frame, most confident first."""
        cv2 = self._cv2
        h, w = frame.shape[:2]
        scale = DET_SIZE / max(h, w)  # letterbox: keep the aspect ratio, pad bottom/right with black
        resized = cv2.resize(frame, (int(round(w * scale)), int(round(h * scale))))
        canvas = np.zeros((DET_SIZE, DET_SIZE, 3), np.uint8)
        canvas[:resized.shape[0], :resized.shape[1]] = resized
        # SCRFD wants RGB, (pixel - 127.5) / 128, NCHW.
        blob = cv2.dnn.blobFromImage(canvas, 1 / 128, (DET_SIZE, DET_SIZE), (127.5, 127.5, 127.5), swapRB=True)
        outputs = self._detector.run(None, {self._det_input: blob})
        boxes, scores, points = [], [], []
        levels = len(DET_STRIDES)
        # Outputs: [scores x3 strides, box distances x3, landmark offsets x3], all in stride units.
        for i, stride in enumerate(DET_STRIDES):
            score = outputs[i].reshape(-1)
            keep = np.where(score >= self.det_threshold)[0]
            if not len(keep):
                continue
            centres = self._anchor_centres(stride)[keep]
            dist = outputs[i + levels][keep] * stride        # distances to the left, top, right, bottom edges
            offs = outputs[i + 2 * levels][keep] * stride    # 5 (dx, dy) landmark offsets
            boxes.append(np.hstack([centres - dist[:, :2], centres + dist[:, 2:]]))
            points.append(centres[:, None, :] + offs.reshape(-1, 5, 2))
            scores.append(score[keep])
        if not boxes:
            return []
        boxes = np.vstack(boxes) / scale     # back to frame pixels
        points = np.vstack(points) / scale
        scores = np.concatenate(scores)
        xywh = [[float(b[0]), float(b[1]), float(b[2] - b[0]), float(b[3] - b[1])] for b in boxes]
        kept = cv2.dnn.NMSBoxes(xywh, scores.tolist(), self.det_threshold, NMS_THRESHOLD)  # drop duplicates
        faces = [Face(tuple(int(round(v)) for v in xywh[i]), float(scores[i]), points[i].astype(np.float32))
                 for i in np.array(kept).reshape(-1)]
        return sorted(faces, key=lambda f: f.score, reverse=True)

    # -- recognition (ArcFace) ------------------------------------------------------------------
    def embed(self, frame, face: Face) -> np.ndarray:
        """512-number ArcFace vector for one face, after aligning its landmarks to ArcFace's template."""
        cv2 = self._cv2
        matrix, _ = cv2.estimateAffinePartial2D(face.kps, ARCFACE_TEMPLATE, method=cv2.LMEDS)
        if matrix is None:  # degenerate landmarks: fall back to a plain resize of the box
            x, y, w, h = face.box
            aligned = cv2.resize(frame[max(0, y):y + h, max(0, x):x + w], (112, 112))
        else:
            aligned = cv2.warpAffine(frame, matrix, (112, 112), borderValue=0)
        blob = cv2.dnn.blobFromImage(aligned, 1 / 127.5, (112, 112), (127.5, 127.5, 127.5), swapRB=True)
        return self._recognizer.run(None, {self._rec_input: blob})[0].flatten().astype(np.float32)

    # -- anti-spoofing (MiniFASNet) -------------------------------------------------------------
    def liveness(self, frame, face: Face) -> float:
        """Probability (0..1) that this is a real face in front of the camera, not a photo or screen."""
        real = []
        for session, scale in self._spoof:
            crop = spoof_crop(frame, face.box, scale)
            blob = crop.transpose(2, 0, 1)[None].astype(np.float32)  # raw 0-255 BGR, NCHW: as trained
            probs = session.run(None, {"input": blob})[0][0]       # [print/paper, real, screen/replay]
            real.append(float(probs[1]))
        return float(np.mean(real))
