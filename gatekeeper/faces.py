"""Offline face detection and embedding using OpenCV's YuNet (detector) and SFace
(recognizer) ONNX models. Model files are SHA-256 pinned; a swapped model is refused."""

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

# Pinned hashes: a tampered model could be made to "recognise" anyone, so it is never loaded.
MODEL_HASHES = {
    "yunet.onnx": "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4",
    "sface.onnx": "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79",
}


class ModelError(RuntimeError):
    pass


@dataclass
class Face:
    box: tuple      # x, y, w, h in pixels
    score: float
    row: np.ndarray  # raw YuNet row (box + landmarks + score), needed for alignment


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
    """Cosine similarity. SFace's suggested same-person threshold is about 0.363."""
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


def open_camera(index: int = 0):
    """Open a webcam with DirectShow (fast to open on Windows). Raises RuntimeError if unavailable."""
    import cv2
    cap = cv2.VideoCapture(index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        cap.release()
        raise RuntimeError("Could not open the camera. Is it in use or blocked in Windows privacy settings?")
    return cap


class FaceEngine:
    def __init__(self, det_threshold: float = 0.9):
        import cv2  # imported lazily: OpenCV is slow to import and only needed for faces
        self._cv2 = cv2
        # YuNet args: model, config, input size, score threshold, NMS threshold, max faces.
        self._detector = cv2.FaceDetectorYN.create(
            verified_model("yunet.onnx"), "", (320, 320), det_threshold, 0.3, 5000)
        self._recognizer = cv2.FaceRecognizerSF.create(verified_model("sface.onnx"), "")
        self._size = (320, 320)

    def detect(self, frame) -> list:
        """All faces in a BGR frame, most confident first."""
        h, w = frame.shape[:2]
        if (w, h) != self._size:  # YuNet must be told the frame size; only do it when it changes
            self._detector.setInputSize((w, h))
            self._size = (w, h)
        _, rows = self._detector.detect(frame)
        if rows is None:
            return []
        # Each row: x, y, w, h, 5 landmark (x, y) pairs, then the confidence at index 14.
        faces = [Face(tuple(int(v) for v in r[:4]), float(r[14]), r) for r in rows]
        return sorted(faces, key=lambda f: f.score, reverse=True)

    def embed(self, frame, face: Face) -> np.ndarray:
        """128-number SFace vector for one face (aligned on its eye/nose/mouth landmarks first)."""
        aligned = self._recognizer.alignCrop(frame, face.row)
        return self._recognizer.feature(aligned).flatten().astype(np.float32)
