"""Offline face detection and embedding using OpenCV's YuNet (detector) and SFace
(recognizer) ONNX models. Model files are SHA-256 pinned; a swapped model is refused."""

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np

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
    env = os.environ.get("GATEKEEPER_MODELS")
    if env:
        return Path(env)
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "models"
    return Path(__file__).resolve().parent.parent / "models"


def verified_model(name: str) -> str:
    path = models_dir() / name
    if not path.is_file():
        raise ModelError(f"Missing model file: {path}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != MODEL_HASHES[name]:
        raise ModelError(f"{name} does not match its pinned SHA-256; refusing to load it.")
    return str(path)


def similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine similarity. SFace's suggested same-person threshold is about 0.363."""
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))


class FaceEngine:
    def __init__(self, det_threshold: float = 0.9):
        import cv2
        self._cv2 = cv2
        self._detector = cv2.FaceDetectorYN.create(
            verified_model("yunet.onnx"), "", (320, 320), det_threshold, 0.3, 5000)
        self._recognizer = cv2.FaceRecognizerSF.create(verified_model("sface.onnx"), "")
        self._size = (320, 320)

    def detect(self, frame) -> list:
        h, w = frame.shape[:2]
        if (w, h) != self._size:
            self._detector.setInputSize((w, h))
            self._size = (w, h)
        _, rows = self._detector.detect(frame)
        if rows is None:
            return []
        faces = [Face(tuple(int(v) for v in r[:4]), float(r[14]), r) for r in rows]
        return sorted(faces, key=lambda f: f.score, reverse=True)

    def embed(self, frame, face: Face) -> np.ndarray:
        aligned = self._recognizer.alignCrop(frame, face.row)
        return self._recognizer.feature(aligned).flatten().astype(np.float32)
