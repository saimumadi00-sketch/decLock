"""Face enrolment: collect several consistent samples, then store them atomically."""

import time

from .faces import similarity

MIN_FACE_PX = 80       # smaller faces give unreliable embeddings
CONSISTENCY = 0.5      # a new sample must resemble the first one, so two people can't mix
MARGIN = 0.25          # extra border around the snapshot crop


class Enroller:
    def __init__(self, engine, store, samples: int = 5, snapshots: bool = True,
                 interval: float = 1.0, clock=time.monotonic):
        self.engine, self.store = engine, store
        self.target, self.snapshots = samples, snapshots
        self.interval, self.clock = interval, clock
        self._samples = []
        self._last = -interval

    @property
    def collected(self) -> int:
        return len(self._samples)

    @property
    def done(self) -> bool:
        return self.collected >= self.target

    def offer(self, frame) -> str:
        """Feed one camera frame. Returns a status string for on-screen feedback."""
        faces = self.engine.detect(frame)
        if not faces:
            return "no_face"
        if len(faces) > 1:
            return "multiple_faces"
        face = faces[0]
        if min(face.box[2], face.box[3]) < MIN_FACE_PX:
            return "too_small"
        if self.clock() - self._last < self.interval:
            return "hold_still"
        embedding = self.engine.embed(frame, face)
        if self._samples and similarity(self._samples[0][0], embedding) < CONSISTENCY:
            return "inconsistent"
        self._samples.append((embedding, self._snapshot(frame, face) if self.snapshots else None))
        self._last = self.clock()
        return "captured"

    def commit(self) -> int:
        if not self.done:
            raise RuntimeError(f"Only {self.collected} of {self.target} samples collected.")
        self.store.replace_all(self._samples)
        return self.collected

    @staticmethod
    def _snapshot(frame, face) -> bytes:
        import cv2
        x, y, w, h = face.box
        mx, my = int(w * MARGIN), int(h * MARGIN)
        H, W = frame.shape[:2]
        crop = frame[max(0, y - my):min(H, y + h + my), max(0, x - mx):min(W, x + w + mx)]
        ok, jpg = cv2.imencode(".jpg", crop, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return jpg.tobytes() if ok else b""


MESSAGES = {
    "no_face": "No face found",
    "multiple_faces": "Only one person in view, please",
    "too_small": "Move closer",
    "hold_still": "Hold still...",
    "inconsistent": "Doesn't match your first sample",
    "captured": "Captured",
}


def run_camera_enrolment(enroller: Enroller, camera_index: int = 0, timeout: float = 120) -> bool:
    """Interactive preview window. ESC cancels. Returns True if enough samples were collected."""
    import cv2
    cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
    if not cap.isOpened():
        raise RuntimeError("Could not open the camera. Is it in use or blocked in Windows privacy settings?")
    deadline = time.monotonic() + timeout
    try:
        while not enroller.done and time.monotonic() < deadline:
            ok, frame = cap.read()
            if not ok:
                continue
            status = enroller.offer(frame)
            shown = frame.copy()
            text = f"{enroller.collected}/{enroller.target}  {MESSAGES[status]}  (Esc to cancel)"
            cv2.putText(shown, text, (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            cv2.imshow("Gatekeeper enrolment", shown)
            if cv2.waitKey(1) & 0xFF == 27:
                return False
        return enroller.done
    finally:
        cap.release()
        cv2.destroyAllWindows()
