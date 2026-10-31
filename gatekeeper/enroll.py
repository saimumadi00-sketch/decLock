"""Face enrolment: collect several consistent samples, then store them atomically."""

import time

from .faces import open_camera, similarity

MIN_FACE_PX = 80       # smaller faces give unreliable embeddings
CONSISTENCY = 0.5      # a new sample must resemble the first one, so two people can't mix
MARGIN = 0.25          # extra border around the snapshot crop


class Enroller:
    def __init__(self, engine, store, samples: int = 5, snapshots: bool = True,
                 interval: float = 1.0, clock=time.monotonic):
        self.engine, self.store = engine, store
        self.target, self.snapshots = samples, snapshots
        self.interval, self.clock = interval, clock  # min. seconds between samples, for variety
        self._samples = []           # [(embedding, jpeg_or_None)], kept in memory until commit()
        self._last = -interval       # so the very first good frame is captured at once

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
        """Save all samples, replacing any earlier enrolment. Nothing is saved until this succeeds."""
        if not self.done:
            raise RuntimeError(f"Only {self.collected} of {self.target} samples collected.")
        self.store.replace_all(self._samples)
        return self.collected

    @staticmethod
    def _snapshot(frame, face) -> bytes:
        """JPEG of the face plus a margin, clipped to the frame edges."""
        import cv2
        x, y, w, h = face.box
        mx, my = int(w * MARGIN), int(h * MARGIN)
        H, W = frame.shape[:2]
        crop = frame[max(0, y - my):min(H, y + h + my), max(0, x - mx):min(W, x + w + mx)]
        ok, jpg = cv2.imencode(".jpg", crop, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return jpg.tobytes() if ok else b""


# offer() status -> text shown to the user.
MESSAGES = {
    "no_face": "No face found",
    "multiple_faces": "Only one person in view, please",
    "too_small": "Move closer",
    "hold_still": "Hold still...",
    "inconsistent": "Doesn't match your first sample",
    "captured": "Captured",
}


def run_camera_enrolment(enroller: Enroller, camera_index: int = 0, timeout: float = 120) -> bool:
    """Interactive preview window (CLI). ESC cancels. Returns True if enough samples were collected."""
    import cv2
    cap = open_camera(camera_index)
    deadline = time.monotonic() + timeout
    try:
        while not enroller.done and time.monotonic() < deadline:
            ok, frame = cap.read()
            if not ok:
                continue
            status = enroller.offer(frame)
            shown = frame.copy()  # draw on a copy so the text never ends up in a snapshot
            text = f"{enroller.collected}/{enroller.target}  {MESSAGES[status]}  (Esc to cancel)"
            cv2.putText(shown, text, (10, 28), cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
            cv2.imshow("Gatekeeper enrolment", shown)
            if cv2.waitKey(1) & 0xFF == 27:  # Esc
                return False
        return enroller.done
    finally:
        cap.release()
        cv2.destroyAllWindows()
