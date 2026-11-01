"""Liveness for face unlock: MiniFASNet anti-spoofing on every frame, plus a randomized
challenge-response (e.g. "turn your head left, then look up") that a photo or a recorded video
can't answer.

Why head movements: the challenge is measured from the face's own landmarks. Tilting or rotating
a flat photo moves every landmark together, so the nose never shifts relative to the eyes the way
it does when a real head turns. The order is random each time (from the OS's secure random source),
so a pre-recorded video would have to show exactly the right moves in the right order, and any move
in a WRONG direction fails the attempt.

The flow, fed one camera frame at a time (Challenge.feed):
  1. "center"   look at the camera: N frontal frames that match the enrolled face and look real.
                Their head pose becomes this attempt's baseline.
  2. "step"     each random direction in turn, within STEP_SECONDS, measured against the baseline.
                Between steps the head must come back to the centre first.
  3. "confirm"  look back at the camera: the enrolled face must match again at the end.
Throughout: exactly one face, the same face (its box must move smoothly between frames), every
frame checked by MiniFASNet, and any frontal frame that clearly isn't the enrolled person fails it.
"""

import math
import secrets
import time
from dataclasses import dataclass

import numpy as np

DIRECTIONS = {  # direction -> instruction shown to the user
    "left": "Slowly turn your head to the left",
    "right": "Slowly turn your head to the right",
    "up": "Slowly look up",
    "down": "Slowly look down",
}
STEPS = 2                 # random directions per attempt (4 x 3 = 12 possible sequences)
LIVE_THRESHOLD = 0.70     # MiniFASNet "real" probability a frame needs to count
MAX_SPOOF_FRAMES = 6      # more frames than this below LIVE_THRESHOLD: treated as a spoof, attempt fails
MIN_HITS = 3              # consecutive good frames needed for the centre and confirm phases
STEP_HITS = 2             # consecutive frames past the threshold to complete a head-movement step
STEP_SECONDS = 5.0        # time allowed per step
MAX_MISSES = 8            # frames in a row with no face before the attempt fails (detector blips are fine)
FRONTAL_YAW = 0.15        # |yaw| below this counts as "looking at the camera"
YAW_DELTA = 0.22          # sideways nose shift (in eye-distances) that counts as a head turn
PITCH_DELTA = 0.10        # vertical nose shift (as a share of the eye-mouth distance) that counts as up/down
MIN_IOU = 0.25            # face box overlap between consecutive frames: lower means a different face appeared
WRONG_FACTOR = 1.5        # a move counts as "wrong direction" only when this much past the threshold
                          # (people tilt a little while turning; that must not fail them)
WRONG_FACE_FRAMES = 3     # frontal frames clearly NOT the enrolled person before the attempt fails
WRONG_FACE_MARGIN = 0.10  # "clearly": this far below the match threshold


@dataclass
class Observation:
    """What one camera frame showed (built by matcher.FaceMatcher.observe)."""
    faces: int                 # number of faces detected
    box: tuple = None          # x, y, w, h of the face (when exactly one)
    identity: float = None     # similarity to the enrolled face
    live: float = None         # MiniFASNet real-face probability
    yaw: float = None          # see head_pose()
    pitch: float = None


def head_pose(kps) -> tuple:
    """(yaw, pitch) from SCRFD's 5 landmarks, ignoring head roll.

    yaw:   sideways nose offset from the eye midpoint, in eye-distances. About 0 when facing the
           camera; positive when the nose points to the IMAGE's right, which is the person's own
           LEFT (the camera faces them; frames are not mirrored).
    pitch: how far down the nose sits between the eye line (0) and the mouth line (1). Looking up
           makes it smaller, looking down makes it larger. Compared with the attempt's own baseline.
    """
    kps = np.asarray(kps, dtype=np.float64)
    left_eye, right_eye, nose, mouth_l, mouth_r = kps
    angle = math.atan2(right_eye[1] - left_eye[1], right_eye[0] - left_eye[0])  # head roll
    c, s = math.cos(-angle), math.sin(-angle)
    centre = (left_eye + right_eye) / 2
    rotated = (kps - centre) @ np.array([[c, s], [-s, c]])  # rotate so the eyes are level
    eye_dist = max(np.linalg.norm(right_eye - left_eye), 1e-6)
    nose_r, mouth_mid = rotated[2], (rotated[3] + rotated[4]) / 2
    yaw = nose_r[0] / eye_dist
    pitch = nose_r[1] / max(mouth_mid[1], 1e-6)
    return float(yaw), float(pitch)


def random_challenge(steps: int = STEPS) -> list:
    """`steps` different directions in a random order, from the OS's cryptographic random source."""
    return secrets.SystemRandom().sample(list(DIRECTIONS), steps)


def _iou(a, b) -> float:
    ax, ay, aw, ah = a
    bx, by, bw, bh = b
    ix = max(0, min(ax + aw, bx + bw) - max(ax, bx))
    iy = max(0, min(ay + ah, by + bh) - max(ay, by))
    inter = ix * iy
    union = aw * ah + bw * bh - inter
    return inter / union if union > 0 else 0.0


def _moved(direction: str, d_yaw: float, d_pitch: float, factor: float = 1.0) -> bool:
    """Is the head turned in `direction` (by `factor` x the threshold), relative to the baseline?"""
    return {"left": d_yaw > YAW_DELTA * factor, "right": d_yaw < -YAW_DELTA * factor,
            "up": d_pitch < -PITCH_DELTA * factor, "down": d_pitch > PITCH_DELTA * factor}[direction]


def _centred(d_yaw: float, d_pitch: float) -> bool:
    """Back near the baseline (half the movement thresholds)."""
    return abs(d_yaw) < YAW_DELTA / 2 and abs(d_pitch) < PITCH_DELTA / 2


class Challenge:
    """State machine for one face-unlock attempt. `state`: center / step / confirm / matched / failed."""

    def __init__(self, steps: list, threshold: float, clock=time.monotonic):
        self.steps, self.threshold, self.clock = list(steps), threshold, clock
        self.state, self.reason = "center", ""
        self.step = 0                          # index into self.steps
        self.best = None                       # best identity score seen (for the audit log)
        self._hits, self._misses, self._spoof, self._wrong = 0, 0, 0, 0
        self._baseline, self._samples = None, []
        self._prev_box, self._deadline = None, None
        self._returning = False                # between steps: waiting for the head to come back to centre

    @property
    def started(self) -> bool:
        """After the centre phase the same face must stay in view; before it, nothing can fail."""
        return self.state in ("step", "confirm")

    @property
    def instruction(self) -> str:
        if self.state == "step" and self._returning:
            return "Now look straight at the camera again"
        if self.state == "step":
            return f"{DIRECTIONS[self.steps[self.step]]} ({self.step + 1}/{len(self.steps)})"
        if self.state == "confirm":
            return "Now look straight at the camera"
        if self.state == "center":
            return "Look straight at the camera"
        return ""

    def _fail(self, reason: str) -> str:
        self.state, self.reason = "failed", reason
        return self.state

    def feed(self, obs: Observation) -> str:
        """Process one frame; returns the new state."""
        if self.state in ("matched", "failed"):
            return self.state
        now = self.clock()
        if self.state == "step" and now > self._deadline:
            return self._fail("too slow to follow the instruction")

        # -- exactly one face, and the same one as before --------------------------------------
        if obs.faces == 0:
            self._misses += 1
            if self.started and self._misses > MAX_MISSES:
                return self._fail("face left the camera view")
            self._hits = 0
            return self.state
        if obs.faces > 1:
            if self.started:
                return self._fail("more than one face in view")
            self._hits = 0
            return self.state
        self._misses = 0
        if self.started and self._prev_box is not None and _iou(self._prev_box, obs.box) < MIN_IOU:
            return self._fail("the face in view changed")
        self._prev_box = obs.box

        # -- anti-spoofing on every frame ------------------------------------------------------
        if obs.live is None or obs.live < LIVE_THRESHOLD:
            self._spoof += 1
            self._hits = 0
            if self._spoof > MAX_SPOOF_FRAMES:
                return self._fail("looks like a photo or a screen")
            return self.state

        # -- identity: checked whenever the face is turned towards the camera --------------------
        base_yaw, base_pitch = self._baseline or (0.0, 0.0)
        frontal = abs(obs.yaw - base_yaw) < FRONTAL_YAW if self._baseline else abs(obs.yaw) < FRONTAL_YAW
        matches = obs.identity is not None and obs.identity >= self.threshold
        if obs.identity is not None and (self.best is None or obs.identity > self.best):
            self.best = obs.identity
        if self.started and frontal and obs.identity is not None \
                and obs.identity < self.threshold - WRONG_FACE_MARGIN:
            self._wrong += 1
            if self._wrong >= WRONG_FACE_FRAMES:
                return self._fail("not the enrolled face")

        # -- phases ----------------------------------------------------------------------------
        if self.state == "center":
            if frontal and matches:
                self._hits += 1
                self._samples.append((obs.yaw, obs.pitch))
                if self._hits >= MIN_HITS:
                    self._baseline = tuple(np.mean(self._samples, axis=0))  # this attempt's "straight ahead"
                    self.state, self._hits = "step", 0
                    self._deadline = now + STEP_SECONDS
            else:
                self._hits, self._samples = 0, []
        elif self.state == "step":
            d_yaw, d_pitch = obs.yaw - base_yaw, obs.pitch - base_pitch
            if self._returning:  # previous step done: wait for the head to come back before the next one
                if _centred(d_yaw, d_pitch):
                    self._returning, self._deadline = False, now + STEP_SECONDS
                return self.state
            wanted = self.steps[self.step]
            if any(_moved(d, d_yaw, d_pitch, WRONG_FACTOR) for d in DIRECTIONS if d != wanted):
                return self._fail("moved in the wrong direction")  # a replayed video "sweeping" fails here
            self._hits = self._hits + 1 if _moved(wanted, d_yaw, d_pitch) else 0
            if self._hits >= STEP_HITS:
                self.step, self._hits = self.step + 1, 0
                if self.step == len(self.steps):
                    self.state = "confirm"
                else:
                    self._returning, self._deadline = True, now + STEP_SECONDS
        elif self.state == "confirm":
            self._hits = self._hits + 1 if (frontal and matches) else 0
            if self._hits >= MIN_HITS:
                self.state = "matched"
        return self.state
