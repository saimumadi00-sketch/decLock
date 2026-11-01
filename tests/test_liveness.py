"""Head-pose geometry and the randomized challenge (liveness.py)."""

import math

import numpy as np
import pytest

from gatekeeper import liveness
from gatekeeper.liveness import DIRECTIONS, Challenge, Observation, head_pose, random_challenge

FRONTAL = np.array([[100, 100], [160, 100], [130, 130], [110, 160], [150, 160]], np.float64)


def transformed(kps, angle_deg=0.0, scale=1.0, squash_x=1.0, shift=(0, 0)):
    """Apply what holding up / tilting a FLAT photo does: rotate, scale, squash, move (all landmarks together)."""
    a = math.radians(angle_deg)
    rot = np.array([[math.cos(a), -math.sin(a)], [math.sin(a), math.cos(a)]])
    centre = kps.mean(axis=0)
    out = (kps - centre) * [squash_x, 1.0] @ rot.T * scale + centre + shift
    return out


def test_frontal_face_has_no_yaw():
    yaw, pitch = head_pose(FRONTAL)
    assert yaw == pytest.approx(0.0) and pitch == pytest.approx(0.5)


def test_head_roll_does_not_look_like_a_turn():
    yaw, pitch = head_pose(transformed(FRONTAL, angle_deg=25))
    assert yaw == pytest.approx(0.0, abs=1e-6) and pitch == pytest.approx(0.5, abs=1e-6)


@pytest.mark.parametrize("angle,scale,squash", [(0, 1.5, 1.0), (15, 0.7, 1.0), (0, 1.0, 0.6), (-20, 1.2, 0.5)])
def test_moving_or_tilting_a_flat_photo_never_registers_as_a_head_movement(angle, scale, squash):
    yaw, pitch = head_pose(transformed(FRONTAL, angle, scale, squash, shift=(40, -30)))
    assert abs(yaw) < liveness.YAW_DELTA / 2 and abs(pitch - 0.5) < liveness.PITCH_DELTA / 2


def test_real_head_turn_and_nod_register():
    left = FRONTAL.copy()
    left[2, 0] += 20       # nose towards the image's right = the person's left
    up = FRONTAL.copy()
    up[2, 1] -= 12         # nose closer to the eye line
    assert head_pose(left)[0] > liveness.YAW_DELTA
    assert head_pose(up)[1] < 0.5 - liveness.PITCH_DELTA


def test_challenge_is_random_and_valid():
    seen = {tuple(random_challenge()) for _ in range(200)}
    assert len(seen) > 6  # 12 possible orders; 200 draws hit many of them
    for steps in seen:
        assert len(steps) == liveness.STEPS == len(set(steps)) and set(steps) <= set(DIRECTIONS)


class Clock:
    t = 0.0

    def __call__(self):
        return self.t


def frame(yaw=0.0, pitch=0.5, identity=0.9, live=0.95, faces=1, box=(50, 50, 160, 160)):
    return Observation(faces=faces, box=box, identity=identity, live=live, yaw=yaw, pitch=pitch)


def run(challenge, frames, clock, dt=0.1):
    for f in frames:
        clock.t += dt
        state = challenge.feed(f)
    return state


def test_nothing_fails_before_the_attempt_really_starts():
    clock = Clock()
    c = Challenge(["left", "up"], 0.4, clock)
    # No face, two faces, a stranger: all just wait in the first phase.
    assert run(c, [frame(faces=0)] * 20 + [frame(faces=2)] * 5 + [frame(identity=0.1)] * 5, clock) == "center"


def test_full_sequence_and_return_to_centre_between_steps():
    clock = Clock()
    c = Challenge(["left", "right"], 0.4, clock)
    run(c, [frame()] * liveness.MIN_HITS, clock)
    assert c.state == "step" and "left" in c.instruction
    run(c, [frame(yaw=0.35)] * liveness.STEP_HITS, clock)
    assert c._returning and "straight" in c.instruction  # still turned left: must come back first
    run(c, [frame(yaw=0.35)], clock)                     # staying left now is NOT a wrong-direction fail
    assert c.state == "step"
    run(c, [frame()] + [frame(yaw=-0.35)] * liveness.STEP_HITS, clock)
    assert c.state == "confirm"
    assert run(c, [frame()] * liveness.MIN_HITS, clock) == "matched"


def test_someone_else_looking_at_the_camera_mid_challenge_fails():
    clock = Clock()
    c = Challenge(["left", "up"], 0.4, clock)
    run(c, [frame()] * liveness.MIN_HITS, clock)
    assert run(c, [frame(identity=0.1)] * liveness.WRONG_FACE_FRAMES, clock) == "failed"
    assert "not the enrolled face" in c.reason


def test_face_leaving_the_view_fails_once_started():
    clock = Clock()
    c = Challenge(["left", "up"], 0.4, clock)
    run(c, [frame()] * liveness.MIN_HITS, clock)
    assert run(c, [frame(faces=0)] * (liveness.MAX_MISSES + 1), clock) == "failed"


def test_a_few_spoof_like_frames_are_tolerated_but_not_many():
    clock = Clock()
    c = Challenge(["left", "up"], 0.4, clock)
    run(c, [frame(live=0.3)] * liveness.MAX_SPOOF_FRAMES, clock)
    assert c.state == "center"                            # a few bad frames (blur, light) are fine
    assert run(c, [frame(live=0.3)], clock) == "failed" and "photo" in c.reason
