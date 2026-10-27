# human.py human-like puases
import math, time, random

TAP_PAUSE, FORM_PAUSE, READ_PAUSE, REVIEW_PAUSE = 0.4, 0.8, 2.5, 2.0
_rng = random.Random()

def seed_time(seed):
    """Seed the timing stream for one session (to make it reproducible)"""
    _rng.seed(seed)

def think(seconds=2.0, sigma=0.6):
    """Pause ~seconds (median), with the odd longer gap. capped at 20s"""
    time.sleep(min(_rng.lognormvariate(math.log(seconds), sigma), 20))