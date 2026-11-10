#usage run te shell script in the same dir as this file in the repo

import argparse
import csv
import os
import random
import time
import traceback
from datetime import datetime, timezone

import collect  # reuse: get_events, write_session, clean_virtual_device, ensure_server_prefs, next_seed
from attacks_qais import ATTACKS, run_attack

LABEL = "attack"
MANIFEST = collect.MANIFEST


def append_manifest(row):
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    new = not os.path.exists(MANIFEST)
    with open(MANIFEST, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["session_id", "label", "seed", "n_events", "started_at",
                        "ended_at", "file", "attack_class", "n_mistakes"])
        w.writerow(row)


def run_one(seed, attack_class, func, mode):
    baseline = len(collect.get_events())
    collect.clean_virtual_device()
    started = datetime.now(timezone.utc).isoformat()

    result = run_attack(attack_class, func, seed, mode)
    time.sleep(collect.SETTLE_SEC)
    ended = datetime.now(timezone.utc).isoformat()

    allev = collect.get_events()
    if len(allev) < baseline:
        baseline = 0
    session_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}_{seed}"
    path, n = collect.write_session(allev[baseline:], session_id)
    # n_mistakes column mirrors collect.py; for attacks it counts attack steps (1)
    append_manifest([session_id, LABEL, seed, n, started, ended,
                     os.path.basename(path), attack_class, 1])
    print(f"  {session_id} [{attack_class}/{mode}/{result.get('attack', '?')}]: "
          f"{n} events -> {os.path.basename(path)}")


def run_batch(classes, per_attack, modes, base_seed=0):
    try:
        collect.get_events()
    except Exception as e:
        raise SystemExit(f"Hook not reachable at {collect.HOOK_URL} ({e}) Start it first")
    collect.ensure_server_prefs()

    rng = random.Random(base_seed)
    plan = []
    for cls in classes:
        for mode in modes:
            # Shuffled deck: every variant runs once (random order) before
            # any variant repeats - raising --per-attack adds coverage first,
            # duplicates only after a class's whole deck is exhausted.
            deck = []
            while len(deck) < per_attack:
                block = ATTACKS[cls][:]
                rng.shuffle(block)
                deck.extend(block)
            for func in deck[:per_attack]:
                plan.append((cls, func, mode))
    rng.shuffle(plan)

    for i, (cls, func, mode) in enumerate(plan):
        seed = base_seed + i
        print(f"---------- session {i + 1} / {len(plan)}  {cls}  {mode}  ----------")
        try:
            run_one(seed, cls, func, mode)
        except Exception as e:
            print(f"Session {seed} ({cls}/{mode}) failed: {e}")
            traceback.print_exc()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--attacks", default=",".join(ATTACKS),
                   help="comma-separated attack classes (default: all)")
    p.add_argument("--per-attack", type=int, default=1,
                   help="sessions per attack class per mode")
    p.add_argument("--mode", choices=["genuine", "direct", "both"], default="both",
                   help="genuine = login via journey first, direct = adb/API only")
    p.add_argument("--seed", type=int, default=None, help="base seed (default: next free)")
    a = p.parse_args()

    classes = [c.strip() for c in a.attacks.split(",") if c.strip() in ATTACKS]
    unknown = [c.strip() for c in a.attacks.split(",") if c.strip() and c.strip() not in ATTACKS]
    if unknown:
        raise SystemExit(f"unknown attack classes: {unknown} (valid: {sorted(ATTACKS)})")
    modes = ["genuine", "direct"] if a.mode == "both" else [a.mode]
    run_batch(classes, a.per_attack, modes,
              base_seed=a.seed if a.seed is not None else collect.next_seed())
