from journey import start_journey
from datetime import datetime, timezone
import json, os, csv, time, subprocess, urllib.request


PKG = "com.android.insecurebankv2"
HOOK_URL = "http://127.0.0.1:8000/events"
HERE       = os.path.dirname(__file__)
OUT_DIR    = os.path.join(HERE, "..", "datasets", "raw")
MANIFEST   = os.path.join(HERE, "..", "datasets", "labels.csv")
LABEL      = "benign"
SETTLE_SEC = 1.5

def get_events():
    with urllib.request.urlopen(HOOK_URL, timeout=5) as r:
        return json.load(r)

def clean_virtual_device():
    """Start fresh virutal device"""
    subprocess.run(["adb", "shell", "am", "force-stop", PKG], check=True) # kill the app and make the next lunch start clean
    subprocess.run(["adb", "logcat", "-c"], check=True) # clear the log buffer

def run_one_flow(seed):
    baseline = len(get_events()) #events already in the hook
    clean_virtual_device()
    started = datetime.now(timezone.utc).isoformat()

    start_journey(seed)
    time.sleep(SETTLE_SEC)

    allev = get_events()
    if len(allev) < baseline:  # hook was restarted, list shrank
        baseline = 0

    session_id = f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}_{seed}"
    path, n = write_session(allev[baseline:], session_id)
    append_manifest([session_id, LABEL, seed, n, started, os.path.basename(path), ""])
    print(f"  {session_id}: {n} events -> {os.path.basename(path)}")


def write_session(events, session_id):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, f"{LABEL}_{session_id}.jsonl")
    events = sorted(events, key=lambda e: e.get("timestamp", ""))

    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    return path, len(events)

def append_manifest(row):
    os.makedirs(os.path.dirname(MANIFEST), exist_ok=True)
    new = not os.path.exists(MANIFEST)

    with open(MANIFEST, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["session_id", "label", "seed", "n_events", "started_at", "file", "attack_class"])
        w.writerow(row)

def next_seed(default=0):
    if not os.path.exists(MANIFEST):
        return default
    with open(MANIFEST, newline="") as f:
        seeds = [int(r["seed"]) for r in csv.DictReader(f)]
    return max(seeds) + 1 if seeds else default

def run_batch(num_flows, base_seed=0):
    try:
        get_events()

    except Exception as e:
        raise SystemExit(f"Hook not reachable at {HOOK_URL} ({e}) Start it first")
    
    for i in range(num_flows):
        seed = base_seed + i
        print(f"---------- session {i + 1} / {num_flows} ----------")
        try:
            run_one_flow(seed)
        except Exception as e:
            print(f"Session {seed} falied:{e}")

if __name__ == "__main__":
    num_flows = int(input("Number of user flows: "))
    run_batch(num_flows, base_seed=next_seed())