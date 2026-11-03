import json, glob, os
import pandas as pd

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(CURR_DIR, "datasets", "raw")
OUTPUT_DIR = os.path.join(CURR_DIR, "datasets")
files =  glob.glob(os.path.join(RAW_DIR, "*.jsonl"))
OUTCOME_KEYS = ("status", "execution_result", "connection_result",
                "detection_result", "validation_result")

ENV_EVENTS   = {"ME-11", "ME-14", "ME-15"}

# ------------------ load raw jsonl to one row per event -------------------------
def load_events(raw_dir):
    """
    Stacking .josonl files from raw_dir into one dataframe with columns: session_id, event_id, compoenent, t, data
    
    Args:
        raw_dir: the direcotry that contains the .jonsl files, each .jonsl file must be in this format:
            {
                "event_id": "ME-XX",
                "event_type": "",
                "timestamp": "",
                "component": "",
                "data": {} -> dict
            }, 
    Return:
        event_df: dataframe of the files with columns: [columns: session_id, event_id, compoenent, t, data]
    """
    rows = []

    for path in sorted(glob.glob(os.path.join(raw_dir, "*.jsonl"))):
        sid = os.path.basename(path).replace(".jsonl", "")

        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    e = json.loads(line)
                    e["session_id"] = sid
                    rows.append(e)

    event_df = pd.DataFrame(rows)
    event_df["t"] = pd.to_datetime(event_df["timestamp"], errors="coerce")
    return event_df

def _get(d, key):
    """from d dictonary get the value at key or None if d is not a dict"""
    return d.get(key) if isinstance(d, dict) else None

def is_failure(data):
    """report if the result of an event is a failure or not (e.g, HTTP request, SQL, ...)"""

    for k in OUTCOME_KEYS:
        v = str(_get(data, k) or "").upper()
        if v in ("FAILURE", "ERROR") or v.startswith("HTTP_4") or v.startswith("HTTP_5"):
            return True
    return False

def _count_val(event_df, eid, field, value):
    """in event_df for event id eid count the number field=value for each session"""

    sub_df = event_df[event_df.event_id == eid]
    if sub_df.empty:
        return pd.Series(dtype = "float64")
    
    return sub_df["data"].apply(lambda d: _get(d, field) == value).groupby(sub_df["session_id"]).sum()

def _distinct(event_df, eid, field):
    """in event_df for event id eid count the number field=value for each session"""

    sub_df = event_df[event_df.event_id == eid]
    if sub_df.empty: 
        return pd.Series(dtype="float64")
    
    return sub_df["data"].apply(lambda d: _get(d, field)).groupby(sub_df["session_id"]).nunique()

# ----------------------------- Table 1: per-session feature vector --------------------

def build_tabular(event_df):
    """
    Collapse each session events into one fixed numeric row
    Args:
        event_df: per-event dataframe from load_events.
    Return:
        feat: dataframe indexed by session_id (one row per session)
    """
    event_df = event_df.sort_values(["session_id", "t"]).copy()

    feat = event_df.pivot_table(index="session_id", columns="event_id",
                          aggfunc="size", fill_value=0).add_prefix("n_")  # event-type counts

    feat["n_events"]     = event_df.groupby("session_id").size()
    feat["n_components"] = event_df.groupby("session_id")["component"].nunique()
    feat["duration_s"]   = event_df.groupby("session_id")["t"].agg(
                               lambda s: (s.max() - s.min()).total_seconds())

    act = event_df[~event_df.event_id.isin(ENV_EVENTS)].copy()   #timing on action events only
    act["gap"] = act.groupby("session_id")["t"].diff().dt.total_seconds()
    feat["mean_gap_s"] = act.groupby("session_id")["gap"].mean()
    feat["std_gap_s"]  = act.groupby("session_id")["gap"].std()

    fail = event_df["data"].apply(is_failure)                       # outcome
    feat["n_failures"]    = fail.groupby(event_df["session_id"]).sum()
    feat["frac_failures"] = feat["n_failures"] / feat["n_events"]

    feat["n_not_parameterized"]         = _count_val(event_df, "ME-07", "parameterization_status", "NOT_PARAMETERIZED")
    feat["n_distinct_query_structures"] = _distinct(event_df, "ME-07", "query_structure")
    feat["n_distinct_url_paths"]        = _distinct(event_df, "ME-10", "url_path")
    feat["n_distinct_ports"]            = _distinct(event_df, "ME-10", "destination_port")
    sub10 = event_df[event_df.event_id == "ME-10"]
    
    if not sub10.empty:
        err = sub10["data"].apply(lambda d: not str(_get(d, "connection_result") or "").startswith("HTTP_2"))
        feat["n_http_errors"] = err.groupby(sub10["session_id"]).sum()
    
    feat["n_sensitive_logs"]     = _count_val(event_df, "ME-05", "sensitivity_classification", "SENSITIVE")
    feat["n_anonymous_provider"] = _count_val(event_df, "ME-09", "authentication_state", "ANONYMOUS")

    return feat.fillna(0).sort_index()

# -------------- Table 2: per-session sequences --------------
def build_sequences(event_df):
    return (event_df.sort_values("t").groupby("session_id")["event_id"].apply(list)).to_dict()

# ------------- Summary and main ---------------------
def summary(df):
    per = df.groupby("session_id").size()

    print("sessions:", df.session_id.nunique(), " total events: ", len(df))
    print("events/session: min %d median %d max %d" % (per.min(), per.median(), per.max()))
    print("\nevent_id counts:\n", df.event_id.value_counts().to_string())
    print("\ncomponents:\n", df.component.value_counts().to_string())

def main():
    df = load_events(RAW_DIR)

    summary(df)
    feat = build_tabular(df)
    feat.to_csv(os.path.join(OUTPUT_DIR, "features.csv"))
    print("Table 1 shape: ", feat.shape)
    print("Columns: ", feat.columns)

    seqs = build_sequences(df)
    with open(os.path.join(OUTPUT_DIR, "sequences.json"), "w", encoding="utf-8") as f:
        json.dump(seqs, f)    

    print("Table 2 : ", len(seqs), " Sessions")

if __name__ == "__main__":
    main()