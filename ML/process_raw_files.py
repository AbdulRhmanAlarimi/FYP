"""
process_raw_files.py: process raw session (.jsonl in dataset/raw) and turn them into input for the two models
"""
import json, glob, os
import pandas as pd

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
RAW_DIR = os.path.join(CURR_DIR, "datasets", "raw")
OUTPUT_DIR = os.path.join(CURR_DIR, "datasets")

# Rule events that are not usefull for the ML models, (debugger, integrity, root, emulator)
RULE_EVENTS = {"ME-11", "ME-13", "ME-14", "ME-15"}
ML_EVENTS = [f"ME-{i:02d}" for i in range(1, 16) if f"ME-{i:02d}" not in RULE_EVENTS]

# every backend endpoint the app calls
ENDPOINTS = ["/login", "/getaccountdetails", "/getaccounts", "/getmyaccounts", "/gettransactions",
             "/getbeneficiaries", "/addbeneficiary", "/deletebeneficiary", "/getbillcategories",
             "/getbillhistory", "/paybill", "/deposit", "/dotransfer", "/getprofile",
             "/updateprofile", "/changepassword", "/signup"]

# screens a user can open before logging
PRE_LOGIN_SCREENS = {"LoginActivity", "DoLogin", "SignUpActivity", "FilePrefActivity", "WrongLogin"}

OWN_APP = "com.android.insecurebankv2"

# ------------------ load raw jsonl to one row per event -------------------------
def load_events(raw_dir):
    """
    from all the .josonl files turn them into one dataframe
    
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
        event_df: dataframe of the files with columns: [columns: session_id, event_id, compoenent, t, the fields inside "data" are separate columns]
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
    fields = pd.json_normalize(event_df["data"].tolist())  
    event_df = pd.concat([event_df.drop(columns="data"), fields], axis=1)
    event_df["t"] = pd.to_datetime(event_df["timestamp"], errors="coerce", utc=True, format="ISO8601")
    return order_events(event_df)

def order_events(event_df):
    """sort events by their session lunch, then by seq (hook own counter)"""

    event_df["launch_start"] = event_df.groupby(["session_id", "launch_id"])["t"].transform("min")
    event_df = event_df.sort_values(["session_id", "launch_start", "seq"])

    return event_df.drop(columns="launch_start").reset_index(drop=True)


# ----------------------------- Table 1: per-session feature vector --------------------

def count(ev, condition):
    """how many events per session match the condition"""
    return condition.groupby(ev["session_id"]).sum()


def build_tabular(events):
    """one row of features per session"""

    ev = events[~events.event_id.isin(RULE_EVENTS)] #execlude rule event's (not usefull)
    by_session = ev.groupby("session_id") #events groupyed by sessions

    #how many of each event type we have 
    feat = (pd.crosstab(ev.session_id, ev.event_id)
              .reindex(columns=ML_EVENTS, fill_value=0)
              .add_prefix("n_"))

    # ----- size (number of events) and timing ----
    feat["n_events"] = by_session.size()
    feat["n_screens"] = by_session["component"].nunique()
    feat["duration_s"] = by_session["t"].agg(lambda t: (t.max() - t.min()).total_seconds())
    gaps = by_session["t"].diff().dt.total_seconds()
    feat["mean_gap_s"] = gaps.groupby(ev.session_id).mean()
    feat["std_gap_s"] = gaps.groupby(ev.session_id).std()

    # ---- outcomes ---
    
    # for filtering netwrok and sql events
    net, sql = ev.event_id == "ME-10", ev.event_id == "ME-07"

    feat["n_login_failures"] = count(ev, ev.login_result == "FAILURE")
    feat["n_http_errors"] = count(ev, net & ~ev.connection_result.astype(str).str.startswith("HTTP_2"))
    feat["n_failures"] = feat.n_login_failures + feat.n_http_errors
    feat["n_sensitive_logs"] = count(ev, ev.sensitivity_classification == "SENSITIVE")

    #injection signs
    feat["n_suspicious_input"] = count(ev, ev.validation_result == "SUSPICIOUS")
    feat["n_not_parameterized"] = count(ev, sql & (ev.parameterization_status == "NOT_PARAMETERIZED"))
    feat["n_query_shapes"] = ev[sql].groupby("session_id")["query_structure"].nunique()

    #who opened which screen
    screen = ev.event_id == "ME-09"
    feat["n_anon_privileged"] = count(ev, screen & (ev.authentication_state == "ANONYMOUS") #anynomyous user opend not a pre login screen
                                      & ~ev.component.isin(PRE_LOGIN_SCREENS))
    
    caller = ev.caller_package.fillna(ev.get("source_package")).fillna("UNKNOWN")
    feat["n_external_caller"] = count(ev, ev.event_id.isin(["ME-09", "ME-12"])
                                      & (ev.component != "LoginActivity")      # opening the app is normal
                                      & ~caller.isin(["UNKNOWN", OWN_APP]))

    #what the user did: one count per backend endpoint
    feat["n_endpoints"] = ev[net].groupby("session_id")["url_path"].nunique() # number of called endpoints
    for endpoint in ENDPOINTS:
        feat["n_ep_" + endpoint.strip("/")] = count(ev, net & (ev.url_path == endpoint)) #count for number of calls for each endpoint

    return feat.fillna(0).sort_index()


# -------------- Table 2: per-session sequences --------------

# add additional info for each event type:
TOKEN_FIELDS = {
    "ME-09": ["component", "authentication_state"],     # screen + auth state      
    "ME-10": ["url_path"],                              # url path
    "ME-07": ["operation", "parameterization_status"],  # sql opeation + parameterization_status
    "ME-06": ["login_result"],                          # login worked or not
}

def token(row):
    """one step of the session sequnce, e.g ME-09|DepositActivity|AUTHENTICATED or ME-10|/deposit"""
    details = [str(row[f]) for f in TOKEN_FIELDS.get(row.event_id, []) if pd.notna(row[f])]
    return "|".join([row.event_id] + details)

def build_sequences(events):
    """one ordered list of steps per session"""

    ev = events[~events.event_id.isin(RULE_EVENTS)]
    ev = ev.assign(step=ev.apply(token, axis=1))
    
    return ev.groupby("session_id")["step"].apply(list).to_dict()

# ------------- Summary and main ---------------------
def main():

    # load the raw events
    events = load_events(RAW_DIR)

    # ----- debug info ----
    per_session = events.groupby("session_id").size()
    print(f"{events.session_id.nunique()} sessions, {len(events)} events "
          f"(min {per_session.min()}, median {per_session.median():.0f}, max {per_session.max()} per session)")
    # ----------------

    # build tabl 1 features
    features = build_tabular(events)
    features.to_csv(os.path.join(OUTPUT_DIR, "features.csv"))

    print("Table 1:", features.shape)

    # build sequntial model features (event1 ----> .... ---> event n)
    sequences = build_sequences(events)
    with open(os.path.join(OUTPUT_DIR, "sequences.json"), "w", encoding="utf-8") as f:
        json.dump(sequences, f)
    
    print("Table 2:", len(sequences), "sessions")

if __name__ == "__main__":
    main()