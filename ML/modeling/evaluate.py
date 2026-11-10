"""
evaluate.py: split sessions by time, train every detector on benign sessions,
set its alarm threshold on validation sessions, and measure it on test sessions

Prints two comparisons:
  1. ML part:       do the ML models beat the simple baseline?
  2. Final comparison: does adding ML to the rules improve on the rules alone?
"""
import os, sys
import pandas as pd

# Python only finds modules in the folders listed in sys.path.
# Running "python modeling/evaluate.py" lists only modeling/, but
# process_raw_files.py is one folder up, in ML/, so we add ML/ to the list.
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")   # .../ML
sys.path.insert(0, ROOT)                                                # search ML/first

import process_raw_files as prf
from models import TabularModel, MarkovModel, ZScoreBaseline


RESULTS_DIR = os.path.join(ROOT, "results")
TIMING = ["duration_s", "mean_gap_s", "std_gap_s"]
USE_TIMING = False     # execlude the timing feature
QUANTILE = 0.99         # alarm threshold


def temporal_split(labels, train=0.5, val=0.2):
    """
    split data into train, valdiation, test splits,
    oldest benign sessions train, the next ones validate, the newest test, attacks are always test
    """

    benign = labels[labels.label == "benign"].sort_values("started_at")
    a, b = int(len(benign) * train), int(len(benign) * (train + val))

    test = list(benign.index[b:]) + list(labels[labels.label != "benign"].index)
    return list(benign.index[:a]), list(benign.index[a:b]), test


def main():
    # data
    labels = pd.read_csv(os.path.join(prf.OUTPUT_DIR, "labels.csv"), index_col="session_id")
    labels["started_at"] = pd.to_datetime(labels.started_at, utc=True, format="ISO8601")
    events = prf.load_events(prf.RAW_DIR)
    X = prf.build_tabular(events)

    if not USE_TIMING:
        X = X.drop(columns=TIMING)

    sequences = prf.build_sequences(events)
    train, val, test = temporal_split(labels.loc[X.index])

    # train on benign-train + score each session
    scores = pd.DataFrame(index=X.index)
    
    for name in ["ECOD", "IForest", "HBOS"]:
        scores[name] = TabularModel(name).fit(X.loc[train]).score(X)
    
    markov = MarkovModel().fit({s: sequences[s] for s in train})
    scores["Markov"] = markov.score(sequences)
    scores["ZScoreBaseline"] = ZScoreBaseline().fit(X.loc[train]).score(X)

    # threshold on validation then measure on test
    thresholds = scores.loc[val].quantile(QUANTILE)   # one threshold per model
    alarms = scores > thresholds
     
    benign_test = [s for s in test if labels.label[s] == "benign"] # being data in test split
    attacks = labels.loc[[s for s in test if labels.label[s] != "benign"]] #attack data in test split, empty until attacks exist
    
    rows = []
    for name in scores:
        row = {"model": name,
               "false_alarms": f"{alarms.loc[benign_test, name].sum()}/{len(benign_test)}", # false alarm, beign data in test flagged
               "FPR_%": round(100 * alarms.loc[benign_test, name].mean(), 1)}
        
        for attack_class, group in attacks.groupby("attack_class"):
            row[f"{attack_class}_detected_%"] = round(100 * alarms.loc[group.index, name].mean(), 1)
            
        rows.append(row)
    
    results = pd.DataFrame(rows).set_index("model")

    # save and print
    os.makedirs(RESULTS_DIR, exist_ok=True)
    results.to_csv(os.path.join(RESULTS_DIR, "results.csv"))
    alarms.add_suffix("_alarm").join(labels[["label", "attack_class"]]).to_csv(os.path.join(RESULTS_DIR, "alarms.csv"))
    scores.join(labels[["label", "attack_class"]]).to_csv(os.path.join(RESULTS_DIR, "scores.csv"))

    markov.export(os.path.join(RESULTS_DIR, "markov_model.json"), thresholds["Markov"])
    
    print(f"train {len(train)}  val {len(val)}  test {len(test)}   "
          f"{X.shape[1]} features, timing {'on' if USE_TIMING else 'off'}\n")
    print(results.to_string())

if __name__ == "__main__":
    main()