"""
evaluate.py: split sessions by time, train every detector on benign sessions,
set its alarm threshold on validation sessions, and measure it on test sessions

Prints whether the ML models beat the simple baseline (overall and per attack class),
and saves three charts in results/: detection per model, ROC curves, detection per attack class.
"""
import os, sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")    # save charts to files, no window
import matplotlib.pyplot as plt
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

# Python only finds modules in the folders listed in sys.path.
# Running "python modeling/evaluate.py" lists only modeling/, but
# process_raw_files.py is one folder up, in ML/, so we add ML/ to the list.
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")   # .../ML
sys.path.insert(0, ROOT)                                                # search ML/first

import process_raw_files as prf
from models import TabularModel, MarkovModel, LSTMModel, ZScoreBaseline


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


def save_charts(scores, y, results, per_class):
    """three basic charts: % of attacks detected per model, ROC curve of each model,
    and % of each attack class detected"""

    # 0. bar chart: % of all attacks detected at the chosen threshold (false alarms written next to each bar)
    fig, ax = plt.subplots(figsize=(7, 3.5))
    bars = ax.barh(results.index[::-1], results["recall_%"][::-1], color="tab:blue")
    for bar, (detected, fpr) in zip(bars, results[["detected", "FPR_%"]].values[::-1]):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{detected}  (false alarms {fpr}%)", va="center", fontsize=8)
    ax.set(xlim=(0, 100), xlabel="attacks detected (%)", title="Attacks detected per model (test set)")
    fig.savefig(os.path.join(RESULTS_DIR, "detection_per_model.png"), dpi=150, bbox_inches="tight")

    # 1. ROC: how well each model's score ranks attacks above benign sessions
    fig, ax = plt.subplots(figsize=(6, 5))
    for name in scores:
        fpr, tpr, _ = roc_curve(y, scores[name])
        ax.plot(fpr, tpr, label=f"{name} (AUC {roc_auc_score(y, scores[name]):.2f})")
    ax.plot([0, 1], [0, 1], color="grey", linewidth=1, linestyle="--")   # random guess
    ax.set(xlabel="false positive rate", ylabel="attacks detected (true positive rate)", title="ROC curves (test set)")
    ax.legend(loc="lower right")
    fig.savefig(os.path.join(RESULTS_DIR, "roc_curves.png"), dpi=150, bbox_inches="tight")

    # 2. detection per attack class, at the chosen threshold
    fig, ax = plt.subplots(figsize=(10, 4))
    im = ax.imshow(per_class.values, cmap="Blues", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(per_class.shape[1]), [c.replace("_", "\n") for c in per_class.columns], fontsize=8)
    ax.set_yticks(range(per_class.shape[0]), per_class.index)
    for i in range(per_class.shape[0]):
        for j in range(per_class.shape[1]):
            v = per_class.values[i, j]
            ax.text(j, i, f"{v:.0f}%", ha="center", va="center", fontsize=8, color="white" if v > 60 else "black")
    ax.set_title(f"Attacks detected per class (threshold = {QUANTILE:.0%} of validation scores)")
    fig.colorbar(im, ax=ax)
    fig.savefig(os.path.join(RESULTS_DIR, "detection_per_class.png"), dpi=150, bbox_inches="tight")


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

    for name in ["ECOD", "IForest", "AutoEncoder"]:
        scores[name] = TabularModel(name).fit(X.loc[train]).score(X)

    markov = MarkovModel().fit({s: sequences[s] for s in train})
    scores["Markov"] = markov.score(sequences)
    train_sequences = {s: sequences[s] for s in train}
    scores["LSTM"] = LSTMModel().fit(train_sequences).score(sequences)        # report only
    scores["ZScoreBaseline"] = ZScoreBaseline().fit(X.loc[train]).score(X)

    # threshold on validation then measure on test
    thresholds = scores.loc[val].quantile(QUANTILE)   # one threshold per model
    alarms = scores > thresholds

    benign_test = [s for s in test if labels.label[s] == "benign"] # being data in test split
    attacks = labels.loc[[s for s in test if labels.label[s] != "benign"]] #attack data in test split
    y = labels.loc[test, "label"] != "benign"                     # True = attack

    rows = []
    for name in scores:
        row = {"model": name,
               "false_alarms": f"{alarms.loc[benign_test, name].sum()}/{len(benign_test)}", # false alarm, beign data in test flagged
               "FPR_%": round(100 * alarms.loc[benign_test, name].mean(), 1),
               "detected": f"{alarms.loc[attacks.index, name].sum()}/{len(attacks)}",       # attacks in test flagged
               "recall_%": round(100 * alarms.loc[attacks.index, name].mean(), 1),
               # threshold-free: how well the score ranks attacks above benign (1.0 perfect, 0.5 random)
               "ROC_AUC": round(roc_auc_score(y, scores.loc[test, name]), 3),
               "PR_AUC": round(average_precision_score(y, scores.loc[test, name]), 3)}

        for attack_class, group in attacks.groupby("attack_class"):
            row[f"{attack_class}_detected_%"] = round(100 * alarms.loc[group.index, name].mean(), 1)

        rows.append(row)

    results = pd.DataFrame(rows).set_index("model")
    per_class = results.filter(like="_detected_%").rename(columns=lambda c: c.replace("_detected_%", ""))

    # save and print
    os.makedirs(RESULTS_DIR, exist_ok=True)
    results.to_csv(os.path.join(RESULTS_DIR, "results.csv"))
    alarms.add_suffix("_alarm").join(labels[["label", "attack_class"]]).to_csv(os.path.join(RESULTS_DIR, "alarms.csv"))
    scores.join(labels[["label", "attack_class"]]).to_csv(os.path.join(RESULTS_DIR, "scores.csv"))
    save_charts(scores.loc[test], y, results, per_class)

    markov.export(os.path.join(RESULTS_DIR, "markov_model.json"), thresholds["Markov"])

    print(f"train {len(train)}  val {len(val)}  test {len(test)}   "
          f"{X.shape[1]} features, timing {'on' if USE_TIMING else 'off'}\n")
    print(results.drop(columns=per_class.columns.map(lambda c: c + "_detected_%")).to_string(), "\n")
    print("Detection rate per attack class (%):")
    print(per_class.to_string())

if __name__ == "__main__":
    main()
