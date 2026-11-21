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
from sklearn.metrics import (roc_auc_score, average_precision_score, roc_curve,
                             recall_score, precision_score, f1_score)

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

SMOOTHING = [0.0003, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0]   # Markov smoothing values to try


def tuned_markov(order, train_sequences, val_sequences):
    """fit a Markov model with the smoothing that best predicts NORMAL validation sessions
    (lowest average surprise) - attacks are never used to choose it"""
    best = min(SMOOTHING, key=lambda k: MarkovModel(order, k).fit(train_sequences).score(val_sequences).mean())
    return MarkovModel(order, best).fit(train_sequences)


NEW_DATA_FROM = pd.Timestamp("2026-11-19", tz="UTC")   # the day the new benign collection started

def temporal_split(labels, train=0.5, val=0.2):
    """
    split data into train, valdiation, test splits, attacks are always test.
    old and new benign data are each split by time (oldest train, next validate, newest test),
    so the new kinds of sessions also reach training
    """
    tr, va, te = [], [], []
    benign = labels[labels.label == "benign"].sort_values("started_at")

    for part in [benign[benign.started_at < NEW_DATA_FROM], benign[benign.started_at >= NEW_DATA_FROM]]:
        a, b = int(len(part) * train), int(len(part) * (train + val))
        tr += list(part.index[:a]); va += list(part.index[a:b]); te += list(part.index[b:])

    return tr, va, te + list(labels[labels.label != "benign"].index)


def save_charts(scores, y, results, per_class):
    """four basic charts: % of attacks detected per model, recall/precision/F1 per model,
    ROC curve of each model, and % of each attack class detected"""

    # 0. bar chart: % of all attacks detected at the chosen threshold (false alarms written next to each bar)
    fig, ax = plt.subplots(figsize=(7, 3.5))
    bars = ax.barh(results.index[::-1], results["recall_%"][::-1], color="tab:blue")
    for bar, (detected, fpr) in zip(bars, results[["detected", "FPR_%"]].values[::-1]):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                f"{detected}  (false alarms {fpr}%)", va="center", fontsize=8)
    ax.set(xlim=(0, 100), xlabel="attacks detected (%)", title="Attacks detected per model (test set)")
    fig.savefig(os.path.join(RESULTS_DIR, "detection_per_model.png"), dpi=150, bbox_inches="tight")

    # 0b. recall, precision and F1 side by side for each model (F1 value written on top)
    metrics = results[["recall_%", "precision_%", "F1_%"]]
    ax = metrics.plot.bar(figsize=(11, 4), width=0.8, rot=0, color=["tab:blue", "tab:orange", "tab:green"])
    for bar, f1 in zip(ax.containers[2], metrics["F1_%"]):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, f"{f1:.0f}", ha="center", fontsize=8)
    ax.set(ylim=(0, 105), ylabel="%", xlabel="", title="Recall, precision and F1 per model (test set)")
    ax.legend(["recall", "precision", "F1"], loc="upper left", ncol=3, frameon=False)
    ax.figure.savefig(os.path.join(RESULTS_DIR, "scores_per_model.png"), dpi=150, bbox_inches="tight")

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

    for name in ["ECOD", "AutoEncoder"]:
        scores[name] = TabularModel(name).fit(X.loc[train]).score(X)

    train_sequences = {s: sequences[s] for s in train}
    val_sequences = {s: sequences[s] for s in val}              # normal sessions only
    markov = tuned_markov(1, train_sequences, val_sequences)
    scores["Markov"] = markov.score(sequences)
    markov2 = tuned_markov(2, train_sequences, val_sequences)   # the model exported to the phone
    scores["Markov2"] = markov2.score(sequences)
    scores["LSTM"] = LSTMModel().fit(train_sequences).score(sequences)        # report only
    scores["ZScoreBaseline"] = ZScoreBaseline().fit(X.loc[train]).score(X)

    # hybrid: alarm when the steps (Markov2) OR the counts (ZScore) are unusual.
    # each score is divided by its 99% value on training sessions so both are on the same scale, then take the larger
    limit = lambda name: scores[name] / scores.loc[train, name].quantile(QUANTILE)
    scores["Markov2+ZScore"] = pd.concat([limit("Markov2"), limit("ZScoreBaseline")], axis=1).max(axis=1)

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
               # recall: attacks caught, precision: alarms that were attacks (depends on the attack/benign ratio of the test set)
               "recall_%": round(100 * recall_score(y, alarms.loc[test, name]), 1),
               "precision_%": round(100 * precision_score(y, alarms.loc[test, name], zero_division=0), 1),
               "F1_%": round(100 * f1_score(y, alarms.loc[test, name], zero_division=0), 1),
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

    markov2.export(os.path.join(RESULTS_DIR, "markov_model.json"), thresholds["Markov2"])

    print(f"train {len(train)}  val {len(val)}  test {len(test)}   "
          f"{X.shape[1]} features, timing {'on' if USE_TIMING else 'off'}, "
          f"Markov smoothing {markov.smoothing} (order 1) / {markov2.smoothing} (order 2)\n")
    print(results.drop(columns=per_class.columns.map(lambda c: c + "_detected_%")).to_string(), "\n")
    print("Detection rate per attack class (%):")
    print(per_class.to_string())

if __name__ == "__main__":
    main()
