import math
from collections import Counter, defaultdict
import pandas as pd
from sklearn.preprocessing import StandardScaler
from pyod.models.ecod import ECOD
from pyod.models.iforest import IsolationForest
from pyod.models.hbos import HBOS


# -------------------- Models -----------------------------
class TabularModel:
    """ECOD, IsolationForest, or HBOS, trained on Table 1 of being data"""

    def __init__(self, model_name):
        self.model = {"ECOD": ECOD(), "IForest": IsolationForest(random_state=0), "HBOS": HBOS()}[model_name]

    def fit(self, X):
        self.scaler = StandardScaler().fit(X)
        self.model.fit(self.scaler.transform(X))
        return self

    def score(self, X):
        Z = self.scaler.transform(X)
        return pd.Series([self.model.decision_function(Z[i:i + 1])[0] for i in range(len(Z))], index=X.index)

class MarkovModel:
    """
    learn which step follow which step, from the seqnuce data from Table 2,

    """
    def fit(self, sequences):
        self.counting_next = defaultdict(Counter) # counting for event (a, b) how many times event a get followed by event b

        for setp in sequences.values():
            for a, b in zip(["START"] + setp, setp + ["END"]):# add START and END in two list then count which one follow which
                self.counting_next[a][b] += 1                 # ["START", Login,   DoLogin,  Transfer]
                                                              # ["Login", DoLoing, Transfer, END]
        self.num_steps = len({event for seq in sequences.values() for event in seq}) + 1
        return self

    def surprise(self, a, b):
        seen = self.counting_next.get(a, Counter()) # what seen after a, if a is new then counter is empty
        probability = -math.log((seen[b] + 1) / (sum(seen.values()) + self.num_steps))
        return probability

    def score(self, sequences):
        scores = {}

        for sid, sequence in sequences.items():
            total_surprise = sum( # for each sequnce calcalute the superise then take sum
                self.surprise(a, b)
                for a, b in zip(["START"] + sequence, sequence + ["END"])
            )

            scores[sid] = total_surprise / (len(sequence) + 1)

        return pd.Series(scores)

# ------------- baseline ---------------------
class ZScoreBaseline:
    """
    Simple statical model as our "dummy" baseline.
    ZScore:
    How many standrad deviation is the session most unsual feature away from the being averge?
    """

    def fit(self, X):
        self.mean, self.std = X.mean(), X.std()
        return self
    def score(self, X):
        diff = (X - self.mean()).abs()
        z = diff / self.std.where(self.std > 0)
        z = z.fillna((diff > 0) * 1000.0) # feature with std == 0 get z = nan, so if they are different 
                                          # in the new X, fill nan with 1000
        return z.max(axis = 1) # maximum z score