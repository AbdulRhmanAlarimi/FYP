import math, json
from collections import Counter, defaultdict
import pandas as pd
import torch
from torch import nn
from torch.nn.utils.rnn import pad_sequence
from sklearn.preprocessing import StandardScaler
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest
from pyod.models.auto_encoder import AutoEncoder


# -------------------- Models -----------------------------
class TabularModel:
    """ECOD, IsolationForest, or AutoEncoder, trained on Table 1 of being data"""

    def __init__(self, model_name):
        models = {"ECOD": lambda: ECOD(),
                  "IForest": lambda: IForest(random_state=0),
                  "AutoEncoder": lambda: AutoEncoder(random_state=0, preprocessing=False, verbose=0)}
        self.model = models[model_name]()

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
    order=1 looks at the previous step (shipped to the phone), order=2 at the previous two steps (report only)
    """
    def __init__(self, order=1):
        self.order = order

    def pairs(self, sequence):
        """(previous step(s), next step) for every step, with START before and END after
        order 1: ("START", Login), ("Login", DoLogin) ...  order 2: ("START > START", Login), ("START > Login", DoLogin) ..."""
        steps = ["START"] * self.order + sequence + ["END"]
        for i in range(self.order, len(steps)):
            yield " > ".join(steps[i - self.order:i]), steps[i]

    def fit(self, sequences):
        self.counting_next = defaultdict(Counter) # counting for event (a, b) how many times event a get followed by event b

        for setp in sequences.values():
            for a, b in self.pairs(setp):
                self.counting_next[a][b] += 1

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
                for a, b in self.pairs(sequence)
            )

            scores[sid] = total_surprise / (len(sequence) + 1)

        return pd.Series(scores)

    def export(self, path, threshold):
        """save what the phone needs: the surprise of each step pair seen in training,
        the surprise of a never-seen pair after each step, and the alarm threshold"""

        model = {"threshold": threshold,
                 "unseen_step": math.log(self.num_steps),     # previous step (events) never seen in training 
                 "unseen_after": {a: math.log(sum(c.values()) + self.num_steps) for a, c in self.counting_next.items()},
                 "pairs": {a: {b: self.surprise(a, b) for b in c} for a, c in self.counting_next.items()}}
        
        with open(path, "w") as f:
            json.dump(model, f, indent=1)

# ------------- deep sequence model (report only, not shipped to the phone) ---------------------
class LSTMModel:
    """
    same idea as the Markov model, but an LSTM reads the whole session so far to predict the next step.
    score = average surprise (-log probability of the real next step) per step, like MarkovModel.
    settings are fixed in advance (no tuning on the test set), seed fixed for reproducible results
    """
    def __init__(self, embed=32, hidden=64, epochs=20, lr=0.005, batch=32, seed=0):
        self.embed, self.hidden, self.epochs, self.lr, self.batch, self.seed = embed, hidden, epochs, lr, batch, seed

    def encode(self, sequence):
        """steps to numbers: 0 = padding, 1 = step never seen in training"""
        return torch.tensor([self.vocab.get(s, 1) for s in ["START"] + sequence + ["END"]])

    def surprise(self, x):
        """-log probability of each real next step (0 at padding)"""
        h, _ = self.net["lstm"](self.net["embed"](x[:, :-1]))
        logits = self.net["out"](h)
        return nn.functional.cross_entropy(logits.transpose(1, 2), x[:, 1:], ignore_index=0, reduction="none")

    def fit(self, sequences):
        torch.manual_seed(self.seed)
        steps = sorted({s for seq in sequences.values() for s in seq})
        self.vocab = {s: i + 2 for i, s in enumerate(["START", "END"] + steps)}
        size = len(self.vocab) + 2
        self.net = nn.ModuleDict({"embed": nn.Embedding(size, self.embed, padding_idx=0),
                                  "lstm": nn.LSTM(self.embed, self.hidden, batch_first=True),
                                  "out": nn.Linear(self.hidden, size)})
        optimizer = torch.optim.Adam(self.net.parameters(), lr=self.lr)

        data = [self.encode(s) for s in sequences.values()]
        for _ in range(self.epochs):
            order = torch.randperm(len(data))
            for i in range(0, len(data), self.batch):
                x = pad_sequence([data[j] for j in order[i:i + self.batch]], batch_first=True)
                surprise = self.surprise(x)
                loss = surprise.sum() / (x[:, 1:] != 0).sum()    # average over real steps
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
        return self

    def score(self, sequences):
        with torch.no_grad():
            x = pad_sequence([self.encode(s) for s in sequences.values()], batch_first=True)
            per_session = self.surprise(x).sum(1) / (x[:, 1:] != 0).sum(1)
        return pd.Series(per_session.numpy(), index=list(sequences))

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
        diff = (X - self.mean).abs()
        z = diff / self.std.where(self.std > 0)
        z = z.fillna((diff > 0) * 1000.0) # feature with std == 0 get z = nan, so if they are different 
                                          # in the new X, fill nan with 1000
        return z.max(axis = 1) # maximum z score