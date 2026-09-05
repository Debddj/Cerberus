import math

import numpy as np


class SequenceTransformerScorer:
    """
    Lightweight Sequence Neural Autoencoder for detecting anomalous tool chains.
    Learns dense representations of tool transitions and flags high reconstruction error.
    """

    def __init__(self, embedding_dim: int = 16, hidden_dim: int = 32, max_vocab: int = 64):
        self.embedding_dim = embedding_dim
        self.hidden_dim = hidden_dim
        self.max_vocab = max_vocab
        self.vocab: dict[str, int] = {}
        self.inv_vocab: dict[int, str] = {}
        self.is_fitted = False

        # Weight matrices
        self.rng = np.random.default_rng(42)
        self.W_embed = self.rng.normal(0.0, 0.1, size=(max_vocab, embedding_dim))
        self.W_enc = self.rng.normal(0.0, 0.1, size=(embedding_dim, hidden_dim))
        self.W_dec = self.rng.normal(0.0, 0.1, size=(hidden_dim, embedding_dim))
        self.baseline_reconstruction_error = 0.5

    def _get_token_id(self, tool_name: str) -> int:
        if tool_name not in self.vocab:
            if len(self.vocab) < self.max_vocab:
                idx = len(self.vocab)
                self.vocab[tool_name] = idx
                self.inv_vocab[idx] = tool_name
            else:
                return 0
        return self.vocab[tool_name]

    def fit(self, sequences: list[list[str]], epochs: int = 10):
        if not sequences:
            return

        # Build vocabulary
        for seq in sequences:
            for tool in seq:
                self._get_token_id(tool)

        # Train simple autoencoder projection on sequence pairs/n-grams
        errors = []
        for seq in sequences:
            for i in range(len(seq) - 1):
                t1, t2 = seq[i], seq[i + 1]
                idx1 = self._get_token_id(t1)
                idx2 = self._get_token_id(t2)

                x = self.W_embed[idx1]
                target = self.W_embed[idx2]

                # Forward: embed -> hidden -> decode
                h = np.tanh(x @ self.W_enc)
                recon = h @ self.W_dec

                diff = recon - target
                err = float(np.mean(diff**2))
                errors.append(err)

                # Hebbian / gradient descent nudge
                grad_dec = np.outer(h, diff)
                grad_enc = np.outer(x, (diff @ self.W_dec.T) * (1 - h**2))
                self.W_dec -= 0.05 * grad_dec
                self.W_enc -= 0.05 * grad_enc

        if errors:
            self.baseline_reconstruction_error = max(0.01, float(np.mean(errors)))
        self.is_fitted = True

    def score(self, tool_sequence: list[str]) -> tuple[float, list[str]]:
        if not tool_sequence or len(tool_sequence) < 2:
            return 0.0, []

        total_err = 0.0
        pairs_count = 0

        for i in range(len(tool_sequence) - 1):
            t1, t2 = tool_sequence[i], tool_sequence[i + 1]
            if t1 not in self.vocab or t2 not in self.vocab:
                # Novel token encountered
                total_err += 3.0 * self.baseline_reconstruction_error
                pairs_count += 1
                continue

            idx1 = self.vocab[t1]
            idx2 = self.vocab[t2]
            x = self.W_embed[idx1]
            target = self.W_embed[idx2]

            h = np.tanh(x @ self.W_enc)
            recon = h @ self.W_dec
            diff = recon - target
            err = float(np.mean(diff**2))
            total_err += err
            pairs_count += 1

        avg_err = total_err / max(1, pairs_count)
        # Ratio over baseline
        ratio = avg_err / max(1e-4, self.baseline_reconstruction_error)

        # Sigmoid normalize
        normalized_score = float(1.0 / (1.0 + math.exp(-0.8 * (ratio - 2.0))))
        normalized_score = round(min(1.0, max(0.0, normalized_score)), 3)

        factors = []
        if normalized_score > 0.65:
            factors.append(
                f"Neural Sequence Anomaly: Autoencoder reconstruction loss {ratio:.2f}x above baseline"
            )

        return normalized_score, factors
