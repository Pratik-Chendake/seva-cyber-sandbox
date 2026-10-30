"""
Custom Neural Network Classifier with Randomly Initialized Weights.
Part of Seva Cyber Sandbox (Phase 3).

DESIGN SPECIFICATION:
1. Strict ₹0 Budget & Offline Local CPU Execution:
   - Built entirely on NumPy without external cloud APIs, pretrained weights,
     or heavy deep-learning frameworks.
2. Architecture:
   - Multi-Layer Perceptron (MLP) over deterministic character n-gram feature hashing.
   - Input layer: D-dimensional hashed character n-grams (3-gram to 5-gram) with sign hashing
     and L2 normalization.
   - Hidden Layer 1: H1 units, He-normal random initialization, LeakyReLU activation, Dropout.
   - Hidden Layer 2: H2 units, He-normal random initialization, LeakyReLU activation, Dropout.
   - Output Layer: 3 logits (phishing, legitimate, protective_advisory), Xavier-uniform initialization.
   - Numerically stable Softmax and Categorical Cross-Entropy with L2 regularization.
   - Adam optimizer (adaptive moment estimation) implemented in NumPy.
3. Random Initialization Guarantee:
   - Every trainable weight and bias parameter is initialized randomly using a configurable seed.
   - Zero pretrained weights, foundation models, embeddings, or external vocabularies are used.
4. Security & Serialization:
   - Model weights saved strictly in safe NumPy .npz format (allow_pickle=False).
   - Accompanying JSON metadata records configuration, seed, dataset version, and class mapping.
   - Safe inference: handles empty, malformed, and non-string inputs gracefully.
"""

from collections import Counter
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

# Label to class index mapping (fixed taxonomy)
LABEL_TO_IDX = {
    "phishing": 0,
    "legitimate": 1,
    "protective_advisory": 2,
}
IDX_TO_LABEL = {v: k for k, v in LABEL_TO_IDX.items()}
NUM_CLASSES = 3
MODEL_VERSION = "custom-mlp-v1.0.0"


class CharacterNGramHasher:
    """
    Deterministic character n-gram feature hasher.
    Extracts character subwords (min_n to max_n) and maps them into a fixed D-dimensional
    sparse representation using the hashing trick with independent sign hashing and L2 normalization.
    """

    def __init__(self, num_features: int = 1024, min_n: int = 3, max_n: int = 5):
        self.num_features = int(num_features)
        self.min_n = int(min_n)
        self.max_n = int(max_n)

    def _hash_ngram(self, ngram: str) -> Tuple[int, float]:
        """Returns (bucket_index, sign) deterministically using hashlib md5."""
        digest = hashlib.md5(ngram.encode("utf-8")).digest()
        idx = int.from_bytes(digest[:4], "little") % self.num_features
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        return idx, sign

    def transform_text(self, text: str) -> np.ndarray:
        """Transforms a single text string into a normalized D-dimensional float32 vector."""
        vec = np.zeros(self.num_features, dtype=np.float32)
        if not text or not isinstance(text, str):
            return vec

        cleaned = text.strip().lower()
        if not cleaned:
            return vec

        # Pad with boundary markers for word boundary awareness
        padded = f"^{cleaned}$"
        length = len(padded)
        count = 0

        for n in range(self.min_n, min(self.max_n + 1, length + 1)):
            for i in range(length - n + 1):
                ngram = padded[i : i + n]
                idx, sign = self._hash_ngram(ngram)
                vec[idx] += sign
                count += 1

        # L2 normalize
        norm = np.linalg.norm(vec)
        if norm > 1e-8:
            vec /= norm

        return vec

    def transform_batch(self, texts: List[str]) -> np.ndarray:
        """Transforms a list of texts into a (B, D) float32 matrix."""
        b = len(texts)
        mat = np.zeros((b, self.num_features), dtype=np.float32)
        for i, t in enumerate(texts):
            mat[i] = self.transform_text(t)
        return mat


class CustomNeuralClassifier:
    """
    Three-class Feed-Forward Neural Network trained with Adam optimizer from randomly
    initialized weights.
    """

    def __init__(
        self,
        input_dim: int = 1024,
        hidden_dim1: int = 64,
        hidden_dim2: int = 32,
        num_classes: int = NUM_CLASSES,
        learning_rate: float = 0.005,
        weight_decay: float = 1e-4,
        dropout_rate: float = 0.2,
        leaky_relu_alpha: float = 0.01,
        seed: int = 42,
    ):
        self.input_dim = input_dim
        self.hidden_dim1 = hidden_dim1
        self.hidden_dim2 = hidden_dim2
        self.num_classes = num_classes
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.dropout_rate = dropout_rate
        self.leaky_relu_alpha = leaky_relu_alpha
        self.seed = seed
        self.model_version = MODEL_VERSION

        self.hasher = CharacterNGramHasher(num_features=input_dim)
        self.rng = np.random.RandomState(seed)

        # Initialize parameters randomly
        self._init_weights()

        # Optimizer state (Adam)
        self._init_adam()

        # Cache for backprop
        self._cache: Dict[str, Any] = {}

    def _init_weights(self) -> None:
        """
        Randomly initializes all trainable parameters using He (Kaiming) normal
        and Xavier (Glorot) uniform distributions.
        """
        # Layer 1: He normal
        std1 = np.sqrt(2.0 / self.input_dim)
        self.W1 = self.rng.normal(0.0, std1, (self.input_dim, self.hidden_dim1)).astype(np.float32)
        self.b1 = np.zeros((1, self.hidden_dim1), dtype=np.float32)

        # Layer 2: He normal
        std2 = np.sqrt(2.0 / self.hidden_dim1)
        self.W2 = self.rng.normal(0.0, std2, (self.hidden_dim1, self.hidden_dim2)).astype(np.float32)
        self.b2 = np.zeros((1, self.hidden_dim2), dtype=np.float32)

        # Layer 3: Xavier uniform
        limit3 = np.sqrt(6.0 / (self.hidden_dim2 + self.num_classes))
        self.W3 = self.rng.uniform(-limit3, limit3, (self.hidden_dim2, self.num_classes)).astype(np.float32)
        self.b3 = np.zeros((1, self.num_classes), dtype=np.float32)

    def _init_adam(self) -> None:
        """Initializes first and second moment vectors for the Adam optimizer."""
        self.t = 0
        self.m_W1 = np.zeros_like(self.W1)
        self.v_W1 = np.zeros_like(self.W1)
        self.m_b1 = np.zeros_like(self.b1)
        self.v_b1 = np.zeros_like(self.b1)

        self.m_W2 = np.zeros_like(self.W2)
        self.v_W2 = np.zeros_like(self.W2)
        self.m_b2 = np.zeros_like(self.b2)
        self.v_b2 = np.zeros_like(self.b2)

        self.m_W3 = np.zeros_like(self.W3)
        self.v_W3 = np.zeros_like(self.W3)
        self.m_b3 = np.zeros_like(self.b3)
        self.v_b3 = np.zeros_like(self.b3)

    def _leaky_relu(self, z: np.ndarray) -> np.ndarray:
        return np.where(z > 0, z, z * self.leaky_relu_alpha)

    def _leaky_relu_grad(self, z: np.ndarray) -> np.ndarray:
        return np.where(z > 0, 1.0, self.leaky_relu_alpha)

    @staticmethod
    def _softmax(logits: np.ndarray) -> np.ndarray:
        """Numerically stable softmax computation."""
        shifted = logits - np.max(logits, axis=-1, keepdims=True)
        exp_vals = np.exp(shifted)
        return exp_vals / np.sum(exp_vals, axis=-1, keepdims=True)

    def forward(self, X: np.ndarray, training: bool = False) -> np.ndarray:
        """
        Executes forward propagation through the 3 layers.
        Returns class probability estimates (B, num_classes).
        """
        # Layer 1
        Z1 = np.dot(X, self.W1) + self.b1
        A1 = self._leaky_relu(Z1)

        M1 = None
        if training and self.dropout_rate > 0.0:
            M1 = (self.rng.uniform(0.0, 1.0, A1.shape) >= self.dropout_rate).astype(np.float32)
            A1_dropped = (A1 * M1) / (1.0 - self.dropout_rate)
        else:
            A1_dropped = A1

        # Layer 2
        Z2 = np.dot(A1_dropped, self.W2) + self.b2
        A2 = self._leaky_relu(Z2)

        M2 = None
        if training and self.dropout_rate > 0.0:
            M2 = (self.rng.uniform(0.0, 1.0, A2.shape) >= self.dropout_rate).astype(np.float32)
            A2_dropped = (A2 * M2) / (1.0 - self.dropout_rate)
        else:
            A2_dropped = A2

        # Output Layer
        Z3 = np.dot(A2_dropped, self.W3) + self.b3
        probs = self._softmax(Z3)

        if training:
            self._cache = {
                "X": X,
                "Z1": Z1,
                "A1": A1,
                "M1": M1,
                "A1_dropped": A1_dropped,
                "Z2": Z2,
                "A2": A2,
                "M2": M2,
                "A2_dropped": A2_dropped,
                "Z3": Z3,
                "probs": probs,
            }

        return probs

    def compute_loss(
        self,
        probs: np.ndarray,
        Y_onehot: np.ndarray,
        class_weights: Optional[np.ndarray] = None,
    ) -> float:
        """
        Computes Categorical Cross-Entropy loss with optional class weighting
        and L2 parameter regularization.
        """
        eps = 1e-9
        clipped = np.clip(probs, eps, 1.0 - eps)
        log_probs = np.log(clipped)

        if class_weights is not None:
            weighted_ce = -np.sum(Y_onehot * log_probs * class_weights, axis=-1)
            data_loss = float(np.mean(weighted_ce))
        else:
            data_loss = float(-np.mean(np.sum(Y_onehot * log_probs, axis=-1)))

        # L2 Regularization penalty
        l2_reg = 0.5 * self.weight_decay * (
            np.sum(self.W1 ** 2) + np.sum(self.W2 ** 2) + np.sum(self.W3 ** 2)
        )
        return data_loss + float(l2_reg)

    def backward(
        self,
        Y_onehot: np.ndarray,
        class_weights: Optional[np.ndarray] = None,
    ) -> Dict[str, np.ndarray]:
        """
        Executes backpropagation and calculates analytical parameter gradients.
        """
        batch_size = Y_onehot.shape[0]
        probs = self._cache["probs"]
        A2_dropped = self._cache["A2_dropped"]
        A1_dropped = self._cache["A1_dropped"]
        Z2 = self._cache["Z2"]
        Z1 = self._cache["Z1"]
        M2 = self._cache["M2"]
        M1 = self._cache["M1"]
        X = self._cache["X"]

        # Output error
        if class_weights is not None:
            dZ3 = (probs - Y_onehot) * class_weights / batch_size
        else:
            dZ3 = (probs - Y_onehot) / batch_size

        # Layer 3 gradients
        dW3 = np.dot(A2_dropped.T, dZ3) + self.weight_decay * self.W3
        db3 = np.sum(dZ3, axis=0, keepdims=True)

        # Backprop through Layer 2
        dA2_dropped = np.dot(dZ3, self.W3.T)
        if M2 is not None and self.dropout_rate > 0.0:
            dA2 = (dA2_dropped * M2) / (1.0 - self.dropout_rate)
        else:
            dA2 = dA2_dropped

        dZ2 = dA2 * self._leaky_relu_grad(Z2)
        dW2 = np.dot(A1_dropped.T, dZ2) + self.weight_decay * self.W2
        db2 = np.sum(dZ2, axis=0, keepdims=True)

        # Backprop through Layer 1
        dA1_dropped = np.dot(dZ2, self.W2.T)
        if M1 is not None and self.dropout_rate > 0.0:
            dA1 = (dA1_dropped * M1) / (1.0 - self.dropout_rate)
        else:
            dA1 = dA1_dropped

        dZ1 = dA1 * self._leaky_relu_grad(Z1)
        dW1 = np.dot(X.T, dZ1) + self.weight_decay * self.W1
        db1 = np.sum(dZ1, axis=0, keepdims=True)

        return {
            "dW1": dW1,
            "db1": db1,
            "dW2": dW2,
            "db2": db2,
            "dW3": dW3,
            "db3": db3,
        }

    def update_parameters(
        self,
        grads: Dict[str, np.ndarray],
        beta1: float = 0.9,
        beta2: float = 0.999,
        eps: float = 1e-8,
    ) -> None:
        """Applies Adam optimizer updates to all parameters."""
        self.t += 1
        lr = self.learning_rate
        t = self.t

        for param_name in ["W1", "b1", "W2", "b2", "W3", "b3"]:
            theta = getattr(self, param_name)
            grad = grads[f"d{param_name}"]
            m = getattr(self, f"m_{param_name}")
            v = getattr(self, f"v_{param_name}")

            m = beta1 * m + (1.0 - beta1) * grad
            v = beta2 * v + (1.0 - beta2) * (grad ** 2)

            m_hat = m / (1.0 - beta1 ** t)
            v_hat = v / (1.0 - beta2 ** t)

            theta_new = theta - lr * m_hat / (np.sqrt(v_hat) + eps)

            setattr(self, param_name, theta_new)
            setattr(self, f"m_{param_name}", m)
            setattr(self, f"v_{param_name}", v)

    def fit_batch(
        self,
        X_batch: np.ndarray,
        Y_batch: np.ndarray,
        class_weights: Optional[np.ndarray] = None,
    ) -> float:
        """Executes a single forward-backward-update step on a mini-batch."""
        probs = self.forward(X_batch, training=True)
        loss = self.compute_loss(probs, Y_batch, class_weights=class_weights)
        grads = self.backward(Y_batch, class_weights=class_weights)
        self.update_parameters(grads)
        return loss

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predicts class probabilities for input matrix X."""
        return self.forward(X, training=False)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predicts class indices (0, 1, 2) for input matrix X."""
        probs = self.predict_proba(X)
        return np.argmax(probs, axis=-1)

    def predict_one(self, text: str, hasher: Optional[CharacterNGramHasher] = None) -> Dict[str, Any]:
        """
        Public inference API for a single text input string.
        Safe against empty, whitespace, and malformed inputs.
        """
        h = hasher or self.hasher
        if not isinstance(text, str) or not text.strip():
            # Graceful default for empty input: return ambiguous/uninformative distribution
            return {
                "predicted_label": "legitimate",
                "predicted_index": 1,
                "confidence": 0.3333,
                "probabilities": {
                    "phishing": 0.3333,
                    "legitimate": 0.3334,
                    "protective_advisory": 0.3333,
                },
                "model_version": self.model_version,
                "is_experimental": True,
                "note": "Input is empty or whitespace. Returning default neutral distribution.",
            }

        vec = h.transform_text(text)
        X = np.expand_dims(vec, axis=0)
        probs = self.predict_proba(X)[0]
        pred_idx = int(np.argmax(probs))
        pred_label = IDX_TO_LABEL[pred_idx]
        conf = float(probs[pred_idx])

        return {
            "predicted_label": pred_label,
            "predicted_index": pred_idx,
            "confidence": round(conf, 4),
            "probabilities": {
                "phishing": round(float(probs[0]), 4),
                "legitimate": round(float(probs[1]), 4),
                "protective_advisory": round(float(probs[2]), 4),
            },
            "model_version": self.model_version,
            "is_experimental": True,
            "note": "Experimental prototype model trained from random initialization. Probabilities are uncalibrated softmax estimates.",
        }

    def save_checkpoint(self, checkpoint_dir: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Safely serializes weights using NumPy .npz (allow_pickle=False) and saves JSON metadata.
        """
        os.makedirs(checkpoint_dir, exist_ok=True)
        weights_file = os.path.join(checkpoint_dir, "model_weights.npz")
        meta_file = os.path.join(checkpoint_dir, "model_metadata.json")

        # Save weights safely without pickle
        np.savez_compressed(
            weights_file,
            W1=self.W1,
            b1=self.b1,
            W2=self.W2,
            b2=self.b2,
            W3=self.W3,
            b3=self.b3,
        )

        full_meta = {
            "model_version": self.model_version,
            "input_dim": self.input_dim,
            "hidden_dim1": self.hidden_dim1,
            "hidden_dim2": self.hidden_dim2,
            "num_classes": self.num_classes,
            "learning_rate": self.learning_rate,
            "weight_decay": self.weight_decay,
            "dropout_rate": self.dropout_rate,
            "leaky_relu_alpha": self.leaky_relu_alpha,
            "seed": self.seed,
            "label_to_index": LABEL_TO_IDX,
            "hasher": {
                "num_features": self.hasher.num_features,
                "min_n": self.hasher.min_n,
                "max_n": self.hasher.max_n,
            },
            "architecture": "MLP (3-layer feedforward) over deterministic character n-gram hashing",
            "weight_initialization": "Layer 1: He normal, Layer 2: He normal, Layer 3: Xavier uniform",
            "optimizer": "Adam (NumPy implementation)",
            "is_experimental": True,
        }
        if metadata:
            full_meta["training_metadata"] = metadata

        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(full_meta, f, indent=2, ensure_ascii=False)

        return checkpoint_dir

    @classmethod
    def load_checkpoint(cls, checkpoint_dir: str) -> "CustomNeuralClassifier":
        """
        Safely loads a model checkpoint from safe .npz weights and JSON metadata.
        Validates tensor dimensions and keys.
        """
        weights_file = os.path.join(checkpoint_dir, "model_weights.npz")
        meta_file = os.path.join(checkpoint_dir, "model_metadata.json")

        if not os.path.exists(weights_file):
            raise FileNotFoundError(f"Missing weights file at {weights_file}")
        if not os.path.exists(meta_file):
            raise FileNotFoundError(f"Missing metadata file at {meta_file}")

        with open(meta_file, "r", encoding="utf-8") as f:
            meta = json.load(f)

        model = cls(
            input_dim=meta["input_dim"],
            hidden_dim1=meta["hidden_dim1"],
            hidden_dim2=meta["hidden_dim2"],
            num_classes=meta["num_classes"],
            learning_rate=meta["learning_rate"],
            weight_decay=meta["weight_decay"],
            dropout_rate=meta["dropout_rate"],
            leaky_relu_alpha=meta["leaky_relu_alpha"],
            seed=meta["seed"],
        )

        with np.load(weights_file, allow_pickle=False) as data:
            expected_keys = {"W1", "b1", "W2", "b2", "W3", "b3"}
            if not expected_keys.issubset(set(data.files)):
                raise ValueError(f"Corrupt checkpoint: missing keys {expected_keys - set(data.files)}")

            model.W1 = data["W1"].astype(np.float32)
            model.b1 = data["b1"].astype(np.float32)
            model.W2 = data["W2"].astype(np.float32)
            model.b2 = data["b2"].astype(np.float32)
            model.W3 = data["W3"].astype(np.float32)
            model.b3 = data["b3"].astype(np.float32)

        # Validate tensor shapes
        assert model.W1.shape == (model.input_dim, model.hidden_dim1), f"W1 shape mismatch: {model.W1.shape}"
        assert model.b1.shape == (1, model.hidden_dim1), f"b1 shape mismatch: {model.b1.shape}"
        assert model.W2.shape == (model.hidden_dim1, model.hidden_dim2), f"W2 shape mismatch: {model.W2.shape}"
        assert model.b2.shape == (1, model.hidden_dim2), f"b2 shape mismatch: {model.b2.shape}"
        assert model.W3.shape == (model.hidden_dim2, model.num_classes), f"W3 shape mismatch: {model.W3.shape}"
        assert model.b3.shape == (1, model.num_classes), f"b3 shape mismatch: {model.b3.shape}"

        model.model_version = meta.get("model_version", MODEL_VERSION)

        return model


def load_custom_model(
    checkpoint_dir: str,
) -> Tuple[CustomNeuralClassifier, CharacterNGramHasher, Dict[str, Any]]:
    """
    Convenience wrapper to load a custom neural model checkpoint, its character hasher,
    and associated training metadata.
    """
    model = CustomNeuralClassifier.load_checkpoint(checkpoint_dir)
    meta_path = os.path.join(checkpoint_dir, "model_metadata.json")
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    return model, model.hasher, meta

