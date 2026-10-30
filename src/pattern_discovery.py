"""
Offline Autonomous Fraud Pattern Discovery Engine for Seva Cyber Sandbox (Phase 6.2).

PRIVACY, ETHICS & SAFETY GOVERNANCE:
1. Strict ₹0 Budget & 100% Local Execution:
   - Uses Python standard library and local SQLite persistence only. Zero paid APIs,
     cloud services, pretrained weights, or external threat-intelligence queries.
2. Zero Raw Content Retained or Discovered:
   - Evaluates only abstract 1024-dimensional character n-gram feature vectors and
     passive structural characteristics (e.g. IP host, punycode, URL shorteners).
   - Raw chat messages, sanitized texts, and raw URLs are NEVER stored or emitted in hypotheses.
3. Cryptographic Feature Irreversibility:
   - Character n-gram hashing into 1024 buckets is non-reversible. This module discovers
     statistical associations over opaque bucket indices, never inventing fake words.
4. Autonomous Discovery != Automatic Rule Activation:
   - Discovered patterns are hypotheses recorded in candidate catalogues.
   - Candidates start in 'draft' or 'needs_more_evidence'.
   - The engine CANNOT set 'approved_by_human'. Only an explicit human review can approve.
   - Approving a candidate NEVER automatically alters production scoring or detection rules.
5. Strict Provenance Separation:
   - Human-reviewed local cases and synthetic corpus data are tracked under separate provenances.
   - Synthetic discoveries are explicitly labeled as synthetic demonstrations.
   - The locked evaluation dataset ('data/phishing_eval_dataset.json') is NEVER mined.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import math
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

# =============================================================================
# CONSTANTS & SCHEMAS
# =============================================================================

PATTERN_SCHEMA_VERSION = "1.0.0"
PATTERN_DISCOVERY_VERSION = "pattern-discovery-v1.0.0"
DEFAULT_CATALOG_DIR = os.path.join("models", "pattern_catalog")
AUDIT_LOG_FILENAME = "pattern_review_audit.jsonl"

VALID_LIFECYCLE_STATES = {
    "draft",
    "needs_more_evidence",
    "ready_for_human_review",
    "rejected",
    "approved_by_human",
}

VALID_PATTERN_TYPES = {
    "ngram_feature_association",
    "ngram_feature_pair",
    "structural_url_characteristic",
    "structural_ngram_hybrid",
}

VALID_CLASSES = {
    "phishing",
    "legitimate",
    "protective_advisory",
}

# Conservative Statistical Thresholds
MIN_SUPPORT_THRESHOLD = 3           # Minimum examples to create any hypothesis
REVIEW_READY_MIN_SUPPORT = 5        # Minimum examples to leave 'needs_more_evidence'
MIN_CONCENTRATION_THRESHOLD = 0.70  # At least 70% of occurrences must belong to dominant class
MIN_LIFT_THRESHOLD = 1.30           # Must be 1.3x more prevalent in dominant class than baseline
MIN_WILSON_LOWER_BOUND = 0.50       # 95% Wilson lower bound for concentration

# Strict privacy forbidden keys
FORBIDDEN_CANDIDATE_KEYS = {
    "text", "raw_text", "sanitized_text", "url", "raw_url",
    "phone", "aadhaar", "otp", "password", "case_id",
    "dedup_fingerprint", "notes", "reviewer_notes", "secret"
}


# =============================================================================
# EXCEPTIONS
# =============================================================================

class PatternDiscoveryError(Exception):
    """Base exception for pattern discovery errors."""
    pass


class PatternValidationError(PatternDiscoveryError):
    """Raised when candidate pattern data violates schema or privacy policies."""
    pass


class PatternCatalogError(PatternDiscoveryError):
    """Raised when catalog versioning, loading, or serialization fails."""
    pass


class PatternReviewError(PatternDiscoveryError):
    """Raised when an invalid lifecycle state transition or review operation is attempted."""
    pass


# =============================================================================
# MATHEMATICAL & STATISTICAL HELPERS
# =============================================================================

def get_utc_now_iso() -> str:
    """Returns current UTC ISO-8601 timestamp string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_candidate_id(prefix: str = "PAT-CAND") -> str:
    """Generates a collision-resistant candidate pattern identifier."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:8].upper()
    return f"{prefix}-{date_str}-{short_uuid}"


def compute_wilson_lower_bound(successes: int, total: int, z: float = 1.96) -> float:
    """
    Computes the Wilson score confidence interval lower bound for a binomial proportion.
    Penalizes small sample sizes rigorously (e.g. 3/3 yields ~0.438 lower bound,
    while 30/30 yields ~0.887 lower bound).
    """
    if total <= 0:
        return 0.0
    p_hat = successes / total
    denom = 1.0 + (z * z) / total
    centre = p_hat + (z * z) / (2.0 * total)
    spread = z * math.sqrt((p_hat * (1.0 - p_hat) / total) + (z * z) / (4.0 * total * total))
    lower = (centre - spread) / denom
    return max(0.0, min(1.0, round(lower, 4)))


def compute_feature_statistics(
    supporting_count: int,
    total_dataset_count: int,
    class_occurrences: Dict[str, int],
    dataset_class_totals: Dict[str, int],
) -> Dict[str, Any]:
    """
    Computes rigorous frequency and association statistics for a candidate feature.
    """
    if total_dataset_count <= 0 or supporting_count <= 0:
        return {}

    overall_prevalence = round(supporting_count / total_dataset_count, 4)

    # Determine dominant class
    dominant_class = max(class_occurrences, key=lambda c: class_occurrences[c])
    dom_count = class_occurrences.get(dominant_class, 0)
    dom_total = dataset_class_totals.get(dominant_class, 0)

    # Class concentration P(class | feature)
    concentration = round(dom_count / supporting_count, 4) if supporting_count > 0 else 0.0

    # Class prevalence / recall P(feature | class)
    class_prevalence = round(dom_count / dom_total, 4) if dom_total > 0 else 0.0

    # Lift = P(class | feature) / P(class)
    baseline_class_prob = dom_total / total_dataset_count if total_dataset_count > 0 else 0.0
    lift = round(concentration / baseline_class_prob, 4) if baseline_class_prob > 0 else 0.0

    # Wilson lower bound for dominant class concentration
    wilson_lb = compute_wilson_lower_bound(dom_count, supporting_count)

    # Laplace smoothed precision: (k + 1) / (N + C)
    num_classes = len(VALID_CLASSES)
    laplace_prec = round((dom_count + 1) / (supporting_count + num_classes), 4)

    return {
        "dominant_class": dominant_class,
        "support": supporting_count,
        "prevalence": overall_prevalence,
        "class_occurrences": class_occurrences,
        "class_concentration": concentration,
        "class_prevalence": class_prevalence,
        "lift": lift,
        "wilson_lower_bound": wilson_lb,
        "laplace_smoothed_precision": laplace_prec,
    }


# =============================================================================
# CANDIDATE PATTERN DATA CLASS
# =============================================================================

@dataclass
class CandidatePattern:
    """
    Structured representation of a discovered fraud or legitimacy pattern hypothesis.
    STRICT PRIVACY: Never contains raw text, raw URLs, reviewer notes, case IDs, or PII.
    """
    candidate_id: str
    pattern_schema_version: str
    discovery_timestamp_utc: str
    candidate_pattern_type: str
    opaque_feature_identifiers: List[str]
    target_class: str
    supporting_example_count: int
    total_dataset_examples: int
    class_distribution: Dict[str, int]
    statistical_evidence: Dict[str, Any]
    uncertainty_or_limitations: List[str]
    data_provenance: str
    algorithm_version: str
    lifecycle_state: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Validates that candidate pattern conforms strictly to schema and safety rules."""
        if not self.candidate_id or not isinstance(self.candidate_id, str):
            raise PatternValidationError("Candidate ID must be a non-empty string.")
        if self.pattern_schema_version != PATTERN_SCHEMA_VERSION:
            raise PatternValidationError(
                f"Unsupported pattern schema version '{self.pattern_schema_version}'; expected '{PATTERN_SCHEMA_VERSION}'."
            )
        if self.candidate_pattern_type not in VALID_PATTERN_TYPES:
            raise PatternValidationError(
                f"Invalid candidate pattern type '{self.candidate_pattern_type}'; valid: {VALID_PATTERN_TYPES}."
            )
        if self.target_class not in VALID_CLASSES:
            raise PatternValidationError(
                f"Invalid target class '{self.target_class}'; valid: {VALID_CLASSES}."
            )
        if self.lifecycle_state not in VALID_LIFECYCLE_STATES:
            raise PatternValidationError(
                f"Invalid lifecycle state '{self.lifecycle_state}'; valid: {VALID_LIFECYCLE_STATES}."
            )
        if not isinstance(self.opaque_feature_identifiers, list) or not self.opaque_feature_identifiers:
            raise PatternValidationError("opaque_feature_identifiers must be a non-empty list.")
        if self.supporting_example_count < 1:
            raise PatternValidationError("supporting_example_count must be at least 1.")

        # Validate that statistical_evidence does not contain non-finite numbers (NaN or Inf)
        if isinstance(self.statistical_evidence, dict):
            for k, v in self.statistical_evidence.items():
                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                    raise PatternValidationError(f"Statistical evidence field '{k}' has non-finite value ({v}).")

        # Privacy verification: forbidden keys check
        cand_dict = asdict(self)
        for key in FORBIDDEN_CANDIDATE_KEYS:
            if key in cand_dict or key in self.metadata:
                raise PatternValidationError(f"Forbidden sensitive key '{key}' leaked into candidate pattern.")

    def to_dict(self) -> Dict[str, Any]:
        """Returns validated dictionary representation."""
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CandidatePattern":
        """Reconstructs and validates a CandidatePattern from a dictionary."""
        if not isinstance(data, dict):
            raise PatternValidationError("Candidate pattern data must be a dictionary.")

        # Check for forbidden fields
        for key in FORBIDDEN_CANDIDATE_KEYS:
            if key in data:
                raise PatternValidationError(f"Malformed candidate contains forbidden key '{key}'.")

        instance = cls(
            candidate_id=data.get("candidate_id", ""),
            pattern_schema_version=data.get("pattern_schema_version", ""),
            discovery_timestamp_utc=data.get("discovery_timestamp_utc", ""),
            candidate_pattern_type=data.get("candidate_pattern_type", ""),
            opaque_feature_identifiers=data.get("opaque_feature_identifiers", []),
            target_class=data.get("target_class", ""),
            supporting_example_count=data.get("supporting_example_count", 0),
            total_dataset_examples=data.get("total_dataset_examples", 0),
            class_distribution=data.get("class_distribution", {}),
            statistical_evidence=data.get("statistical_evidence", {}),
            uncertainty_or_limitations=data.get("uncertainty_or_limitations", []),
            data_provenance=data.get("data_provenance", "unknown"),
            algorithm_version=data.get("algorithm_version", ""),
            lifecycle_state=data.get("lifecycle_state", "draft"),
            metadata=data.get("metadata", {}),
        )
        instance.validate()
        return instance


# =============================================================================
# FEATURE ASSOCIATION MINERS
# =============================================================================

def standard_limitations_for_feature(
    pattern_type: str,
    support: int,
    wilson_lb: float,
    provenance: str,
) -> List[str]:
    """Assembles mandatory honest limitations and uncertainty statements."""
    limits = [
        "NON_REVERSIBLE_FEATURE_HASHING: Derived from 1024-dimensional character n-gram hashing. "
        "Original words or phrases CANNOT be recovered.",
        "HASH_COLLISION_POTENTIAL: Multiple distinct character subwords may hash to the same bucket index.",
        "NOT_A_DETECTION_RULE: Statistical candidate hypothesis for human analyst review only; "
        "not an active detection or filtering rule.",
    ]
    if "synthetic" in provenance.lower():
        limits.append(
            "SYNTHETIC_EVIDENCE_SOURCE: Derived from synthetic template corpus. "
            "Must NOT be cited as confirmed real-world fraud pattern."
        )
    else:
        limits.append(
            "LOCAL_UNAUTHENTICATED_PROVENANCE: Derived from local unauthenticated operator reviews. "
            "Not certified ground truth from an external cybersecurity agency."
        )

    if support < REVIEW_READY_MIN_SUPPORT:
        limits.append(
            f"SMALL_SAMPLE_SIZE: Only {support} supporting examples observed. "
            f"Statistical significance is preliminary and requires more evidence."
        )
    if wilson_lb < 0.60:
        limits.append(
            f"HIGH_UNCERTAINTY: Wilson 95% confidence lower bound is {wilson_lb:.2f} (< 0.60)."
        )

    return limits


def mine_ngram_feature_associations(
    records: List[Dict[str, Any]],
    provenance: str,
    min_support: int = MIN_SUPPORT_THRESHOLD,
    activation_threshold: float = 0.05,
) -> List[CandidatePattern]:
    """
    Mines individual prominent character n-gram hash indices strongly correlated with specific classes.
    """
    total_records = len(records)
    if total_records < min_support:
        return []

    # Count overall class totals
    class_totals: Dict[str, int] = {c: 0 for c in VALID_CLASSES}
    for r in records:
        lbl = r.get("label")
        if lbl in class_totals:
            class_totals[lbl] += 1

    # Map each feature index to occurrences by class
    # feature_idx -> { 'phishing': count, 'legitimate': count, 'protective_advisory': count }
    feature_class_counts: Dict[int, Dict[str, int]] = {}

    for r in records:
        vec = r.get("feature_vector")
        lbl = r.get("label")
        if not isinstance(vec, list) or len(vec) != 1024 or lbl not in VALID_CLASSES:
            continue

        for idx, val in enumerate(vec):
            if abs(val) >= activation_threshold:
                if idx not in feature_class_counts:
                    feature_class_counts[idx] = {c: 0 for c in VALID_CLASSES}
                feature_class_counts[idx][lbl] += 1

    candidates: List[CandidatePattern] = []
    now_utc = get_utc_now_iso()

    for idx, counts in feature_class_counts.items():
        support = sum(counts.values())
        if support < min_support:
            continue

        stats = compute_feature_statistics(
            supporting_count=support,
            total_dataset_count=total_records,
            class_occurrences=counts,
            dataset_class_totals=class_totals,
        )

        conc = stats.get("class_concentration", 0.0)
        lift = stats.get("lift", 0.0)
        wilson_lb = stats.get("wilson_lower_bound", 0.0)
        dom_class = stats.get("dominant_class")

        # Eligibility threshold for candidate generation
        if conc >= MIN_CONCENTRATION_THRESHOLD and lift >= MIN_LIFT_THRESHOLD:
            # Conservative state assignment: small samples or high uncertainty stay in needs_more_evidence
            if support < REVIEW_READY_MIN_SUPPORT or wilson_lb < MIN_WILSON_LOWER_BOUND:
                state = "needs_more_evidence"
            else:
                state = "draft"

            limitations = standard_limitations_for_feature(
                pattern_type="ngram_feature_association",
                support=support,
                wilson_lb=wilson_lb,
                provenance=provenance,
            )

            cand = CandidatePattern(
                candidate_id=generate_candidate_id("PAT-NGRAM"),
                pattern_schema_version=PATTERN_SCHEMA_VERSION,
                discovery_timestamp_utc=now_utc,
                candidate_pattern_type="ngram_feature_association",
                opaque_feature_identifiers=[f"feature_idx_{idx}"],
                target_class=dom_class,
                supporting_example_count=support,
                total_dataset_examples=total_records,
                class_distribution=counts,
                statistical_evidence=stats,
                uncertainty_or_limitations=limitations,
                data_provenance=provenance,
                algorithm_version=PATTERN_DISCOVERY_VERSION,
                lifecycle_state=state,
                metadata={"feature_dim": 1024, "activation_threshold": activation_threshold},
            )
            candidates.append(cand)

    return candidates


def mine_ngram_feature_pairs(
    records: List[Dict[str, Any]],
    provenance: str,
    min_support: int = MIN_SUPPORT_THRESHOLD,
    activation_threshold: float = 0.05,
    top_k_candidates: int = 25,
) -> List[CandidatePattern]:
    """
    Mines co-occurring character n-gram feature index pairs that exhibit enhanced discrimination.
    Restricts search to top prominent single features to prevent combinatorial explosion.
    """
    total_records = len(records)
    if total_records < min_support:
        return []

    # First, find prominent single features
    singles = mine_ngram_feature_associations(
        records=records,
        provenance=provenance,
        min_support=min_support,
        activation_threshold=activation_threshold,
    )
    if len(singles) < 2:
        return []

    # Sort by concentration & support to take top K most informative features
    singles_sorted = sorted(
        singles,
        key=lambda c: (c.statistical_evidence.get("class_concentration", 0), c.supporting_example_count),
        reverse=True,
    )[:top_k_candidates]

    prominent_indices = [
        int(c.opaque_feature_identifiers[0].replace("feature_idx_", ""))
        for c in singles_sorted
    ]

    class_totals: Dict[str, int] = {c: 0 for c in VALID_CLASSES}
    for r in records:
        lbl = r.get("label")
        if lbl in class_totals:
            class_totals[lbl] += 1

    # Map pairs (idx1, idx2) -> class occurrences
    pair_counts: Dict[Tuple[int, int], Dict[str, int]] = {}

    for r in records:
        vec = r.get("feature_vector")
        lbl = r.get("label")
        if not isinstance(vec, list) or len(vec) != 1024 or lbl not in VALID_CLASSES:
            continue

        active_in_record = [i for i in prominent_indices if abs(vec[i]) >= activation_threshold]
        for a_idx in range(len(active_in_record)):
            for b_idx in range(a_idx + 1, len(active_in_record)):
                pair = (min(active_in_record[a_idx], active_in_record[b_idx]),
                        max(active_in_record[a_idx], active_in_record[b_idx]))
                if pair not in pair_counts:
                    pair_counts[pair] = {c: 0 for c in VALID_CLASSES}
                pair_counts[pair][lbl] += 1

    candidates: List[CandidatePattern] = []
    now_utc = get_utc_now_iso()

    for pair, counts in pair_counts.items():
        support = sum(counts.values())
        if support < min_support:
            continue

        stats = compute_feature_statistics(
            supporting_count=support,
            total_dataset_count=total_records,
            class_occurrences=counts,
            dataset_class_totals=class_totals,
        )

        conc = stats.get("class_concentration", 0.0)
        lift = stats.get("lift", 0.0)
        wilson_lb = stats.get("wilson_lower_bound", 0.0)
        dom_class = stats.get("dominant_class")

        # Higher bar for pairs: must be highly concentrated (>= 75%)
        if conc >= 0.75 and lift >= MIN_LIFT_THRESHOLD:
            if support < REVIEW_READY_MIN_SUPPORT or wilson_lb < MIN_WILSON_LOWER_BOUND:
                state = "needs_more_evidence"
            else:
                state = "draft"

            limitations = standard_limitations_for_feature(
                pattern_type="ngram_feature_pair",
                support=support,
                wilson_lb=wilson_lb,
                provenance=provenance,
            )
            limitations.append(
                "COMBINATORIAL_PAIR_HYPOTHESIS: Evaluated as a co-occurring bucket pair; "
                "risk of overfitting if applied directly without independent verification."
            )

            cand = CandidatePattern(
                candidate_id=generate_candidate_id("PAT-PAIR"),
                pattern_schema_version=PATTERN_SCHEMA_VERSION,
                discovery_timestamp_utc=now_utc,
                candidate_pattern_type="ngram_feature_pair",
                opaque_feature_identifiers=[f"feature_idx_{pair[0]}", f"feature_idx_{pair[1]}"],
                target_class=dom_class,
                supporting_example_count=support,
                total_dataset_examples=total_records,
                class_distribution=counts,
                statistical_evidence=stats,
                uncertainty_or_limitations=limitations,
                data_provenance=provenance,
                algorithm_version=PATTERN_DISCOVERY_VERSION,
                lifecycle_state=state,
                metadata={"pair_indices": list(pair)},
            )
            candidates.append(cand)

    return candidates


def mine_structural_url_characteristics(
    records: List[Dict[str, Any]],
    provenance: str,
    min_support: int = MIN_SUPPORT_THRESHOLD,
) -> List[CandidatePattern]:
    """
    Mines safe structural and URL indicators (e.g. numerical IP host, punycode, shortener,
    suspicious TLD, APK download path, unencrypted HTTP) across labeled records.
    PRIVACY GUARANTEE: Never stores, emits, or matches on raw URL strings.
    """
    total_records = len(records)
    if total_records < min_support:
        return []

    class_totals: Dict[str, int] = {c: 0 for c in VALID_CLASSES}
    for r in records:
        lbl = r.get("label")
        if lbl in class_totals:
            class_totals[lbl] += 1

    # Map characteristic_name -> class occurrences
    char_counts: Dict[str, Dict[str, int]] = {}

    for r in records:
        lbl = r.get("label")
        if lbl not in VALID_CLASSES:
            continue

        struct_flags = r.get("structural_flags", {})
        if not isinstance(struct_flags, dict):
            continue

        for flag_name, is_present in struct_flags.items():
            if is_present:
                if flag_name not in char_counts:
                    char_counts[flag_name] = {c: 0 for c in VALID_CLASSES}
                char_counts[flag_name][lbl] += 1

    candidates: List[CandidatePattern] = []
    now_utc = get_utc_now_iso()

    for flag_name, counts in char_counts.items():
        support = sum(counts.values())
        if support < min_support:
            continue

        stats = compute_feature_statistics(
            supporting_count=support,
            total_dataset_count=total_records,
            class_occurrences=counts,
            dataset_class_totals=class_totals,
        )

        conc = stats.get("class_concentration", 0.0)
        lift = stats.get("lift", 0.0)
        wilson_lb = stats.get("wilson_lower_bound", 0.0)
        dom_class = stats.get("dominant_class")

        if conc >= MIN_CONCENTRATION_THRESHOLD and lift >= 1.20:
            if support < REVIEW_READY_MIN_SUPPORT or wilson_lb < MIN_WILSON_LOWER_BOUND:
                state = "needs_more_evidence"
            else:
                state = "draft"

            limits = [
                f"STRUCTURAL_CHARACTERISTIC_HYPOTHESIS: Evaluated flag '{flag_name}'. "
                f"Does NOT prove malice in isolation; legitimate services occasionally utilize similar structures.",
                "NO_RAW_URL_PERSISTENCE: Derived from passive syntactic URL inspection in RAM; "
                "no target URL or destination domain is retained.",
                "LOCAL_ANALYST_ADVISORY: Requires domain-expert verification before inclusion in threat heuristics.",
            ]
            if support < REVIEW_READY_MIN_SUPPORT:
                limits.append(f"SMALL_SAMPLE_SIZE: Only {support} occurrences observed.")

            cand = CandidatePattern(
                candidate_id=generate_candidate_id("PAT-STRUCT"),
                pattern_schema_version=PATTERN_SCHEMA_VERSION,
                discovery_timestamp_utc=now_utc,
                candidate_pattern_type="structural_url_characteristic",
                opaque_feature_identifiers=[flag_name],
                target_class=dom_class,
                supporting_example_count=support,
                total_dataset_examples=total_records,
                class_distribution=counts,
                statistical_evidence=stats,
                uncertainty_or_limitations=limits,
                data_provenance=provenance,
                algorithm_version=PATTERN_DISCOVERY_VERSION,
                lifecycle_state=state,
                metadata={"characteristic_name": flag_name},
            )
            candidates.append(cand)

    return candidates


# =============================================================================
# PATTERN CATALOG MANAGER
# =============================================================================

class PatternCatalogManager:
    """
    Manages atomic, versioned local pattern catalogues.
    GUARANTEES:
    - Never overwrites an existing catalogue version.
    - Atomically writes via temporary file renaming.
    - Validates schema and asserts forbidden fields are strictly absent.
    - Preserves previous versions intact.
    - Completely separate from model_registry.json.
    """

    def __init__(self, catalog_dir: Optional[str] = None):
        self.catalog_dir = catalog_dir or DEFAULT_CATALOG_DIR
        os.makedirs(self.catalog_dir, exist_ok=True)

    def get_audit_log_path(self) -> str:
        """Returns path to the append-only review audit log."""
        return os.path.join(self.catalog_dir, AUDIT_LOG_FILENAME)

    def list_catalogs(self) -> List[str]:
        """Returns list of existing catalog version files sorted by version."""
        if not os.path.exists(self.catalog_dir):
            return []
        files = [
            f for f in os.listdir(self.catalog_dir)
            if f.startswith("catalog_v") and f.endswith(".json")
        ]
        return sorted(files)

    def get_next_catalog_version(self) -> str:
        """Generates the next sequential catalog version string (e.g. 1.0.0, 1.0.1)."""
        existing = self.list_catalogs()
        if not existing:
            return "1.0.0"

        versions = []
        for fn in existing:
            m = re.search(r"catalog_v(\d+)\.(\d+)\.(\d+)\.json", fn)
            if m:
                versions.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))

        if not versions:
            return "1.0.0"

        last = max(versions)
        return f"{last[0]}.{last[1]}.{last[2] + 1}"

    def save_catalog(
        self,
        candidates: List[CandidatePattern],
        version: Optional[str] = None,
        provenance_filter: str = "local_curated_feedback",
        notes: str = "",
        overwrite: bool = False,
    ) -> str:
        """
        Atomically saves candidate patterns into a versioned JSON catalog.
        Fails safely if the version already exists unless overwrite=True.
        """
        cat_ver = version or self.get_next_catalog_version()
        filename = f"catalog_v{cat_ver}.json"
        target_path = os.path.join(self.catalog_dir, filename)

        if os.path.exists(target_path) and not overwrite:
            raise PatternCatalogError(
                f"Catalogue version '{cat_ver}' already exists at '{target_path}'. Overwrite is prohibited."
            )

        # Validate all candidates
        validated_candidates = []
        for c in candidates:
            c.validate()
            validated_candidates.append(c.to_dict())

        # Compile catalog statistics
        by_type: Dict[str, int] = {}
        by_state: Dict[str, int] = {}
        by_class: Dict[str, int] = {}

        for c in candidates:
            by_type[c.candidate_pattern_type] = by_type.get(c.candidate_pattern_type, 0) + 1
            by_state[c.lifecycle_state] = by_state.get(c.lifecycle_state, 0) + 1
            by_class[c.target_class] = by_class.get(c.target_class, 0) + 1

        payload = {
            "catalog_version": cat_ver,
            "generated_at_utc": get_utc_now_iso(),
            "generator_algorithm": PATTERN_DISCOVERY_VERSION,
            "pattern_schema_version": PATTERN_SCHEMA_VERSION,
            "provenance_filter": provenance_filter,
            "candidate_count": len(candidates),
            "summary": {
                "total_candidates": len(candidates),
                "by_type": by_type,
                "by_state": by_state,
                "by_target_class": by_class,
            },
            "notes": notes,
            "candidate_patterns": validated_candidates,
            "disclaimer": (
                "OFFLINE FRAUD PATTERN HYPOTHESIS CATALOGUE. "
                "Discovered candidate associations are exploratory hypotheses for human analyst triage only. "
                "Approving a candidate pattern does NOT modify active detection rules or alter production threat scores."
            ),
        }

        # Atomic write via temp file
        temp_path = f"{target_path}.tmp.{uuid.uuid4().hex[:6]}"
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(temp_path, target_path)
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

        return target_path

    def load_catalog(
        self,
        catalog_path: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Loads and validates a catalog JSON file.
        Fails safely on malformed JSON or invalid schema.
        """
        if not catalog_path:
            if not version:
                existing = self.list_catalogs()
                if not existing:
                    raise PatternCatalogError(f"No pattern catalogues found in '{self.catalog_dir}'.")
                catalog_path = os.path.join(self.catalog_dir, existing[-1])
            else:
                catalog_path = os.path.join(self.catalog_dir, f"catalog_v{version}.json")

        if not os.path.exists(catalog_path):
            raise PatternCatalogError(f"Catalogue file not found at '{catalog_path}'.")

        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise PatternCatalogError(f"Catalogue file at '{catalog_path}' is corrupted or malformed JSON: {exc}")

        if not isinstance(data, dict):
            raise PatternCatalogError(f"Catalogue at '{catalog_path}' does not contain a JSON object.")

        if "candidate_patterns" not in data or not isinstance(data["candidate_patterns"], list):
            raise PatternCatalogError(f"Catalogue at '{catalog_path}' is missing 'candidate_patterns' list.")

        # Re-validate candidate records
        for item in data["candidate_patterns"]:
            CandidatePattern.from_dict(item)

        return data

    def review_candidate_pattern(
        self,
        candidate_id: str,
        new_state: str,
        reason: str,
        reviewer_label: str = "local_operator_unauthenticated",
        catalog_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes an operator human review decision on a candidate pattern.

        SAFETY GUARANTEES:
        - Only human review can set 'approved_by_human' or 'rejected'.
        - Rejected patterns cannot be silently reactivated.
        - Appends an audit event to pattern_review_audit.jsonl.
        - Updates catalog atomically without altering production threat detection or scoring.
        """
        if new_state not in VALID_LIFECYCLE_STATES:
            raise PatternReviewError(
                f"Invalid lifecycle state '{new_state}'; valid: {VALID_LIFECYCLE_STATES}."
            )

        if not reason or not reason.strip():
            raise PatternReviewError("A descriptive reason must be provided for the review decision.")

        catalog_data = self.load_catalog(catalog_path=catalog_path)
        candidates = catalog_data["candidate_patterns"]

        target_idx = None
        for i, c in enumerate(candidates):
            if c.get("candidate_id") == candidate_id:
                target_idx = i
                break

        if target_idx is None:
            raise PatternReviewError(f"Candidate pattern '{candidate_id}' not found in active catalogue.")

        current = candidates[target_idx]
        prev_state = current.get("lifecycle_state", "draft")

        # Guard against silent reactivation of rejected patterns
        if prev_state == "rejected" and new_state not in ("rejected", "needs_more_evidence"):
            raise PatternReviewError(
                f"Candidate pattern '{candidate_id}' was previously REJECTED. "
                "Silent reactivation to approved_by_human is strictly prohibited by governance policy."
            )

        # Update candidate state and review metadata
        now_utc = get_utc_now_iso()
        current["lifecycle_state"] = new_state
        if "review_history" not in current["metadata"]:
            current["metadata"]["review_history"] = []

        audit_entry = {
            "log_id": f"PAT-AUDIT-{uuid.uuid4().hex[:8].upper()}",
            "candidate_id": candidate_id,
            "previous_state": prev_state,
            "new_state": new_state,
            "reason": reason.strip(),
            "reviewer_label": reviewer_label,
            "timestamp_utc": now_utc,
            "production_rules_modified": False,
            "scoring_altered": False,
        }
        current["metadata"]["review_history"].append(audit_entry)

        # Re-save catalog atomically
        # Re-parse into CandidatePattern objects
        candidate_objs = [CandidatePattern.from_dict(c) for c in candidates]
        resolved_path = catalog_path or os.path.join(self.catalog_dir, f"catalog_v{catalog_data['catalog_version']}.json")
        self.save_catalog(
            candidates=candidate_objs,
            version=catalog_data["catalog_version"],
            provenance_filter=catalog_data.get("provenance_filter", "local_curated_feedback"),
            notes=f"Updated candidate {candidate_id} to {new_state}",
            overwrite=True,
        )

        # Append to audit log
        audit_path = self.get_audit_log_path()
        with open(audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit_entry, ensure_ascii=False) + "\n")

        return {
            "candidate_id": candidate_id,
            "previous_state": prev_state,
            "new_state": new_state,
            "audit_entry": audit_entry,
        }

    def list_review_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Returns recent review audit log entries."""
        audit_path = self.get_audit_log_path()
        if not os.path.exists(audit_path):
            return []

        entries = []
        with open(audit_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
        return entries[-limit:]


# =============================================================================
# PATTERN DISCOVERY ENGINE
# =============================================================================

class PatternDiscoveryEngine:
    """
    Offline engine that discovers fraud and legitimacy patterns from eligible training data.
    COMPLIANCE:
    - Never uses predictions as labels.
    - Strictly separates human-reviewed local cases from synthetic corpus data.
    - Employs curate_training_features() to enforce consent, dedup, and review gates.
    - Never touches the locked evaluation dataset.
    """

    def __init__(self, catalog_manager: Optional[PatternCatalogManager] = None):
        self.catalog_manager = catalog_manager or PatternCatalogManager()

    def discover_patterns_from_curated_feedback(
        self,
        repository: Any,
        secret: Optional[str] = None,
        min_support: int = MIN_SUPPORT_THRESHOLD,
    ) -> Dict[str, Any]:
        """
        Mines patterns from eligible, consented, human-reviewed feature records in the local SQLite repository.
        Strictly re-verifies consent and review eligibility via curate_training_features().
        """
        # Step 1: Curate eligible training features through Phase 6.1.1 gate
        curation_res = repository.curate_training_features(secret=secret)
        eligible = curation_res.get("eligible_records", [])

        if not eligible:
            return {
                "discovery_timestamp_utc": get_utc_now_iso(),
                "provenance": "local_curated_feedback",
                "eligible_records_count": 0,
                "discovered_candidates_count": 0,
                "candidates": [],
                "status": "INSUFFICIENT_EVIDENCE",
                "reason": "No eligible, reviewed, consented feature records available in local repository.",
            }

        # Step 2: Extract passive structural URL characteristics from threat_cases in RAM without storing raw URLs
        enhanced_records: List[Dict[str, Any]] = []
        with repository.get_connection() as conn:
            for rec in eligible:
                case_id = rec.get("case_id")
                struct_flags: Dict[str, bool] = {}

                if case_id:
                    c_row = conn.execute(
                        "SELECT extracted_urls_json, observed_evidence_json, analysis_type FROM threat_cases WHERE case_id = ?;",
                        (case_id,),
                    ).fetchone()
                    if c_row:
                        # Extract structural flags passively without retaining URL string
                        urls = json.loads(c_row["extracted_urls_json"] or "[]")
                        for u in urls:
                            # Passive URL analysis strictly in RAM
                            from src.url_analyzer import analyze_url
                            try:
                                u_eval = analyze_url(u)
                                obs = u_eval.get("observable_characteristics", {})
                                if obs.get("is_ip_address"):
                                    struct_flags["struct_is_ip_address"] = True
                                if obs.get("is_punycode_or_homoglyph"):
                                    struct_flags["struct_is_punycode"] = True
                                if obs.get("is_shortener"):
                                    struct_flags["struct_is_shortener"] = True
                                if obs.get("is_suspicious_tld"):
                                    struct_flags["struct_is_suspicious_tld"] = True
                                if obs.get("has_unusual_port"):
                                    struct_flags["struct_has_unusual_port"] = True
                                if obs.get("has_apk_download"):
                                    struct_flags["struct_has_apk_download"] = True
                                if obs.get("has_excessive_encoding"):
                                    struct_flags["struct_has_excessive_encoding"] = True
                                if not obs.get("is_https"):
                                    struct_flags["struct_unencrypted_http"] = True
                            except Exception:
                                pass

                enhanced_records.append({
                    "feature_vector": rec.get("feature_vector"),
                    "label": rec.get("label"),
                    "structural_flags": struct_flags,
                })

        # Step 3: Run mining routines
        ngram_singles = mine_ngram_feature_associations(
            records=enhanced_records,
            provenance="local_curated_feedback",
            min_support=min_support,
        )
        ngram_pairs = mine_ngram_feature_pairs(
            records=enhanced_records,
            provenance="local_curated_feedback",
            min_support=min_support,
        )
        struct_patterns = mine_structural_url_characteristics(
            records=enhanced_records,
            provenance="local_curated_feedback",
            min_support=min_support,
        )

        all_candidates = ngram_singles + ngram_pairs + struct_patterns

        return {
            "discovery_timestamp_utc": get_utc_now_iso(),
            "provenance": "local_curated_feedback",
            "eligible_records_count": len(eligible),
            "discovered_candidates_count": len(all_candidates),
            "candidates": all_candidates,
            "status": "PASS" if all_candidates else "NEEDS_MORE_EVIDENCE",
            "candidate_breakdown": {
                "ngram_feature_association": len(ngram_singles),
                "ngram_feature_pair": len(ngram_pairs),
                "structural_url_characteristic": len(struct_patterns),
            },
        }

    def discover_patterns_from_synthetic_corpus(
        self,
        corpus_path: str,
        secret: Optional[str] = None,
        min_support: int = 10,
    ) -> Dict[str, Any]:
        """
        Mines patterns from existing synthetic training data for algorithm verification.
        SAFETY CHECKS:
        - NEVER mines the locked evaluation dataset ('phishing_eval_dataset.json').
        - NEVER mines the validation set ('synthetic_validation_corpus.jsonl') to prevent threshold tuning.
        - Explicitly tags all candidates with provenance 'synthetic_seed_v2.2'.
        """
        # Forbidden dataset paths check
        norm_path = corpus_path.replace("\\", "/").lower()
        if "eval" in norm_path or "phishing_eval_dataset" in norm_path:
            raise PatternDiscoveryError(
                "Access denied: Mining the locked evaluation dataset is strictly prohibited."
            )
        if "validation" in norm_path:
            raise PatternDiscoveryError(
                "Access denied: Mining the validation corpus is prohibited to prevent threshold leakage."
            )

        if not os.path.exists(corpus_path):
            raise PatternDiscoveryError(f"Corpus file not found at '{corpus_path}'.")

        from src.dataset_preprocessing import extract_derived_training_features

        records: List[Dict[str, Any]] = []
        with open(corpus_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    item = json.loads(line_str)
                    text = item.get("text", "")
                    label = item.get("ground_truth_label") or item.get("label")
                    if text and label in VALID_CLASSES:
                        ok, vec, _, _ = extract_derived_training_features(text, secret=secret)
                        if ok and vec is not None:
                            records.append({
                                "feature_vector": vec,
                                "label": label,
                                "structural_flags": {},
                            })
                except Exception:
                    continue

        if not records:
            return {
                "discovery_timestamp_utc": get_utc_now_iso(),
                "provenance": "synthetic_seed_v2.2",
                "eligible_records_count": 0,
                "discovered_candidates_count": 0,
                "candidates": [],
                "status": "EMPTY_CORPUS",
            }

        singles = mine_ngram_feature_associations(
            records=records,
            provenance="synthetic_seed_v2.2",
            min_support=min_support,
        )
        pairs = mine_ngram_feature_pairs(
            records=records,
            provenance="synthetic_seed_v2.2",
            min_support=min_support,
        )

        all_candidates = singles + pairs

        return {
            "discovery_timestamp_utc": get_utc_now_iso(),
            "provenance": "synthetic_seed_v2.2",
            "eligible_records_count": len(records),
            "discovered_candidates_count": len(all_candidates),
            "candidates": all_candidates,
            "status": "PASS",
            "candidate_breakdown": {
                "ngram_feature_association": len(singles),
                "ngram_feature_pair": len(pairs),
            },
        }
