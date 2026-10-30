# Seva Cyber Sandbox — Data Acquisition, Provenance & Dataset Review Protocol

> **Document Version:** 1.1.0  
> **Status:** Active Standard  
> **Scope:** Multilingual Phishing Evaluation Dataset, Case Ingestion & Model Testing  

---

## 1. Overview & Objectives

The **Seva Cyber Sandbox** evaluation dataset serves as a rigorous, leak-free benchmark for detecting regional multilingual phishing, social engineering lures, and fraudulent APK campaigns targeting citizens in Maharashtra and across India.

A core tenet of the Seva Cyber Sandbox Project Engineering Rules is **scientific integrity and data realism over inflated metrics**:
1. Zero tolerance for unacknowledged in-sample tuning contamination.
2. Complete provenance transparency for every evaluation record.
3. Strict privacy protection and mandatory scrubbing of personally identifiable information (PII).
4. Campaign-isolated, cryptographically frozen partitions to prevent data leakage and template memorization.

---

## 2. Data Acquisition Channels

All records ingested into the evaluation corpus originate from three legitimate, documented channels:

| Channel | Description | Permitted Ingestion Roles | Review Requirements |
|---|---|---|---|
| **A. Official Regulatory & Law Enforcement Advisories** | Public awareness bulletins, cyber security advisories, and official notices published by CERT-In, Maharashtra Cyber Police, Reserve Bank of India (RBI), MSEDCL, and state departments. | `development`, `validation`, `locked_test` | Direct link or circular reference to the published government/regulatory bulletin. |
| **B. Citizen-Reported Forwarded Messages** | Actual SMS, WhatsApp, and Telegram social-engineering lures forwarded by citizens to cyber cells or reporting portals. | Staging / `development` / `validation` / `locked_test` (post-curation) | Mandatory PII scrubbing, domain extraction, campaign grouping, and dual-analyst review. |
| **C. Synthetic Test Fixtures** | Engineered test vectors designed specifically to evaluate boundary edge cases, parser resilience, script mixing, and evasion techniques (e.g. zero-width characters, homoglyphs, Devanagari numerals). | `development`, `validation` | Explicit notation of the synthetic nature, target vulnerability, and intended behavior. |

---

## 3. Privacy, Anonymization & PII Scrubbing Rules

Under no circumstances may unmasked personal data be committed to the evaluation corpus or persistent test fixtures. The intake pipeline must enforce the following masking rules prior to dataset inclusion:

### 3.1 Mandatory PII Scrubbing Rules
1. **Personal Phone Numbers:** All 10-digit mobile numbers belonging to private individuals or victims must be masked using standard masks (e.g., `98XXXXXX12`, `9800000000`, `+91-XXXXXXXXXX`).
2. **Aadhaar Numbers:** 12-digit Aadhaar numbers and 16-digit Virtual IDs must be completely masked or stripped (e.g., `XXXX-XXXX-1234` or `[AADHAAR MASKED]`).
3. **PAN & Identity Credentials:** Permanent Account Numbers (PAN), Voter IDs, and Passport numbers must be masked.
4. **Bank Account & Card Numbers:** Full bank account numbers and 16-digit debit/credit card numbers must be replaced with `[ACCOUNT MASKED]` or `XXXX-XXXX-XXXX-0000`.
5. **Private Citizen Names:** Personal names of victims or private citizens must be replaced with neutral generic placeholders (e.g., `[नागरिक]`, `[Customer]`).

### 3.2 Preserved Public References (Exceptions to Masking)
The following elements must **NOT** be masked, as they represent vital ground-truth signals for detection and safe operation:
- **Official National & Regional Helplines:** `1930` (National Cyber Crime Helpline), `112` (Emergency Helpline), `1800` toll-free customer support numbers published by state utilities (e.g., MSEDCL `1800-233-3435`).
- **Official Government & Utility Domains:** `cybercrime.gov.in`, `mahadiscom.in`, `aaplesarkar.mahaonline.gov.in`, `rbi.org.in`.
- **Known Malicious Campaign Domains / Phone Numbers:** Fraudulent call-back numbers explicitly publicized in official police warnings as lure contact numbers (e.g., electricity fraud call numbers cited in police FIR advisories).

---

## 4. Four-Tier Provenance Taxonomy

Every record in the evaluation corpus must declare its `provenance_verification_status` using the following 4-tier taxonomy:

```
                                  [Raw Intake Message]
                                           │
                                           ▼
                            [PII Scrubbing & Intake Review]
                                           │
               ┌───────────────────────────┴───────────────────────────┐
               ▼                                                       ▼
    [Official Public Source?]                               [Regional Scam Lure?]
               │                                                       │
         YES   │                                                 YES   │
               ▼                                                       ▼
  verified_official_source                                      curated_exemplar
  (Circular / Bulletin match)                                   (Representative lure pattern)
               │                                                       │
               └───────────────────────────┬───────────────────────────┘
                                           │
               ┌───────────────────────────┴───────────────────────────┐
               ▼                                                       ▼
      synthetic_fixture                                       unverified_intake
  (Engineered edge-case test)                                 (Citizen forward awaiting review)
```

1. **`verified_official_source`**:
   - The message text or alert verbatim matches or directly derives from a verified public warning, press release, or advisory issued by an official authority (e.g., MSEDCL Consumer Alert, CERT-In Advisory, Maharashtra Cyber warning).
   - `source_reference` must cite the specific issuing agency, year, or bulletin identifier.

2. **`curated_exemplar`**:
   - The message represents an authentic social-engineering lure structure commonly reported in regional scams (e.g., electricity disconnection threats, digital arrest extortion, PM Kisan subsidy phishing).
   - Text has been reconstructed from reported exemplars, scrubbed of victim PII, and validated for regional linguistic and behavioral authenticity.

3. **`synthetic_fixture`**:
   - Artificially engineered test inputs designed to exercise specific syntactic quirks (e.g., zero-width non-joiner evasion, URL obfuscation, excessive exclamation marks, numeral substitution).
   - Never claimed to be organic citizen communication.

4. **`unverified_intake`**:
   - Raw incoming forwarded messages received via WhatsApp sandbox, user uploads, or threat feeds that have not yet undergone dual-analyst review and verification.
   - **Restriction:** May only reside in intake logs or provisional development partitions; strictly prohibited from the `locked_test` partition.

---

## 5. Three-Role Dataset Partition Protocol

To prevent test-set contamination and misleading accuracy claims, the evaluation dataset is strictly partitioned into three independent roles:

| Dataset Role | Target Share | Permitted Activities | Campaign Overlap Restriction |
|---|---|---|---|
| **`development`** | ~50% | Rule creation, regex drafting, error analysis, ML prototype training. | $\text{campaigns}(\text{dev}) \cap \text{campaigns}(\text{others}) = \emptyset$ |
| **`validation`** | ~25% | Threshold comparison, candidate rule selection, false-positive tuning. | $\text{campaigns}(\text{val}) \cap \text{campaigns}(\text{others}) = \emptyset$ |
| **`locked_test`** | ~25% | Final benchmark evaluation, release gating, regression reporting. | $\text{campaigns}(\text{locked}) \cap \text{campaigns}(\text{others}) = \emptyset$ |

### 5.1 Strict Campaign-Level Isolation
A major vulnerability in NLP evaluation is **template leakage**: when different variants of the same scam message (e.g., MSEDCL power cut template with slightly different phone numbers) appear in both development and test partitions, models achieve deceptively high scores simply by memorizing recurring template boilerplates.

**Rule:** Every record has an assigned `campaign_id`. Partitioning is strictly performed at the campaign level:
$$\text{campaigns}(\text{development}) \cap \text{campaigns}(\text{validation}) \cap \text{campaigns}(\text{locked\_test}) = \emptyset$$
No campaign may ever have records spanning more than one partition role.

---

## 6. Cryptographic Locking of the Independent Test Partition

The `locked_test` partition represents the independent benchmark against which production readiness is evaluated. To guarantee that test records are never quietly edited or augmented to mask detector regressions:

1. **Manifest File:** `data/locked_test_manifest.json` stores:
   - Canonical list of `record_id`s assigned to `locked_test`.
   - Normalization standard (canonical JSON, sorted keys, UTF-8 encoded).
   - Cryptographic SHA-256 hash of the canonical serialized partition.
2. **Automated Verification:** The evaluation harness (`evaluation/evaluate_phishing.py`) and dataset validator (`src/dataset_validator.py`) compute the SHA-256 checksum on load. If any character, label, or field of a locked record is altered, or if records are added or removed without following the unfreezing protocol, evaluation aborts with a `DatasetValidationError`.
3. **Unfreezing & Promotion Protocol:**
   - Moving new records into `locked_test` or modifying existing records requires:
     1. Formal version bump of the dataset (`schema_version` / dataset version).
     2. Documented changelog entry specifying the reason for change and review signatures.
     3. Regeneration of `data/locked_test_manifest.json` with the new canonical SHA-256 checksum.

---

## 7. Four-Class Ground-Truth Labeling Taxonomy

The evaluation system uses a 4-class taxonomy to separate deceptive threats from legitimate traffic and protective advisories:

1. **`phishing`**:
   - Deceptive or coercive messages soliciting credentials, passwords, OTPs, financial transfers, remote access APK installations, or fraudulent fee payments.
2. **`legitimate`**:
   - Authentic, benign communications, including utility billing notices, delivery updates, government scheme announcements, and conversational messages.
3. **`protective_advisory`**:
   - Official public warnings issued by banks, utilities, or police advising citizens **NOT** to click links, download APKs, or share OTPs.
   - **Evaluation Requirement:** Must be evaluated separately under the protective-negation safeguard. Advisories must never be counted as phishing, nor should they be mixed into binary classification precision/recall denominators.
4. **`ambiguous_needs_review`**:
   - Messages lacking sufficient contextual detail (e.g. truncated forwards, single suspicious numbers without coercive context) where automated classification cannot be definitively ground-truthed.
   - **Evaluation Requirement:** Reported in a dedicated review queue; not included in binary accuracy denominators.

---

## 8. Reporting Disclosures & Scientific Honesty

Every evaluation report generated by Seva Cyber Sandbox must adhere to the following reporting guidelines:
1. **Always State Sample Size ($N$):** Every metric must report the raw count of evaluated records (e.g., `Accuracy: 100.0% (10/10)`) rather than percentages alone.
2. **In-Sample Tuning Disclosure:** Any evaluation run on `development` or historically known samples must display a prominent disclosure:
   > *"HISTORICAL IN-SAMPLE TUNING DISCLOSURE: Reported metrics reflect performance on records historically available during rule development. True out-of-sample generalization requires unseen advisories collected after model freeze."*
3. **Separate Advisory Safeguard Reporting:** False alarms on protective advisories must be reported as a distinct safety metric (`safeguard_success_pct`) and false-alarm count (`0 / N`).
4. **Model Comparison Nuance:** Agreement between rule-based heuristics and statistical ML n-gram models must be reported as *concordance*, explicitly stating that concordance between two heuristic systems does not constitute independent mathematical ground-truth verification.
