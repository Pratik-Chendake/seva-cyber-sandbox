# Seva Cyber Sandbox — Phase 6.4.6: Synthetic Dataset v4 Report

**Document Reference:** `docs/PHASE_6_4_6_DATASET_V4_REPORT.md`  
**Execution Timestamp:** 2026-10-30T20:50:00+05:30  
**Target Project:** Seva Cyber Sandbox (`C:\Users\prati\seva-cyber-sandbox`)  
**Phase Objective:** Generate Synthetic Dataset v4 resolving the critical coverage gaps identified in the Phase 6.4.5 forensic investigation ([`docs/PHASE_6_4_5_REMEDIATION_ANALYSIS_REPORT.md`](file:///C:/Users/prati/seva-cyber-sandbox/docs/PHASE_6_4_5_REMEDIATION_ANALYSIS_REPORT.md)). Specifically: (1) introduce diverse digital-arrest, narcotics, CBI, court, and extortion phishing families; (2) counterbalance with genuine police, court, hospital, and civic administrative notifications; (3) integrate protective advisories containing scam vocabulary; (4) enforce strict 50.0% URL-bearing / 50.0% URL-free balance to eliminate URL shortcut learning; (5) support balanced multilingual representations across Marathi Devanagari (`mr`), Romanized Marathi (`mr-Latn`), Indian English (`en`), and Mixed (`mr-en`); (6) guarantee strict partition isolation across 45 unique campaign families; and (7) initialize the v4 qualification lifecycle exposure ledger in an unexposed state.  
**Operating Mode:** DATASET GENERATION & AUDIT ONLY (No models trained, fine-tuned, or evaluated; ₹0 spend; 100% local CPU execution; zero network calls)  
**Repository Test Suite:** **465/465 passing tests** (`python -m pytest`, 100% pass in 39.90s)  
**Phase 6.4.6 Test Suite:** **27/27 passing tests** ([`tests/test_phase6_4_6_dataset_v4.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_6_dataset_v4.py) in 0.51s)  
**Locked Evaluation Partition Digest:** `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` (VERIFIED UNCHANGED)  
**Retired v3 Exposure Ledger Status:** `EVALUATION_COMPLETED` ([`evaluation/qualification/exposure_ledger.json`](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger.json), untouched)  
**v4 Qualification Lifecycle Status:** `sealed_independent_benchmark` / `UNEXPOSED` ([`evaluation/qualification/exposure_ledger_v4.json`](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger_v4.json))  
**Production Runtime Invariance:** Score Delta = 0 (Heuristic primacy preserved; model registry and active model configuration untouched)  
**Phase 6.4.6 Audit Verdict:** **`PASS`** (All 19 automated audit checks passed; 100% specification compliance)

---

## 1. Dataset Architecture

Synthetic Dataset v4 was architected to eliminate the "Semantic Asymmetry" identified in Phase 6.4.5, where law enforcement tokens ("पोलीस", "Police", "Cyber Cell", "Crime Branch") were historically present exclusively in protective advisories, leaving the neural classifier blind to coercive extortion threats.

```
                          SYNTHETIC DATASET v4 PARTITION ARCHITECTURE
┌──────────────────┬──────────────┬──────────────────────────────────────────┬───────────────┬──────────────────────────┐
│ Partition        │ Record Count │ Campaign Family Count & Breakdown        │ Role / Status │ Target Distribution      │
├──────────────────┼──────────────┼──────────────────────────────────────────┼───────────────┼──────────────────────────┤
│ Training         │ 1,500        │ 30 Families (10 Phish, 10 Legit, 10 Adv) │ development   │ 500 / 500 / 500 records  │
│ Development      │ 300          │ 6 Families (2 Phish, 2 Legit, 2 Adv)     │ validation    │ 100 / 100 / 100 records  │
│ Qualification    │ 450          │ 9 Families (3 Phish, 3 Legit, 3 Adv)     │ qualification │ 150 / 150 / 150 records  │
├──────────────────┼──────────────┼──────────────────────────────────────────┼───────────────┼──────────────────────────┤
│ TOTAL            │ 2,250        │ 45 Disjoint Campaign Families            │ Consolidated  │ 750 / 750 / 750 records  │
└──────────────────┴──────────────┴──────────────────────────────────────────┴───────────────┴──────────────────────────┘
```

### Key Structural Innovations over Dataset v3:
1. **Total Extortion Representation:** Phishing is expanded from pure utility bill/bank OTP lures into coercive digital-arrest, narcotics parcel confiscation, CBI summons, police video interrogation demands, and fake court warrants.
2. **Law Enforcement Counter-Lures in Legitimate:** Genuine police verification appointments, police lost property acknowledgments, and district court cause-list notifications ensure the model learns that law-enforcement terms do not automatically imply fraud or advisory bulletins.
3. **Deconfounded URL Reliance:** Every partition, class, and family enforces an **exact 50.0% URL-bearing and 50.0% URL-free split**, training the model to recognize social engineering and phone/video extortion in the complete absence of web links.
4. **Disjoint Family Guarantee:** All 45 campaign families and 45 scenario categories are independently authored with mutually disjoint templates. No cross-partition template leakage exists.

---

## 2. All 45 Campaign-Family Definitions

All 45 families are implemented in [`scripts/generate_synthetic_corpus_v4.py`](file:///C:/Users/prati/seva-cyber-sandbox/scripts/generate_synthetic_corpus_v4.py):

### 2.1 Training Partition (30 Families, 1,500 Records)

```
                              TRAINING CAMPAIGN FAMILIES (30)
┌────┬────────────────────────────────────────────────┬─────────────────────┬──────────────────────────────────────────────────┐
│ #  │ Campaign Family ID                             │ Ground Truth Label  │ Scenario Description                             │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 1  │ v4_train_phish_digital_arrest_narcotics        │ phishing            │ CBI/Customs narcotics parcel digital arrest      │
│ 2  │ v4_train_phish_cbi_investigation_notice        │ phishing            │ Fake CBI investigation summons & penalty threat  │
│ 3  │ v4_train_phish_narcotics_possession_warrant    │ phishing            │ NCB drug trafficking parcel non-bailable warrant │
│ 4  │ v4_train_phish_police_videocall_summons        │ phishing            │ Crime branch video call interrogation demand     │
│ 5  │ v4_train_phish_cybercrime_financial_fraud      │ phishing            │ Fake cyber cell money laundering frozen account  │
│ 6  │ v4_train_phish_court_warrant_penalty           │ phishing            │ High Court contempt warrant fine payment scam    │
│ 7  │ v4_train_phish_fir_cancellation_settlement     │ phishing            │ Fake police station compromise fee to cancel FIR │
│ 8  │ v4_train_phish_passport_police_verification_fee│ phishing            │ Adverse police verification fee extortion        │
│ 9  │ v4_train_phish_pm_kisan_subsidy_disqualification phishing           │ Scheme disqualification penalty recovery scam    │
│ 10 │ v4_train_phish_mudra_loan_default_attachment   │ phishing            │ Fake subsidy loan default asset attachment threat│
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 11 │ v4_train_legit_passport_police_appointment     │ legitimate          │ Genuine passport police verification appointment │
│ 12 │ v4_train_legit_police_lost_property_acknowledgement legitimate       │ Police portal lost property NC complaint receipt │
│ 13 │ v4_train_legit_district_court_hearing_schedule │ legitimate          │ Genuine eCourts cause-list next hearing date SMS │
│ 14 │ v4_train_legit_court_notice_appearance_info    │ legitimate          │ Routine court appearance informational notice    │
│ 15 │ v4_train_legit_mantralaya_gazette_circular     │ legitimate          │ State government administrative circular gazette │
│ 16 │ v4_train_legit_civil_hospital_opd_schedule     │ legitimate          │ Civil hospital doctor consultation token alert   │
│ 17 │ v4_train_legit_state_board_hall_ticket_download legitimate         │ Public exam hall ticket release notification     │
│ 18 │ v4_train_legit_municipal_water_pipeline_maintenance legitimate       │ Municipal water supply pipeline shutdown notice  │
│ 19 │ v4_train_legit_aadhaar_biometric_update_status │ legitimate          │ Genuine UIDAI biometric update receipt           │
│ 20 │ v4_train_legit_post_office_registered_parcel_pickup legitimate       │ India Post registered article pickup intimation  │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 21 │ v4_train_advisory_mha_digital_arrest_warning   │ protective_advisory │ MHA/I4C advisory that digital arrest is fake     │
│ 22 │ v4_train_advisory_cbi_impersonation_alert      │ protective_advisory │ Official CBI advisory against fake summonses     │
│ 23 │ v4_train_advisory_cybercell_video_extortion    │ protective_advisory │ Cyber cell alert against Skype/WhatsApp calls    │
│ 24 │ v4_train_advisory_ecourt_fake_warrant_notice   │ protective_advisory │ Judicial advisory on fake court arrest warrants  │
│ 25 │ v4_train_advisory_national_1930_helpline       │ protective_advisory │ National cyber helpline 1930 golden hour guide   │
│ 26 │ v4_train_advisory_rbi_predatory_loan_apps      │ protective_advisory │ RBI warning on illegal instant lending apps      │
│ 27 │ v4_train_advisory_pib_scheme_factcheck         │ protective_advisory │ PIB Fact Check debunking fake subsidy letters    │
│ 28 │ v4_train_advisory_police_verification_fee_fraud│ protective_advisory │ Police alert stating verification is free        │
│ 29 │ v4_train_advisory_certin_deepfake_voice_scam   │ protective_advisory │ CERT-In warning on AI voice clone emergencies    │
│ 30 │ v4_train_advisory_sebi_fake_ipo_investment     │ protective_advisory │ SEBI warning against unauthorized trading groups │
└────┴────────────────────────────────────────────────┴─────────────────────┴──────────────────────────────────────────────────┘
```

### 2.2 Development Partition (6 Families, 300 Records)

```
                            DEVELOPMENT CAMPAIGN FAMILIES (6)
┌────┬────────────────────────────────────────────────┬─────────────────────┬──────────────────────────────────────────────────┐
│ #  │ Campaign Family ID                             │ Ground Truth Label  │ Scenario Description                             │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 31 │ v4_dev_phish_customs_fedex_contraband_threat   │ phishing            │ Customs courier parcel contraband extortion      │
│ 32 │ v4_dev_phish_highcourt_contempt_fine_scam      │ phishing            │ High Court contempt bailable warrant fine lure   │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 33 │ v4_dev_legit_rto_smartcard_dispatch            │ legitimate          │ Genuine RTO driving license dispatch tracking SMS│
│ 34 │ v4_dev_legit_property_tax_annual_assessment    │ legitimate          │ Municipal property tax assessment demand notice  │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 35 │ v4_dev_advisory_ed_money_laundering_scam       │ protective_advisory │ Enforcement Directorate (ED) summons scam alert  │
│ 36 │ v4_dev_advisory_dot_sim_termination_alert      │ protective_advisory │ DoT warning that govt never threatens SIM cuts   │
└────┴────────────────────────────────────────────────┴─────────────────────┴──────────────────────────────────────────────────┘
```

### 2.3 Qualification Partition (9 Families, 450 Records) — HELD-BACK & SEALED

```
                           QUALIFICATION CAMPAIGN FAMILIES (9)
┌────┬────────────────────────────────────────────────┬─────────────────────┬──────────────────────────────────────────────────┐
│ #  │ Campaign Family ID                             │ Ground Truth Label  │ Scenario Description                             │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 37 │ v4_qual_phish_nia_terror_funding_interrogation │ phishing            │ Fake NIA summons for illegal foreign transfers   │
│ 38 │ v4_qual_phish_supremecourt_arrest_injunction   │ phishing            │ Fake Supreme Court non-bailable arrest injunction│
│ 39 │ v4_qual_phish_acb_disproportionate_assets_fine │ phishing            │ Fake Anti-Corruption Bureau raid bribe extortion │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 40 │ v4_qual_legit_lok_adalat_dispute_hearing       │ legitimate          │ District Legal Services Authority Lok Adalat SMS │
│ 41 │ v4_qual_legit_police_clearance_certificate_ready legitimate          │ SP office notice to collect verified PCC         │
│ 42 │ v4_qual_legit_municipal_trade_license_reminder │ legitimate          │ Municipal trade & health license renewal notice  │
├────┼────────────────────────────────────────────────┼─────────────────────┼──────────────────────────────────────────────────┤
│ 43 │ v4_qual_advisory_i4c_digital_arrest_sop        │ protective_advisory │ I4C national bulletin on digital arrest fraud    │
│ 44 │ v4_qual_advisory_bar_council_fake_legal_summons│ protective_advisory │ Bar Council alert on fake advocate demand letters│
│ 45 │ v4_qual_advisory_trai_cyber_arrest_ivr         │ protective_advisory │ TRAI warning on automated police impersonation   │
└────┴────────────────────────────────────────────────┴─────────────────────┴──────────────────────────────────────────────────┘
```

---

## 3. Training, Development, and Qualification Distributions

Every record is generated with 50 examples per family, providing clean statistical parity:

```
                                  CORPUS DISTRIBUTIONS
┌────────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┐
│ Dimension              │ Training (1,500)     │ Development (300)    │ Qualification (450)  │
├────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ Phishing Records       │ 500 (33.3%)          │ 100 (33.3%)          │ 150 (33.3%)          │
│ Legitimate Records     │ 500 (33.3%)          │ 100 (33.3%)          │ 150 (33.3%)          │
│ Advisory Records       │ 500 (33.3%)          │ 100 (33.3%)          │ 150 (33.3%)          │
├────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ Marathi Devanagari (mr)│ 390 (26.0%)          │ 78 (26.0%)           │ 117 (26.0%)          │
│ Romanized Marathi      │ 390 (26.0%)          │ 78 (26.0%)           │ 117 (26.0%)          │
│ English (en)           │ 360 (24.0%)          │ 72 (24.0%)           │ 108 (24.0%)          │
│ Mixed Marathi-English  │ 360 (24.0%)          │ 72 (24.0%)           │ 108 (24.0%)          │
├────────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ URL-Bearing (`True`)   │ 750 (50.0%)          │ 150 (50.0%)          │ 225 (50.0%)          │
│ URL-Free (`False`)     │ 750 (50.0%)          │ 150 (50.0%)          │ 225 (50.0%)          │
└────────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┘
```

---

## 4. Semantic Overlap Design

To prevent the custom neural classifier from learning shallow shortcut keywords, law-enforcement and judicial terminology was purposefully distributed across all three classes.

```
                      LAW-ENFORCEMENT KEYWORD DISTRIBUTION
┌──────────────────────┬──────────────────────┬──────────────────────┬──────────────────────┐
│ Term / Token         │ Phishing (750)       │ Legitimate (750)     │ Advisory (750)       │
├──────────────────────┼──────────────────────┼──────────────────────┼──────────────────────┤
│ पोलीस (Marathi)      │ 76 occurrences       │ 39 occurrences       │ 58 occurrences       │
│ police (English/Latn)│ 253 occurrences      │ 151 occurrences      │ 262 occurrences      │
│ cbi                  │ 93 occurrences       │ 47 occurrences       │ 74 occurrences       │
│ fir                  │ 122 occurrences      │ 66 occurrences       │ 0 occurrences        │
│ कोर्ट (Marathi)      │ 25 occurrences       │ 13 occurrences       │ 6 occurrences        │
│ court (English/Latn) │ 275 occurrences      │ 134 occurrences      │ 90 occurrences       │
│ warrant              │ 208 occurrences      │ 0 occurrences        │ 49 occurrences       │
│ अटक (Marathi)        │ 58 occurrences       │ 0 occurrences        │ 41 occurrences       │
│ cyber                │ 104 occurrences      │ 0 occurrences        │ 223 occurrences      │
└──────────────────────┴──────────────────────┴──────────────────────┴──────────────────────┘
```

### Discriminative Intent Principles:
1. **Phishing Intent:** Impersonation accompanied by urgent coercive action, demands for private UPI/wire transfers, threats of physical arrest, or commands to remain on private video calls in isolation.
2. **Legitimate Intent:** Routine administrative process updates, procedural summons without money demands, official postal dispatch tracking, and public civic circulars.
3. **Protective Advisory Intent:** Explicit guidance debunking digital arrest, public helpline reporting instructions (1930), and statutory warnings against online fraud.

---

## 5. URL Balance and Counterfactual Robustness

In Phase 6.4.4, candidate model `candidate_v3_seed202` demonstrated a 69.23% flip rate when phishing URLs were removed. Synthetic Dataset v4 resolves this dependency by ensuring:
- **Exact 50.0% URL Balance:** 1,125 URL-bearing records and 1,125 URL-free records across the 2,250-record corpus.
- **URL-Free Extortion Fraud:** Phishing templates include realistic telephone intimidation:
  > *"तात्काळ इशारा: सीबीआय सायबर सेलकडून तुमच्या नावावर बेकायदेशीर पार्सल जप्त. डिजिटल अटकेपासून सुटण्यासाठी तातडीने 9800000001 वर संपर्क करा आणि व्हिडिओ कॉलवर हजर राहा."*
- **URL-Bearing Legitimate & Advisory Notices:** Benign public service links (`https://ecourts-causelist-portal.invalid`, `https://passport-police-clearance.invalid`, `https://national-cyber-helpline-1930.invalid`) train the model that links do not inherently signal malice.

---

## 6. Language Balance

Linguistic distribution reflects real-world Indian communication across Devanagari script, Romanized Marathi, Indian English, and code-switched SMS/WhatsApp messages:
- **Devanagari Marathi (`mr`):** 585 records (26.0%)
- **Romanized Marathi (`mr-Latn`):** 585 records (26.0%)
- **Indian English (`en`):** 540 records (24.0%)
- **Code-Switched (`mr-en`):** 540 records (24.0%)

---

## 7. Digital-Arrest Scenario Coverage

The dataset comprehensively covers contemporary digital-arrest and extortion vectors:
- **Narcotics Parcel Seizure:** Fake parcels intercepted with contraband (MDMA, banned pharmaceuticals).
- **Video Call Confinement:** Fraudsters directing victims into Skype/WhatsApp video calls with artificial police stations.
- **National Investigation Agency (NIA):** Cross-border terror funding summons in qualification.
- **Counter-Extortion Advisories:** I4C, MHA, CBI, and TRAI bulletins clarifying that digital arrest does not exist under Indian law.

---

## 8. Legitimate Government Notification Coverage

Legitimate scenarios prevent civilian false alarms by modeling genuine administrative communications:
- **Passport Police Verification:** Official reminders to present identity documents at local police stations.
- **Police Lost Property Receipts:** Automated acknowledgments for lost items under non-cognizable reports.
- **eCourts Cause-Lists:** Hearing schedule notifications and routine witness appearance summonses.
- **Public Civic Notices:** Municipal water pipeline shutdowns, smartcard DL dispatch, and tax assessment deadlines.

---

## 9. Protective-Advisory Coverage

Advisory scenarios teach the model to distinguish safety bulletins from scams even when they cite scam terms:
- **National Cyber Helpline 1930:** Explaining the "golden hour" financial freezing mechanism.
- **Predatory Loan App Alerts:** Warning against photo morphing and unauthorized NBFC collection agents.
- **PIB Fact Check Bulletins:** Debunking viral fake subsidy letters and processing fees.
- **Bar Council Alerts:** Warning against fake advocate legal notices demanding private settlements.

---

## 10. Cross-Partition Leakage Audit

The automated audit script [`scripts/audit_synthetic_corpus_v4.py`](file:///C:/Users/prati/seva-cyber-sandbox/scripts/audit_synthetic_corpus_v4.py) confirmed:
1. **Record ID Leakage:** 0 shared IDs.
2. **Campaign Family Leakage:** 0 shared campaign families across partitions.
3. **Scenario Category Leakage:** 0 shared scenario categories across partitions.
4. **Exact Text Leakage:** 0 shared normalized text strings across any partition boundary.
5. **Near-Duplicate Jaccard Similarity:** Max sampled 3-gram character Jaccard similarity across partitions was **0.3241** (well below the 0.85 threshold), confirming structural template divergence.

---

## 11. SHA-256 Manifests

All generated artifacts are pinned with cryptographic digests:

```
                            CRYPTOGRAPHIC DIGEST REGISTRY
┌────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────────────┐
│ File Path                                              │ SHA-256 Digest                                                   │
├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ Training Corpus (1,500 records):                       │                                                                  │
│ data/generated/v4/synthetic_training_corpus.jsonl      │ 6abd8b2b2daa25d6f8bc0263e588d0a3410fd9bae8fb82632b5fe826cb1cc93f │
│ Training Manifest:                                     │                                                                  │
│ data/generated/v4/training_manifest.json               │ fd0e22026a35f7f4fd9f469269382f179b86768b3c2785e36bc33f278446b1d8 │
├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ Development Corpus (300 records):                      │                                                                  │
│ data/generated/v4/synthetic_dev_corpus.jsonl           │ 4814d15a93119eb9934d0ef4127612009b60dc3f5ab607e58d45f349723f9930 │
│ Development Manifest:                                  │                                                                  │
│ data/generated/v4/dev_manifest.json                    │ c49065907b1403ac659242a9205ac975e64c3ffda8e8683c5709a047ba614a77 │
├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ Qualification Corpus (450 records, SEALED):            │                                                                  │
│ data/generated/v4/synthetic_qualification_corpus.jsonl │ d9a3f4a861d971dfb8716f96f7233c42d8291de85ff070ed93893643caa81f7e │
│ Qualification Manifest:                                │                                                                  │
│ data/generated/v4/qualification_manifest.json          │ 865873d9e5361f3be4553ec2ee9d0a2aa221931c82809015bacf549f58b4e912 │
├────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ Corpus Consolidated Manifest:                          │                                                                  │
│ data/generated/v4/v4_corpus_manifest.json              │ f46b73cd2ed5c73063c91777d736c0ea4f040770a89fbdafe2fadea12555cec0 │
│ Automated Quality Audit Report:                        │                                                                  │
│ data/generated/v4/v4_dataset_audit_report.json         │ b167a5da7ce012d27d225c09b92d877181f782121a514c1b9aa92381d3ff834d │
│ v4 Qualification Exposure Ledger:                      │                                                                  │
│ evaluation/qualification/exposure_ledger_v4.json       │ 9baaaaa3ddce6e426c6a330ed21456fb0cc65d3d0c061795ecfb87c669ff21e3 │
└────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────┘
```

---

## 12. Qualification Lifecycle Status

The v4 qualification partition (`d9a3f4a861d9...`) is held back as a pristine, one-time qualification benchmark:
- **Manifest Lifecycle State:** `sealed_independent_benchmark`
- **Exposure Ledger Status:** `UNEXPOSED` ([`evaluation/qualification/exposure_ledger_v4.json`](file:///C:/Users/prati/seva-cyber-sandbox/evaluation/qualification/exposure_ledger_v4.json))
- **Exposure Count:** `0`
- **Events Recorded:** `[]`
- **Evaluation Status:** **Zero model predictions, evaluations, or retraining passes have been executed against this partition.**

---

## 13. Test Results

The dedicated test suite [`tests/test_phase6_4_6_dataset_v4.py`](file:///C:/Users/prati/seva-cyber-sandbox/tests/test_phase6_4_6_dataset_v4.py) executes 27 automated tests covering schema, partitions, balance, semantic overlap, privacy, manifests, and system invariance.

```
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-8.4.2, pluggy-1.7.0
rootdir: C:\Users\prati\seva-cyber-sandbox
configfile: pytest.ini
collected 27 items

tests\test_phase6_4_6_dataset_v4.py ...........................          [100%]

============================= 27 passed in 0.51s ==============================
```

The overall repository test suite stands at **465 passing tests (100% pass rate in 39.90s)**.

---

## 14. Existing Artifact Integrity

1. **v2 Synthetic Corpus:**
   - `synthetic_training_corpus.jsonl`: `8871bf7f...` (UNTOUCHED)
   - `synthetic_validation_corpus.jsonl`: `77911f9d...` (UNTOUCHED)
2. **v3 Synthetic Corpus:**
   - `synthetic_training_corpus.jsonl`: `f8143880...` (UNTOUCHED)
   - `synthetic_dev_corpus.jsonl`: `55e9357a...` (UNTOUCHED)
   - `synthetic_qualification_corpus.jsonl`: `197c62e7...` (UNTOUCHED, SEALED)
3. **Locked Independent Evaluation Partition:**
   - Digest: `9b9c02d438cfca8bd07af89d60bc1d2fb42d460143d016365ab5a1d231ee0cda` (UNTOUCHED)
4. **Model Registry & Runtime:**
   - Active Model: [`custom-mlp-v1.1.0-preproc`](file:///C:/Users/prati/seva-cyber-sandbox/models/experimental_custom_v1/)
   - Operating Mode: `shadow`
   - Score Delta: `0`

---

## 15. Remaining Limitations

1. **Synthetic Representation Boundary:** Synthetic corpora provide rigorous linguistic and structural coverage, but cybercriminals continually invent novel social engineering hooks. Synthetic performance does not constitute certified defense against real-world adversarial evasion.
2. **Static Vocabulary Pools:** While randomized slots yield high lexical diversity, live threat actors employ generative LLMs and typographical perturbation.
3. **Zero Human-Reviewed Live Data:** Dataset v4 is 100% synthetic; consensual human feedback features curated in Phase 6.1 remain segregated until future controlled integration.

---

## 16. Final Verdict

### Final Phase Verdict: `PASS`

**Compliance Summary:**
- **Digital Arrest & Extortion Phishing:** Thoroughly integrated across 10 training, 2 dev, and 3 qualification families.
- **Legitimate Government Notifications:** Balanced across passport, police, eCourts, municipal, and hospital services.
- **Protective Advisories:** Natural scam vocabulary embedded across I4C, CBI, RBI, and TRAI safety alerts.
- **URL Independence:** Exactly 50.0% URL-free and 50.0% URL-bearing across every partition and class.
- **Multilingual Equity:** Balanced representation across Marathi Devanagari, Romanized Marathi, English, and Mixed.
- **Partition Isolation:** 45 disjoint campaign families; zero cross-partition leakage; qualification sealed in exposure ledger.
- **Zero Invariance Regression:** All 465 repository tests pass; production model registry and active configuration untouched.

**STOP CONDITION:** Phase 6.4.6 is complete. No model training, evaluation, or promotion has been initiated.
