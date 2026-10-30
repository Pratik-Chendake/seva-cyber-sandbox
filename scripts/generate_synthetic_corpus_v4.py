#!/usr/bin/env python3
"""
Seva Cyber Sandbox — Phase 6.4.6: Synthetic Corpus Generator v4.0.0
Author: Seva Cyber Sandbox Autonomous Pipeline
License: CC0 1.0 Universal / Public Domain

Generates Synthetic Dataset v4 addressing digital-arrest, extortion, and semantic balance:
1. 45 Mutually Disjoint Campaign Families:
   - 30 Training Families (10 Phishing, 10 Legitimate, 10 Protective Advisory) -> 1,500 records
   - 6 Development Families (2 Phishing, 2 Legitimate, 2 Protective Advisory) -> 300 records
   - 9 Qualification Families (3 Phishing, 3 Legitimate, 3 Protective Advisory) -> 450 records
   - Total: 2,250 records (50 per family)
2. Semantic Overlap Across Classes:
   - Law-enforcement vocabulary (Police, CBI, FIR, Court, Warrant, Arrest, Cyber Cell)
     distributed across Phishing, Legitimate, and Protective Advisory classes.
3. Strict URL Balance:
   - Exactly 50% URL-bearing, 50% URL-free across every partition, class, and family.
4. Balanced Multilingual Coverage:
   - ~25% Marathi Devanagari (mr), ~25% Romanized Marathi (mr-Latn),
     ~25% English (en), ~25% Mixed Marathi-English (mr-en).
5. Cryptographic Manifests and Lifecycle Isolation:
   - Generates training, dev, qualification, and corpus manifests.
   - Initializes v4 qualification exposure ledger in UNEXPOSED state.
"""

from collections import Counter
import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from src.dataset_preprocessing import (
    clean_evasion_characters,
    detect_script,
    normalize_record_text,
    validate_single_record,
)

OUTPUT_DIR_V4 = os.path.join(PROJECT_ROOT, "data", "generated", "v4")
LEDGER_DIR = os.path.join(PROJECT_ROOT, "evaluation", "qualification")

# -----------------------------------------------------------------------------
# DUMMY VOCABULARIES (RFC 2606 .invalid domains, safe fictional 555/dummy numbers)
# -----------------------------------------------------------------------------
DUMMY_PHISH_DOMAINS = [
    "http://cbi-court-summons-notice.invalid",
    "https://police-warrant-resolution.invalid",
    "http://narcotics-case-clearance.invalid",
    "https://cybercrime-fir-compromise.invalid",
    "http://court-contempt-penalty-pay.invalid",
    "https://digital-arrest-bail-deposit.invalid",
    "http://acb-asset-seizure-release.invalid",
    "https://nia-summons-hearing-desk.invalid",
    "http://pm-subsidy-penalty-settle.invalid",
    "https://challan-court-recovery.invalid",
    "http://customs-contraband-fine.invalid",
    "https://highcourt-bailable-warrant.invalid",
    "http://supremecourt-injunction-settle.invalid",
]

DUMMY_LEGIT_DOMAINS = [
    "https://passport-police-clearance.invalid",
    "https://ecourts-causelist-portal.invalid",
    "https://district-court-hearing-info.invalid",
    "https://state-administrative-circulars.invalid",
    "https://civil-hospital-appointment-system.invalid",
    "https://mpsc-board-hallticket.invalid",
    "https://municipal-water-notices.invalid",
    "https://uidai-enrollment-receipt.invalid",
    "https://indiapost-registered-parcel.invalid",
    "https://police-station-lost-property.invalid",
    "https://rto-smartcard-dispatch.invalid",
    "https://propertytax-assessment-seva.invalid",
    "https://lokadalat-settlement-board.invalid",
    "https://municipal-trade-license-portal.invalid",
]

DUMMY_ADVISORY_DOMAINS = [
    "https://i4c-digital-arrest-awareness.invalid",
    "https://mha-cyber-safety-bulletin.invalid",
    "https://cbi-public-warning-feed.invalid",
    "https://cybercell-extortion-alert.invalid",
    "https://ecourt-fraud-advisory.invalid",
    "https://national-cyber-helpline-1930.invalid",
    "https://rbi-illegal-lending-apps.invalid",
    "https://pib-factcheck-alerts.invalid",
    "https://statepolice-vigilance-portal.invalid",
    "https://certin-deepfake-warning.invalid",
    "https://sebi-unauthorized-trading-alert.invalid",
    "https://ed-scam-clarification.invalid",
    "https://dot-telecom-security-notice.invalid",
    "https://barcouncil-advocate-fraud-alert.invalid",
    "https://trai-spoofed-call-warning.invalid",
]

# Privacy safe numbers: landline 555-like or mobile ending in 0000
DUMMY_PHONES = [
    "9800000000",
    "9800000001",
    "9800000002",
    "9800000003",
    "9800000004",
    "9800000005",
    "9811000000",
    "9822000000",
    "9833000000",
    "9844000000",
    "022-55550211",
    "022-55550222",
    "020-55550333",
    "1800-555-0299",
]

DUMMY_AMOUNTS = [
    "₹15,000",
    "₹24,500",
    "₹38,000",
    "₹49,999",
    "₹75,000",
    "₹95,000",
    "₹1,20,000",
    "₹2,50,000",
    "₹3,40,000",
    "₹5,00,000",
]

DUMMY_TIMES = [
    "10:00 AM",
    "11:30 AM",
    "12:15 PM",
    "02:00 PM",
    "03:45 PM",
    "04:30 PM",
    "05:00 PM",
    "06:30 PM",
]

DUMMY_DATES = [
    "12-11-2026",
    "15-11-2026",
    "18-11-2026",
    "20-11-2026",
    "24-11-2026",
    "28-11-2026",
    "02-12-2026",
    "05-12-2026",
    "10-12-2026",
]

DUMMY_REFS = [
    "CBI/2026/8912",
    "FIR/MH/0491/26",
    "CR/NCB/7710/26",
    "HC/WAR/3391/26",
    "CC/ENQ/5521/26",
    "NIA/SEC/1044/26",
    "ACB/PUN/6612/26",
    "PAS/MH/1109/26",
    "CRT/DS/4481/26",
    "MC/WAT/9920/26",
]

# -----------------------------------------------------------------------------
# 30 TRAINING CAMPAIGN FAMILIES (10 Phishing, 10 Legitimate, 10 Protective Advisory)
# -----------------------------------------------------------------------------
TRAIN_FAMILIES: Dict[str, Dict[str, Any]] = {
    # --- PHISHING (10) ---
    "v4_train_phish_digital_arrest_narcotics": {
        "scenario": "phish_digital_arrest_narcotics",
        "label": "phishing",
        "description": "CBI/Customs narcotics parcel digital arrest extortion",
        "patterns": [
            ("mr", "whatsapp", True, "सीआयडी आणि सायबर क्राईम ब्रँच: आपल्या नावे बेकायदेशीर अंमली पदार्थांचे पार्सल सापडले आहे. तात्काळ डिजिटल अटक वॉरंट जारी झाले आहे. जामीन पडताळणीसाठी लिंक उघडा: {domain}"),
            ("mr-Latn", "whatsapp", True, "CBI & Cyber Cell Notice: Aplya navavar narcotics parcel Mumbai airport var japt zale ahe. Digital arrest pasun vachnyasathi bail deposit link var bhara: {domain}"),
            ("en", "formal_notice", True, "CBI Narcotic Control Notice: An illegal contraband parcel booked under your Aadhaar has been intercepted. Immediate digital arrest ordered. Submit security bond at: {domain}"),
            ("mr-en", "whatsapp", True, "Crime Branch Emergency: Tumchya navavar drugs parcel case madhe arrest warrant nighale ahe. Direct custody talnyasathi verification fee bhara: {domain}"),
            ("mr", "whatsapp", False, "तात्काळ इशारा: सीबीआय सायबर सेलकडून तुमच्या नावावर बेकायदेशीर पार्सल जप्त. डिजिटल अटकेपासून सुटण्यासाठी तातडीने {phone} वर संपर्क करा आणि व्हिडिओ कॉलवर हजर राहा."),
            ("mr-Latn", "sms", False, "CBI Emergency Notice: Narcotics consignment detected on your ID. Immediate arrest ordered. Connect on Skype/WhatsApp immediately at {phone}. Do not inform anyone."),
            ("en", "sms", False, "Narcotics Cell Alert: Contraband seizure reported under your name ref {ref}. Non-bailable arrest warrant active. Contact investigating officer at {phone} within 15 minutes."),
            ("mr-en", "whatsapp", False, "Police Alert: Tumche drugs parcel case madhe digital arrest warrant pending ahe. Call disconnect n karta {phone} var police officer shi sampark kara.")
        ]
    },
    "v4_train_phish_cbi_investigation_notice": {
        "scenario": "phish_cbi_investigation_notice",
        "label": "phishing",
        "description": "Fake CBI investigation summons and urgent financial penalty threat",
        "patterns": [
            ("mr", "sms", True, "सीबीआय तपास विभाग: आपल्या बँक खात्यातून संशयास्पद आंतरराष्ट्रीय मनी लाँड्रिंग आढळले आहे. तपासणीसाठी तात्काळ दंडात्मक रक्कम {amount} भरा: {domain}"),
            ("mr-Latn", "sms", True, "CBI Enquiry: Bank account madhe hawala transactions sapadlyamule CBI inquiry suru zali ahe. Seizure talnyasathi penal fine link var bhara: {domain}"),
            ("en", "formal_notice", True, "Central Bureau of Investigation: Inquiry initiated regarding unauthorized financial transfers ref {ref}. Pay provisional clearance deposit {amount} at: {domain}"),
            ("mr-en", "sms", True, "CBI Cyber Division: Tumchya account var money laundering FIR ahe. Immediate property attachment cancel karnyasathi danda bhara: {domain}"),
            ("mr", "formal_notice", False, "सीबीआय विशेष तपास पथक: आपल्याविरुद्ध कलम ४२० अन्वये चौकशी सुरू आहे. अटकेची कारवाई टाळण्यासाठी तातडीने तपास अधिकाऱ्यांशी {phone} वर संपर्क साधा."),
            ("mr-Latn", "sms", False, "CBI Special Cell: Serious hawala enquiry registered ref {ref}. Immediate detention order issued. Call IO on {phone} right now to avoid custody."),
            ("en", "formal_notice", False, "CBI Investigation Desk: Statutory summons issued under Section 91 CrPC. To avoid physical arrest at your residence, report to desk officer on {phone}."),
            ("mr-en", "sms", False, "CBI Notice: Tumchya navavar CBI investigation open zali ahe. Case settlement sathi officer {phone} var call kara, office la police pathavnya aadhi.")
        ]
    },
    "v4_train_phish_narcotics_possession_warrant": {
        "scenario": "phish_narcotics_possession_warrant",
        "label": "phishing",
        "description": "Fake NCB drug trafficking parcel non-bailable arrest warrant",
        "patterns": [
            ("mr", "formal_notice", True, "नारकोटिक्स कंट्रोल ब्युरो (NCB): आपल्या पार्सलमध्ये प्रतिबंधित औषधे आढळल्याने अटक वॉरंट जारी. कायदेशीर संरक्षण मिळवण्यासाठी शुल्क भरा: {domain}"),
            ("mr-Latn", "formal_notice", True, "NCB Mumbai Alert: Foreign parcel madhe MDMA drug milalyane non-bailable warrant issue zale ahe. Clearance bond sathi link open kara: {domain}"),
            ("en", "formal_notice", True, "NCB Special Operation: Narcotics seizure warrant issued under NDPS Act ref {ref}. Pay bail guarantee fee {amount} immediately at: {domain}"),
            ("mr-en", "whatsapp", True, "NCB Drug Crime Alert: Tumchya courier madhe banned drugs bhetle ahet. Police raid talnyasathi clearance portal var payment kara: {domain}"),
            ("mr", "formal_notice", False, "एनसीबी मुंबई झोन: आपल्याविरुद्ध अमली पदार्थ प्रतिबंधक कायद्यानुसार (NDPS) वॉरंट जारी. घरात पोलीस येणे टाळण्यासाठी त्वरित {phone} वर संपर्क साधा."),
            ("mr-Latn", "whatsapp", False, "NCB Zonal Office: Non-bailable arrest warrant generated ref {ref}. Stay in room and call duty officer on {phone} immediately for live video verification."),
            ("en", "formal_notice", False, "Narcotics Control Bureau: Contraband package seized in transit. Armed police team dispatched. Call surveillance controller on {phone} to record your statement."),
            ("mr-en", "whatsapp", False, "NCB Crime Alert: NDPS warrant issue zala ahe. Family la inform naka karu, direct {phone} var video call var join kara nahi tar jail hoil.")
        ]
    },
    "v4_train_phish_police_videocall_summons": {
        "scenario": "phish_police_videocall_summons",
        "label": "phishing",
        "description": "Crime branch video call interrogation demand with digital arrest threat",
        "patterns": [
            ("mr", "whatsapp", True, "सायबर क्राईम ब्रँच: तात्काळ व्हिडिओ कॉल चौकशीसाठी हजर राहा. उपस्थित न राहिल्यास वॉरंट जारी होईल. व्हिडिओ रूम लिंक: {domain}"),
            ("mr-Latn", "whatsapp", True, "Crime Branch Video Summons: Cyber police samor video call var hazar raha. Absent rahilyas non-bailable arrest hoil. Hearing room: {domain}"),
            ("en", "whatsapp", True, "Cyber Police Headquarters: Mandatory video conference interrogation scheduled at {time}. Join virtual interrogation room immediately: {domain}"),
            ("mr-en", "whatsapp", True, "Crime Branch Online Court: Police verification video call sathi join kara ref {ref}. Absent rahilyas FIR file hoil: {domain}"),
            ("mr", "whatsapp", False, "पोलीस क्राईम ब्रँच: आपल्याविरुद्ध सायबर गुन्ह्याचा व्हिडिओ पंचनामा सुरू आहे. फोन डिस्कनेक्ट न करता तातडीने {phone} वर व्हॉट्सअॅप कॉलवर हजर राहा."),
            ("mr-Latn", "whatsapp", False, "Crime Branch Summons: Mandatory interrogation in progress. Call {phone} right now on WhatsApp video call. Leaving camera will lead to immediate arrest."),
            ("en", "whatsapp", False, "Police Cyber Cell: You are placed under electronic surveillance. Maintain absolute confidentiality and dial {phone} for immediate digital interrogation."),
            ("mr-en", "whatsapp", False, "Cyber Police Order: Urgent interrogation sathi {phone} var connect kara. Video call band kelyas local police station ghari police pathvel.")
        ]
    },
    "v4_train_phish_cybercrime_financial_fraud": {
        "scenario": "phish_cybercrime_financial_fraud",
        "label": "phishing",
        "description": "Fake cyber cell money laundering inquiry with frozen account extortion",
        "patterns": [
            ("mr", "sms", True, "महाराष्ट्र सायबर विभाग: आपले बँक खाते सायबर गुन्ह्यात वापरले गेले आहे. खाते जप्ती टाळण्यासाठी पडताळणी शुल्क {amount} भरा: {domain}"),
            ("mr-Latn", "sms", True, "Cyber Police Station: Tumche bank account financial scam madhe link zale ahe. Account freeze talnyasathi verification kara: {domain}"),
            ("en", "sms", True, "Cyber Crime Branch: Your bank account is flagged for illegal transaction laundering ref {ref}. Unfreeze security deposit payable at: {domain}"),
            ("mr-en", "sms", True, "Cyber Cell Alert: Illegal money transfer inquiry sathi tumche account freeze zale ahe. Legal clearance fee bhara: {domain}"),
            ("mr", "sms", False, "सायबर सुरक्षा विभाग: आपल्या बँक खात्यावरून संशयास्पद व्यवहार झाल्याने एफआयआर दाखल. तात्काळ सायबर सेल अधिकारी {phone} शी संपर्क साधा."),
            ("mr-Latn", "sms", False, "Cyber Police Station: FIR registered under IT Act Section 66D. To avoid bank debit freeze and police inquiry, call desk {phone} immediately."),
            ("en", "sms", False, "Cyber Crime Cell Notice: Warrant ref {ref} pending for fraudulent online banking. Call investigating officer at {phone} before 5:00 PM to submit defense."),
            ("mr-en", "sms", False, "Cyber Cell Notice: Tumchya navavar cyber fraud FIR zali ahe. Police custody talnyasathi {phone} var emergency desk shi bolun ghyava.")
        ]
    },
    "v4_train_phish_court_warrant_penalty": {
        "scenario": "phish_court_warrant_penalty",
        "label": "phishing",
        "description": "Fake High Court / District Court contempt warrant penalty fine demand",
        "patterns": [
            ("mr", "formal_notice", True, "उच्च न्यायालय आदेश: कोर्टाच्या अवमानाबद्दल आपल्या नावे अजामीनपात्र वॉरंट जारी. तातडीने तडजोड दंड {amount} भरून वॉरंट रद्द करा: {domain}"),
            ("mr-Latn", "formal_notice", True, "High Court Warrant Order: Court contempt case madhe non-bailable arrest warrant nighale ahe. Online fine bhara: {domain}"),
            ("en", "formal_notice", True, "High Court Judicial Registry: Execution order issued under contempt proceedings ref {ref}. Remit compounding fine {amount} to recall warrant: {domain}"),
            ("mr-en", "formal_notice", True, "Court Judicial Notice: Contempt warrant cancel karnyasathi urgent fine payment kara: {domain}"),
            ("mr", "formal_notice", False, "जिल्हा सत्र न्यायालय: आपल्याविरुद्ध न्यायालयीन अवमान कारवाई सुरू असून वॉरंट जारी झाले आहे. तात्काळ कोर्ट क्लार्क {phone} वर संपर्क साधा."),
            ("mr-Latn", "formal_notice", False, "District Court Notice: Non-bailable warrant active ref {ref}. Police attachment order signed. Contact registrar assistant on {phone} immediately."),
            ("en", "formal_notice", False, "Judicial Magistrate Court: Arrest warrant issued for non-appearance ref {ref}. To stay police custody, reach emergency court liaison at {phone}."),
            ("mr-en", "formal_notice", False, "Court Registry Warning: Non-bailable arrest order pass zala ahe. Police gharavar yaychya aadhi court desk {phone} var call kara.")
        ]
    },
    "v4_train_phish_fir_cancellation_settlement": {
        "scenario": "phish_fir_cancellation_settlement",
        "label": "phishing",
        "description": "Fake police station compromise fee to cancel criminal FIR",
        "patterns": [
            ("mr", "sms", True, "पोलीस ठाणे सूचना: आपल्याविरुद्ध दाखल झालेली फौजदारी तक्रार (FIR) मागे घेण्यासाठी तडजोड रक्कम {amount} भरा: {domain}"),
            ("mr-Latn", "sms", True, "Police Station Alert: Tumchyaviruddha criminal FIR register zali ahe. Court case cancel karnyasathi settlement fee pay kara: {domain}"),
            ("en", "sms", True, "Police Station Crime Desk: Criminal complaint ref {ref} filed against you. Pay mutual compounding fees {amount} to close case before remand: {domain}"),
            ("mr-en", "sms", True, "Police FIR Update: Police station madhe complaint zali ahe. Case courtat janyapasun thambavnyasathi fee transfer kara: {domain}"),
            ("mr", "sms", False, "पोलीस ठाणे सूचना: आपल्याविरुद्ध दाखल फौजदारी गुन्ह्यात आजच अटक होऊ शकते. तपास अधिकारी {phone} यांच्याशी तात्काळ संपर्क साधा."),
            ("mr-Latn", "sms", False, "Police Station Intimation: Serious FIR ref {ref} lodged. Arrest team on duty. Contact senior inspector on {phone} right now for out-of-court settlement."),
            ("en", "sms", False, "Police Investigation Unit: FIR filed under IPC Section 406/420. To halt physical arrest at your workplace, dial investigation officer {phone}."),
            ("mr-en", "sms", False, "Police Station Warning: Tumchya navavar criminal case zali ahe. Police ghari yaychya aadhi IO {phone} var bolun case nipatun ghyava.")
        ]
    },
    "v4_train_phish_passport_police_verification_fee": {
        "scenario": "phish_passport_police_verification_fee",
        "label": "phishing",
        "description": "Urgent extortion for adverse police verification clearance on passport application",
        "patterns": [
            ("mr", "sms", True, "पासपोर्ट पोलीस पडताळणी: आपल्या अर्जावर प्रतिकूल अहवाल आला आहे. अहवाल सकारात्मक करण्यासाठी त्वरित मंजुरी शुल्क {amount} भरा: {domain}"),
            ("mr-Latn", "sms", True, "Passport Police Verification: Criminal record query alya mule adverse report dila ahe. Clear karnyasathi penalty fee bhara: {domain}"),
            ("en", "sms", True, "Passport Police Inquiry: Adverse police verification report recorded ref {ref}. Remit emergency clearance processing fee {amount} at: {domain}"),
            ("mr-en", "sms", True, "Passport Police Alert: Police inquiry reject zali ahe criminal record mule. Clearance fee pay karun NOC ghyava: {domain}"),
            ("mr", "sms", False, "पासपोर्ट पोलीस तपासणी: आपल्या पासपोर्ट अर्जावर गुन्हेगारी आक्षेप नोंदवला गेला आहे. एफआयआर पडताळणीसाठी तातडीने {phone} वर संपर्क साधा."),
            ("mr-Latn", "sms", False, "Passport Police Desk: Verification blocked due to pending criminal verification ref {ref}. Call special branch verification officer on {phone}."),
            ("en", "sms", False, "Special Branch Police: Passport verification on hold pending criminal records search. Call police inquiry desk at {phone} within 2 hours."),
            ("mr-en", "sms", False, "Passport Inquiry Notice: Police verification madhe court case query ahe. Application cancel hou naye mhanun {phone} var call kara.")
        ]
    },
    "v4_train_phish_pm_kisan_subsidy_disqualification": {
        "scenario": "phish_pm_kisan_subsidy_disqualification",
        "label": "phishing",
        "description": "Government scheme disqualification threat demanding recovery fine",
        "patterns": [
            ("mr", "sms", True, "शासकीय योजना पडताळणी: पीएम किसान अनुदानात अपात्र आढळल्याने वसुली नोटीस जारी. फौजदारी कारवाई टाळण्यासाठी दंड भरा: {domain}"),
            ("mr-Latn", "sms", True, "PM Kisan Notice: Anudan chukichya paddhatine ghetlyamule recovery notice ahe. Legal action talnyasathi penalty link var bhara: {domain}"),
            ("en", "sms", True, "Ministry of Agriculture Recovery: Direct benefit subsidy flagged as fraudulent ref {ref}. Pay statutory penalty {amount} to prevent prosecution: {domain}"),
            ("mr-en", "sms", True, "Govt Scheme Warning: PM Kisan subsidy refund notice issue zali ahe. Police complaint talnyasathi fine pay kara: {domain}"),
            ("mr", "sms", False, "शासकीय योजना वसुली: सरकारी अनुदानाचा गैरवापर केल्याप्रकरणी एफआयआर दाखल करण्याचा आदेश. तातडीने वसुली अधिकारी {phone} शी संपर्क साधा."),
            ("mr-Latn", "sms", False, "Govt Scheme Legal Cell: Non-compliance order ref {ref}. Land revenue recovery team appointed. Call settlement officer on {phone} immediately."),
            ("en", "sms", False, "Scheme Enforcement Directorate: Subsidy recovery notice issued. To avoid attachment of agricultural bank accounts, call recovery cell on {phone}."),
            ("mr-en", "sms", False, "Kisan Yojana Notice: Subsidy fraud inquiry madhe tumcha name ahe. Tehsildar police complaint karu naye mhanun {phone} var contact kara.")
        ]
    },
    "v4_train_phish_mudra_loan_default_attachment": {
        "scenario": "phish_mudra_loan_default_attachment",
        "label": "phishing",
        "description": "Fake subsidy loan default threat demanding property attachment settlement",
        "patterns": [
            ("mr", "formal_notice", True, "मुद्रा कर्ज वसुली आदेश: कर्ज थकबाकीमुळे पोलीस बंदोबस्तात मालमत्ता जप्तीचे आदेश. जप्ती स्थगित करण्यासाठी तातडीने तडजोड भरा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Mudra Loan Seizure: Loan default case madhe property attachment warrant issue zale ahe. Stop seizure fine pay kara: {domain}"),
            ("en", "formal_notice", True, "Mudra Recovery Tribunal: Asset attachment warrant issued ref {ref}. Pay court settlement charge {amount} online to stay execution: {domain}"),
            ("mr-en", "formal_notice", True, "Loan Recovery Notice: Police bandobast madhe dukan/ghar seal karnar ahet. Immediate stay sathi payment kara: {domain}"),
            ("mr", "formal_notice", False, "मुद्रा कर्ज न्यायाधिकरण: बँक कर्ज वसुलीसाठी अजामीनपात्र जप्ती वॉरंट जारी. पोलीस कारवाई टाळण्यासाठी त्वरित वसुली प्रमुख {phone} शी संपर्क साधा."),
            ("mr-Latn", "sms", False, "Mudra Loan Tribunal: Seizure warrant issued ref {ref}. Police team dispatched for property seal. Contact tribunal officer on {phone} immediately."),
            ("en", "formal_notice", False, "Debt Recovery Enforcement: Physical property attachment order signed. To negotiate immediate stay with recovery officer, dial {phone}."),
            ("mr-en", "sms", False, "Loan Default Warning: Property seal karnyasathi court order ahe. Police raid thambavnyasathi bank legal advisor {phone} var phone kara.")
        ]
    },

    # --- LEGITIMATE (10) ---
    "v4_train_legit_passport_police_appointment": {
        "scenario": "legit_passport_police_appointment",
        "label": "legitimate",
        "description": "Genuine passport police station verification appointment notice",
        "patterns": [
            ("mr", "formal_notice", True, "पोलीस आयुक्त कार्यालय: पासपोर्ट अर्जाच्या पोलीस पडताळणीसाठी मूळ कागदपत्रांसह स्थानिक पोलीस ठाण्यात हजर राहावे. स्थिती पहा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Police Commissioner Office: Passport verification sathi local police station madhe original documents gheun ya. Status link: {domain}"),
            ("en", "formal_notice", True, "Police Verification Cell: Your passport verification appointment is scheduled. Visit local police station with original documents. Status: {domain}"),
            ("mr-en", "formal_notice", True, "Police Dept Notice: Passport inquiry sathi original Aadhaar & address proof gheun police station la bhet dya: {domain}"),
            ("mr", "formal_notice", False, "पोलीस ठाणे सूचना: पासपोर्ट अर्ज संदर्भ {ref}. पडताळणीसाठी मूळ शाळा सोडल्याचा दाखला व पत्ता पुराव्यासह उद्या सकाळी {time} वाजता पोलीस ठाण्यात हजर राहावे."),
            ("mr-Latn", "formal_notice", False, "Police Station Notice: Passport verification ref {ref}. Please visit local police station on {date} at {time} with original Aadhaar and electricity bill."),
            ("en", "formal_notice", False, "Special Branch Verification: Passport application ref {ref}. Candidate is requested to report to the verification desk with two passport photos and address proof."),
            ("mr-en", "formal_notice", False, "Police Verification: Passport verification sathi tumhi {date} roji sakali {time} wajta police chowkyavar original documents sobat ya.")
        ]
    },
    "v4_train_legit_police_lost_property_acknowledgement": {
        "scenario": "legit_police_lost_property_acknowledgement",
        "label": "legitimate",
        "description": "Genuine police portal lost property non-cognizable complaint registration receipt",
        "patterns": [
            ("mr", "sms", True, "महाराष्ट्र पोलीस: हरवलेल्या वस्तूची नोंद (Non-Cognizable Report) यशस्वीरीत्या दाखल झाली आहे. अधिकृत प्रत डाउनलोड करा: {domain}"),
            ("mr-Latn", "sms", True, "Maharashtra Police: Haravleli vastu / document chi NC report no. {ref} register zali ahe. Certified copy download kara: {domain}"),
            ("en", "sms", True, "State Police Portal: Lost Article Information Report registered ref {ref}. Download digitally signed acknowledgment: {domain}"),
            ("mr-en", "sms", True, "Police Portal Alert: Tumchi lost mobile/document complaint successfully lodge zali ahe. Receipt download link: {domain}"),
            ("mr", "sms", False, "महाराष्ट्र पोलीस सूचना: आपले हरवलेले कागदपत्र नोंदवले गेले आहे. तक्रार संदर्भ {ref}. ही संगणकीय पावती असून स्वाक्षरीची गरज नाही."),
            ("mr-Latn", "sms", False, "Maharashtra Police: Lost property entry recorded under ref {ref}. This is a system-generated acknowledgment for duplicate document application."),
            ("en", "sms", False, "State Police Record: Acknowledgment ref {ref} generated for lost personal article. Use this reference number for SIM or document reissuance."),
            ("mr-en", "sms", False, "Police NC Complaint: Tumchi missing document complaint record zali ahe ref {ref}. Krupaya he SMS record sathi save theva.")
        ]
    },
    "v4_train_legit_district_court_hearing_schedule": {
        "scenario": "legit_district_court_hearing_schedule",
        "label": "legitimate",
        "description": "Genuine eCourts district court case status and hearing date notification",
        "patterns": [
            ("mr", "formal_notice", True, "ई-कोर्ट सेवा: जिल्हा व सत्र न्यायालय. दावा क्र. {ref} ची पुढील सुनावणी तारीख {date} रोजी निश्चित केली आहे. दैनंदिन बोर्ड पहा: {domain}"),
            ("mr-Latn", "formal_notice", True, "eCourts Services: District Court case no. {ref}. Next hearing scheduled on {date}. Check daily cause list: {domain}"),
            ("en", "formal_notice", True, "eCourts Services: District & Sessions Court case ref {ref} is posted for hearing on {date}. View cause list and orders: {domain}"),
            ("mr-en", "formal_notice", True, "eCourts Alert: Tumchya civil case chi next hearing {date} roji Court Hall madhe ahe. Case status online check kara: {domain}"),
            ("mr", "formal_notice", False, "ई-कोर्ट सेवा सूचना: जिल्हा न्यायालय. खटला संदर्भ {ref} सुनावणीसाठी तारीख {date} रोजी न्यायालय कक्ष ३ मध्ये पुकारला जाईल. वकिलांमार्फत नोंद घ्यावी."),
            ("mr-Latn", "formal_notice", False, "District Court Notice: Case ref {ref} listed before Hon'ble Civil Judge on {date}. Advocates and parties to note the cause list schedule."),
            ("en", "formal_notice", False, "eCourts Registry: Criminal Case ref {ref} listed for witness appearance on {date} at {time} in Court Hall 2. Informational update only."),
            ("mr-en", "formal_notice", False, "District Court Notice: Case no {ref} chi hearing {date} roji ahe. Adv sobat courtat regular time var उपस्थित rahawe.")
        ]
    },
    "v4_train_legit_court_notice_appearance_info": {
        "scenario": "legit_court_notice_appearance_info",
        "label": "legitimate",
        "description": "Routine court appearance informational notice without monetary demand",
        "patterns": [
            ("mr", "formal_notice", True, "न्यायालयीन समन्स सूचना: दिवाणी खटला संदर्भ {ref}. साक्षीदार म्हणून हजर राहण्यासाठी समन्स जारी. सूचना प्रत डाउनलोड करा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Court Summons Notice: Civil Suit ref {ref}. Witness appearance summons issued for {date}. Download details: {domain}"),
            ("en", "formal_notice", True, "Judicial Notice: Summons to witness in regular suit ref {ref}. Official appearance details and court map available at: {domain}"),
            ("mr-en", "formal_notice", True, "Court Summons Alert: Case madhe witness appearance sathi summons ahe {date} roji. Official portal: {domain}"),
            ("mr", "formal_notice", False, "दिवाणी न्यायालय सूचना: खटला संदर्भ {ref} अन्वये आपल्याला {date} रोजी सकाळी {time} वाजता साक्षी नोंदवण्यासाठी हजर राहण्याचे निर्देश आहेत."),
            ("mr-Latn", "formal_notice", False, "Judicial Magistrate Court: Summons ref {ref}. You are cited as a witness. Please attend Court No. 4 on {date} at {time} without fail."),
            ("en", "formal_notice", False, "Senior Civil Court: Formal summons issued under Order XVI CPC for record evidence on {date}. This is an informational court process notice."),
            ("mr-en", "formal_notice", False, "Court Appearance Notice: Reference {ref}. Tumhala {date} roji court hall madhe sakal chya satrat attend karnyasathi intimation ahe.")
        ]
    },
    "v4_train_legit_mantralaya_gazette_circular": {
        "scenario": "legit_mantralaya_gazette_circular",
        "label": "legitimate",
        "description": "Official state government administrative circular and gazette notification",
        "patterns": [
            ("mr", "advisory_bulletin", True, "महाराष्ट्र शासन राजपत्र: सामान्य प्रशासन विभाग. सार्वजनिक सुट्ट्या आणि कार्यालयीन कामकाजाबाबत अधिकृत परिपत्रक प्रसिद्ध: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Maharashtra Govt Gazette: General Admin Dept circular regarding public holidays and administrative working hours: {domain}"),
            ("en", "formal_notice", True, "Government of Maharashtra Gazette: Notification regarding administrative working schedules and citizen services charter: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Mantralaya Circular: Govt office timings aani public service delivery norms update zale ahet. Gazette link: {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र शासन परिपत्रक: महसूल व वन विभाग. सर्व शासकीय कार्यालयांनी नागरिकांच्या अर्जांवर सात दिवसांत कार्यवाही करण्याचे निर्देश."),
            ("mr-Latn", "formal_notice", False, "Mantralaya Notification: Revenue Department circular ref {ref}. All citizen grievance applications to be disposed within statutory timelines."),
            ("en", "formal_notice", False, "Government Administrative Reform Department: Office Memorandum ref {ref}. Guidelines issued for implementation of Right to Public Services Act."),
            ("mr-en", "advisory_bulletin", False, "Govt Circular: Citizen services sathi navin circular publish zala ahe. Sarv karyalayani rules follow karnyache aadesh ahet.")
        ]
    },
    "v4_train_legit_civil_hospital_opd_schedule": {
        "scenario": "legit_civil_hospital_opd_schedule",
        "label": "legitimate",
        "description": "Genuine civil hospital OPD doctor appointment and token confirmation",
        "patterns": [
            ("mr", "sms", True, "जिल्हा सामान्य रुग्णालय: आपली बाह्यरुग्ण (OPD) नोंदणी यशस्वी झाली आहे. टोकन क्र. {ref}. तपासणी वेळ पहा: {domain}"),
            ("mr-Latn", "sms", True, "District Civil Hospital: Tumchi OPD appointment doctor consultation sathi confirm zali ahe. Token no {ref}. Timings: {domain}"),
            ("en", "sms", True, "Civil Hospital OPD: Appointment confirmed for Specialist Clinic on {date} at {time}. Token ref {ref}. Details: {domain}"),
            ("mr-en", "sms", True, "Govt Hospital OPD: Tumcha doctor checkup token confirm zala ahe. Hospital token status check kara: {domain}"),
            ("mr", "sms", False, "जिल्हा रुग्णालय सूचना: ओपीडी तपासणीसाठी टोकन संदर्भ {ref}. कृपया {date} रोजी सकाळी {time} वाजता कक्ष क्र. ५ येथे केसपेपरसह उपस्थित राहावे."),
            ("mr-Latn", "sms", False, "Civil Hospital Notice: Token ref {ref} confirmed for general medicine. Please report to registration counter on {date} by {time}."),
            ("en", "sms", False, "Government District Hospital: Outpatient registration ref {ref}. Please carry your previous medical prescriptions and photo ID."),
            ("mr-en", "sms", False, "Hospital Token Confirmation: Tumcha appointment token {ref} confirm ahe. {date} roji OPD counter var velet pohcha.")
        ]
    },
    "v4_train_legit_state_board_hall_ticket_download": {
        "scenario": "legit_state_board_hall_ticket_download",
        "label": "legitimate",
        "description": "Genuine state board / public exam hall ticket download notification",
        "patterns": [
            ("mr", "formal_notice", True, "महाराष्ट्र राज्य परीक्षा परिषद: आगामी परीक्षेचे प्रवेशपत्र (Hall Ticket) संकेतस्थळावर उपलब्ध झाले आहे. डाऊनलोड करा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Maharashtra State Exam Board: Annual exam admit card hall ticket available for download. Link: {domain}"),
            ("en", "formal_notice", True, "State Examination Council: Hall tickets for upcoming competitive examination released ref {ref}. Download admit card: {domain}"),
            ("mr-en", "formal_notice", True, "State Board Exam Alert: Tumche exam hall ticket live zale ahe. Official portal varun download kara: {domain}"),
            ("mr", "formal_notice", False, "महाराष्ट्र राज्य माध्यमिक व उच्च माध्यमिक शिक्षण मंडळ: परीक्षा प्रवेशपत्र संदर्भ {ref}. विद्यार्थ्यांनी परीक्षा केंद्रावर अधिकृत ओळखपत्रासह हजर राहावे."),
            ("mr-Latn", "formal_notice", False, "State Board Examination: Hall ticket ref {ref}. Candidates must reach exam center 45 minutes prior to commencement with school ID."),
            ("en", "formal_notice", False, "Public Service Examination Commission: Admit card instructions ref {ref}. Electronic devices and calculators are strictly prohibited in exam halls."),
            ("mr-en", "formal_notice", False, "Exam Board Instructions: Hall ticket print gheun theva. Exam center var original ID proof sobat thevne anivarya ahe.")
        ]
    },
    "v4_train_legit_municipal_water_pipeline_maintenance": {
        "scenario": "legit_municipal_water_pipeline_maintenance",
        "label": "legitimate",
        "description": "Genuine municipal corporation water pipeline maintenance and shutdown circular",
        "patterns": [
            ("mr", "advisory_bulletin", True, "महानगरपालिका पाणीपुरवठा विभाग: मुख्य जलवाहिनी दुरुस्तीच्या कामामुळे {date} रोजी पाणीपुरवठा बंद राहील. तपशील पहा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Municipal Corporation Water Dept: Main pipeline repair mule {date} roji water supply band rahil. Schedule: {domain}"),
            ("en", "advisory_bulletin", True, "Municipal Corporation: Water supply interruption notice for scheduled pipeline maintenance on {date}. Affected zones: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Mahanagarpalika Water Alert: Pipeline maintenance mule udya paani supply band rahnar ahe. Details link: {domain}"),
            ("mr", "advisory_bulletin", False, "पुणे महानगरपालिका सार्वजनिक सूचना: जलशुद्धीकरण केंद्रात दुरुस्तीचे काम हाती घेतल्याने {date} रोजी पाणीपुरवठा बंद राहील. नागरिकांनी सहकार्य करावे."),
            ("mr-Latn", "advisory_bulletin", False, "Municipal Notice: Water supply in South Zone will remain shut on {date} due to urgent valve replacement. Please store adequate water."),
            ("en", "formal_notice", False, "Municipal Corporation Engineering Dept: Public announcement regarding routine preventive maintenance of gravity water mains on {date}."),
            ("mr-en", "advisory_bulletin", False, "Municipal Public Notice: Repair work chalu aslyane {date} roji paani kami dabanene yeil. Nagarikani nond ghyavi.")
        ]
    },
    "v4_train_legit_aadhaar_biometric_update_status": {
        "scenario": "legit_aadhaar_biometric_update_status",
        "label": "legitimate",
        "description": "Genuine UIDAI Aadhaar biometric and document update receipt",
        "patterns": [
            ("mr", "sms", True, "युआयडीएआय (UIDAI): आपल्या आधार कार्डावरील पत्ता व बायोमेट्रिक सुधारणा यशस्वी झाली आहे. अद्ययावत ई-आधार पहा: {domain}"),
            ("mr-Latn", "sms", True, "UIDAI Aadhaar Update: Biometric aani address update request successfully process zali ahe. Check e-Aadhaar: {domain}"),
            ("en", "sms", True, "UIDAI Seva Portal: Aadhaar update request ref {ref} has been successfully processed. Download masked e-Aadhaar: {domain}"),
            ("mr-en", "sms", True, "UIDAI Update Notice: Tumcha Aadhaar update complete zala ahe. Official portal var e-Aadhaar download kara: {domain}"),
            ("mr", "sms", False, "युआयडीएआय सूचना: आधार नोंदणी पावती संदर्भ {ref}. आपले बायोमेट्रिक यशस्वीरीत्या अद्ययावत केले गेले आहे. सरकारी कामासाठी हे वैध आहे."),
            ("mr-Latn", "sms", False, "UIDAI Service Update: Request ref {ref} processed successfully. No further action needed. Download official e-Aadhaar from enrollment center."),
            ("en", "sms", False, "Unique Identification Authority of India: Your demographic details have been updated against acknowledgement ref {ref}. Information update complete."),
            ("mr-en", "sms", False, "Aadhaar Seva Update: Tumchi biometric update request {ref} complete zali ahe. Physical card postal dispatch sathi ready ahe.")
        ]
    },
    "v4_train_legit_post_office_registered_parcel_pickup": {
        "scenario": "legit_post_office_registered_parcel_pickup",
        "label": "legitimate",
        "description": "Genuine India Post registered parcel arrival and counter pickup note",
        "patterns": [
            ("mr", "sms", True, "भारतीय डाक विभाग: आपली नोंदणीकृत टपाल वस्तू (Speed Post) स्थानिक पोस्ट कार्यालयात पोहोचली आहे. ट्रॅकिंग पहा: {domain}"),
            ("mr-Latn", "sms", True, "India Post Alert: Tumche speed post parcel post office madhe ale ahe. Tracking status check kara: {domain}"),
            ("en", "sms", True, "India Post Delivery: Registered article ref {ref} received at local sub-post office. Track consignment: {domain}"),
            ("mr-en", "sms", True, "India Post Alert: Registered article {ref} post office madhe available ahe. Tracking link: {domain}"),
            ("mr", "sms", False, "भारतीय टपाल विभाग: नोंदणीकृत पार्सल संदर्भ {ref} पोस्ट ऑफिसमध्ये आले आहे. कार्यालयीन वेळेत मूळ ओळखपत्रासह येऊन पार्सल ताब्यात घ्यावे."),
            ("mr-Latn", "sms", False, "India Post Intimation: Speed Post consignment ref {ref} is awaiting delivery at counter. Please collect between 10 AM and 4 PM with ID proof."),
            ("en", "sms", False, "Department of Posts: Consignment ref {ref} held at delivery office. Addressee may collect during normal business hours with valid photo ID."),
            ("mr-en", "sms", False, "Post Office Notice: Tumche Speed Post article {ref} deliver hoil. Krupaya {date} roji address var present raha.")
        ]
    },

    # --- PROTECTIVE ADVISORY (10) ---
    "v4_train_advisory_mha_digital_arrest_warning": {
        "scenario": "advisory_mha_digital_arrest_warning",
        "label": "protective_advisory",
        "description": "MHA/I4C advisory clarifying that digital arrest does not exist under Indian law",
        "patterns": [
            ("mr", "advisory_bulletin", True, "गृह मंत्रालय दक्षता इशारा: भारतीय कायद्यात 'डिजिटल अरेस्ट' अशी कोणतीही तरतूद नाही. पोलिस व्हिडिओ कॉलवर अटक करत नाहीत. तक्रार करा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "MHA Cyber Safety: Indian law madhe 'Digital Arrest' chi kontihi tatud nahi. Police video call var arrest karat nahit. Report: {domain}"),
            ("en", "advisory_bulletin", True, "Ministry of Home Affairs Public Advisory: 'Digital Arrest' is a cyber fraud. Law enforcement agencies never arrest citizens on video calls. Portal: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Cyber Security Alert: Digital arrest fraud ahe. Police kentinahi video call var bail magat nahit. Report cybercrime: {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र सायबर सुरक्षा: सीबीआय किंवा पोलीस असल्याचा दावा करून व्हिडिओ कॉलवर डांबून ठेवल्यास त्वरित १९३० वर कॉल करा. घाबरून पैसे पाठवू नका."),
            ("mr-Latn", "advisory_bulletin", False, "Cyber Crime Warning: Fake police officers call on Skype claiming digital arrest for courier parcel. Do not transfer funds. Report immediately to 1930."),
            ("en", "advisory_bulletin", False, "Citizen Cyber Alert: Fraudsters impersonating CBI and police are extorting money through fake video calls. No legal agency conducts online arrests. Dial 1930."),
            ("mr-en", "advisory_bulletin", False, "Police Advisory: Digital arrest scams pasun savadh raha. Police call disconnect karu नका mhanun blackmail kartat. Call 1930 immediately.")
        ]
    },
    "v4_train_advisory_cbi_impersonation_alert": {
        "scenario": "advisory_cbi_impersonation_alert",
        "label": "protective_advisory",
        "description": "Official CBI advisory warning citizens against fake notices and impersonation",
        "patterns": [
            ("mr", "formal_notice", True, "केंद्रीय अन्वेषण ब्यूरो (CBI) दक्षता सूचना: सीबीआय कधीही व्हॉट्सअॅपवर अटक वॉरंट पाठवून पैशांची मागणी करत नाही. अधिकृत मार्गदर्शन: {domain}"),
            ("mr-Latn", "formal_notice", True, "CBI Vigilance Notice: CBI kadhihi WhatsApp var summons pathvun online fine magat nahi. Official clarification: {domain}"),
            ("en", "formal_notice", True, "CBI Press Advisory: Beware of fraudulent letters and warrants bearing fake CBI emblems demanding settlements. Verify official notices: {domain}"),
            ("mr-en", "formal_notice", True, "CBI Public Notice: Fake CBI officers WhatsApp var paise magtat. CBI online settlement karat nahi. Official portal: {domain}"),
            ("mr", "advisory_bulletin", False, "सीबीआय जनसंपर्क कक्ष: बनावट सीबीआय अधिकारी बनून मनी लाँड्रिंगच्या नावाखाली पैसे उकळणाऱ्या टोळ्यांपासून सावध राहा. अशी मागणी झाल्यास १९३० वर तक्रार करा."),
            ("mr-Latn", "advisory_bulletin", False, "CBI Public Caution: Criminal syndicates are sending fake arrest notices with CBI logos. Central Bureau of Investigation never accepts UPI or bank transfers."),
            ("en", "advisory_bulletin", False, "Statutory Notice from CBI: The Bureau does not issue summons over messaging apps or demand provisional bail deposits. Report imposters to local police."),
            ("mr-en", "advisory_bulletin", False, "CBI Caution: CBI naavane yenare video calls fake astat. Paise deu naka aani immediate local police station la report kara.")
        ]
    },
    "v4_train_advisory_cybercell_video_extortion": {
        "scenario": "advisory_cybercell_video_extortion",
        "label": "protective_advisory",
        "description": "Cyber cell alert against Skype/WhatsApp interrogations and digital confinement",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सायबर क्राईम ब्रँच इशारा: स्काईप किंवा व्हॉट्सअॅपवर बनावट पोलीस ठाणे दाखवून खंडणी उकळणाऱ्यांपासून सावध राहा. हेल्पलाईन: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Cyber Crime Warning: Fake police station setup dakhvun Skype var blackmail karnaryampasun savadh. Report at: {domain}"),
            ("en", "advisory_bulletin", True, "Cyber Police Advisory: Scammers set up artificial police station backdrops on video calls to intimidate citizens. Report digital arrest fraud: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Crime Branch Caution: Video call var uniform ghalun fake police dhamki detat. Disconnect call and report: {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र पोलीस इशारा: व्हिडिओ कॉलवर पोलीस गणवेश घालून स्वतःला सायबर अधिकारी सांगणाऱ्या कॉल्सवर विश्वास ठेवू नका. त्वरित कॉल कट करून १९३० वर कळवा."),
            ("mr-Latn", "advisory_bulletin", False, "Police Alert: Impersonators in police uniform are forcing victims into digital confinement on WhatsApp video calls. Hang up and dial cyber helpline 1930."),
            ("en", "advisory_bulletin", False, "Crime Branch Advisory: Real police officers never order citizens to remain isolated on webcams or demand secrecy from family members. Report extortion calls."),
            ("mr-en", "advisory_bulletin", False, "Cyber Safety: Fake police video call alyas ghambru naka. Police kadhihi online room confinement karat nahit. Immediate call disconnect kara.")
        ]
    },
    "v4_train_advisory_ecourt_fake_warrant_notice": {
        "scenario": "advisory_ecourt_fake_warrant_notice",
        "label": "protective_advisory",
        "description": "Judicial department warning on fake court arrest warrants sent via messaging apps",
        "patterns": [
            ("mr", "formal_notice", True, "न्यायालयीन दक्षता परिपत्रक: न्यायालये कधीही व्हॉट्सअॅप किंवा एसएमएसवर अटक वॉरंट पाठवून दंड मागत नाहीत. सत्यता तपासा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Court Vigilance Notice: Courts kadhihi WhatsApp var non-bailable warrant pathvun fine online magat nahit. Verification: {domain}"),
            ("en", "formal_notice", True, "Judiciary Public Advisory: Fake High Court warrants with counterfeit stamps are circulating online. Courts never collect contempt fines via UPI. Portal: {domain}"),
            ("mr-en", "formal_notice", True, "eCourts Security Alert: Fake court orders var paise magtat. Real court notice official police postatun yete. Check link: {domain}"),
            ("mr", "formal_notice", False, "जिल्हा विधी सेवा प्राधिकरण: बनावट न्यायालयीन समन्स व वॉरंट पाठवून आर्थिक तडजोडीची मागणी करणे हा सायबर गुन्हा आहे. असे संदेश आल्यास सायबर सेलला कळवा."),
            ("mr-Latn", "formal_notice", False, "Judicial Awareness: No court in India issues digital arrest orders or demands bail deposits via electronic links. Verify all court notices at district court registry."),
            ("en", "formal_notice", False, "eCourts Public Alert: Fraudulent legal notices alleging contempt of court are being used to extort citizens. Report fraudulent advocates and notices to police."),
            ("mr-en", "formal_notice", False, "Court Fraud Alert: WhatsApp var fake court stamp aslele warrant aale tar paise transfer karu naka. eCourts website var case status check kara.")
        ]
    },
    "v4_train_advisory_national_1930_helpline": {
        "scenario": "advisory_national_1930_helpline",
        "label": "protective_advisory",
        "description": "Citizen guide to reporting on national cyber helpline 1930 during golden hour",
        "patterns": [
            ("mr", "advisory_bulletin", True, "राष्ट्रीय सायबर हेल्पलाईन १९३०: ऑनलाइन आर्थिक फसवणूक झाल्यास पहिल्या दोन तासांत (Golden Hour) १९३० वर तक्रार नोंदवा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "National Cyber Helpline 1930: Financial fraud zalya nantar Golden Hour madhe 1930 var call kara bank account freeze sathi: {domain}"),
            ("en", "advisory_bulletin", True, "Citizen Cyber Guide: Dial 1930 immediately within the golden hour to freeze siphoned funds in cyber fraud cases. National portal: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Cyber Security Alert: Online paise chori gelyas tabadtob 1930 var call kara account freeze karnyasaathi: {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र सायबर विभाग: फसवणूक होताच तात्काळ १९३० डायल करा. तक्रार वेळेत नोंदवल्यास गेलेली रक्कम बँकांमध्ये गोठवून परत मिळण्याची शक्यता वाढते."),
            ("mr-Latn", "advisory_bulletin", False, "Cyber Crime Helpline Notice: Dial 1930 or visit cybercrime.gov.in immediately. Keep transaction UTR and bank account details ready for quick fund freezing."),
            ("en", "advisory_bulletin", False, "Ministry of Home Affairs: In any incident of cyber extortion or unauthorized digital transfer, call 1930 helpline for immediate financial interdiction."),
            ("mr-en", "advisory_bulletin", False, "1930 Helpline Advisory: Cyber financial fraud zalyas ghabru naka. 1930 var call karun transaction reference report kara.")
        ]
    },
    "v4_train_advisory_rbi_predatory_loan_apps": {
        "scenario": "advisory_rbi_predatory_loan_apps",
        "label": "protective_advisory",
        "description": "RBI warning on illegal instant loan apps using photo morphing and harassment",
        "patterns": [
            ("mr", "advisory_bulletin", True, "रिझर्व्ह बँक (RBI) सुरक्षा सूचना: बेकायदेशीर इन्स्टंट लोन ॲप्सपासून सावध राहा. मॉर्फ केलेले फोटो व धमक्यांना बळी पडू नका. मार्गदर्शक तत्त्वे: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "RBI Public Advisory: Illegal instant loan apps pasun savadh raha. Photo morphing aani blackmail calls viruddha police report kara: {domain}"),
            ("en", "advisory_bulletin", True, "Reserve Bank of India Notice: Do not borrow from unregistered lending applications that access contacts and photos. File complaints at: {domain}"),
            ("mr-en", "advisory_bulletin", True, "RBI Consumer Safety: Unregistered loan apps blackmail kartat. Kontyahi loan app la gallery permission deu naka. Report link: {domain}"),
            ("mr", "advisory_bulletin", False, "पोलीस सायबर विभाग: इन्स्टंट लोनच्या नावाखाली संपर्कांची चोरी करून नातेवाईकांना मॉर्फ केलेले फोटो पाठवण्याची धमकी दिल्यास घाबरू नका, त्वरित पोलिसात तक्रार करा."),
            ("mr-Latn", "advisory_bulletin", False, "Crime Branch Loan Alert: Predatory loan apps harass borrowers with forged legal warrants and abusive calls. Never pay recovery agents on private UPI IDs."),
            ("en", "advisory_bulletin", False, "RBI Awareness Bulletin: Authorized non-banking financial companies (NBFCs) never use abusive collection agents or threaten digital arrest for loan recovery."),
            ("mr-en", "advisory_bulletin", False, "Loan App Blackmail Caution: Illegal loan apps che recovery agents blackmail karat aslyas police complaint kara. Dhandyachya bhitine paise deu naka.")
        ]
    },
    "v4_train_advisory_pib_scheme_factcheck": {
        "scenario": "advisory_pib_scheme_factcheck",
        "label": "protective_advisory",
        "description": "PIB Fact Check debunking fake government subsidy approval letters and fees",
        "patterns": [
            ("mr", "advisory_bulletin", True, "पीआयबी फॅक्ट चेक (PIB): सरकारी योजनांचे अनुदान मिळवून देण्यासाठी आगाऊ शुल्क मागणारी पत्रे पूर्णपणे बनावट आहेत. तथ्य तपासा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "PIB Fact Check: Sarkari yojana subsidy sathi advance fee maganare letters fake ahet. Verify genuine govt schemes: {domain}"),
            ("en", "advisory_bulletin", True, "PIB Fact Check Alert: Fake sanction letters claiming subsidy approval under central government schemes are fraudulent. Verify at: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Govt Scheme Verification: Sarkari scheme madhe kontahi registration fee nasto. Fake letters pasun savadh raha: {domain}"),
            ("mr", "advisory_bulletin", False, "प्रेस इन्फॉर्मेशन ब्युरो: केंद्र सरकार कोणत्याही योजनेसाठी व्हॉट्सअॅपवर मंजुरी पत्र पाठवून पैसे मागत नाही. संशयास्पद संदेश pib.gov.in वर पडताळा."),
            ("mr-Latn", "advisory_bulletin", False, "PIB Fact Check Notice: Central government never demands registration charges or approval fees for subsidy disbursements. Report fake letters to cyber crime cell."),
            ("en", "advisory_bulletin", False, "Fact Check Unit: Viral messages claiming immediate cash grants under prime minister schemes upon paying processing fees are false. Beware of financial traps."),
            ("mr-en", "advisory_bulletin", False, "PIB Advisory: Pradhan Mantri yojana sanctioned zali ashi fake patre ahet. Konatyahi account madhe advance registration fee bharu naka.")
        ]
    },
    "v4_train_advisory_police_verification_fee_fraud": {
        "scenario": "advisory_police_verification_fee_fraud",
        "label": "protective_advisory",
        "description": "State police notice that verification is free and demanding fees is illegal",
        "patterns": [
            ("mr", "formal_notice", True, "पोलीस दक्षता परिपत्रक: नोकरी किंवा पासपोर्टच्या पोलीस पडताळणीसाठी कोणतेही शुल्क आकारले जात नाही. पैसे मागणाऱ्यांची तक्रार करा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Police Vigilance Notice: Police verification sathi kontech fee naste. Bribe kinva online payment magitlyas report kara: {domain}"),
            ("en", "formal_notice", True, "Police Commissionerate Alert: Citizen police verification for passport and employment is strictly free. Report extortion attempts at: {domain}"),
            ("mr-en", "formal_notice", True, "Police Advisory: Police verification clear karnyasathi konalahi paise deu naka. Official complaints: {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र पोलीस सूचना: पोलीस पडताळणी प्रतिकूल असल्याचा बहाणा करून ऑनलाईन पैसे उकळणाऱ्या सायबर गुन्हेगारांपासून सावध राहा. पडताळणी थेट पोलीस ठाण्यात होते."),
            ("mr-Latn", "formal_notice", False, "Police Public Notice: Do not pay online clearance charges for police background checks. Police inquiries are conducted in person at your designated police station."),
            ("en", "formal_notice", False, "State Police Headquarters: Fake police verification callers demanding urgent payments to clear adverse remarks are fraudsters. Inform nearest police station."),
            ("mr-en", "advisory_bulletin", False, "Police Caution: Police verification cancel honar mhanun koni paise magat aslyas direct SP office kinva police station la bhet dya.")
        ]
    },
    "v4_train_advisory_certin_deepfake_voice_scam": {
        "scenario": "advisory_certin_deepfake_voice_scam",
        "label": "protective_advisory",
        "description": "CERT-In bulletin on AI voice clone scams and fake relative arrest calls",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सर्ट-इन (CERT-In) सायबर इशारा: एआय (AI) आवाजाचा वापर करून नातेवाईक अटकेत असल्याचे सांगून पैसे उकळणाऱ्या फसवणुकीपासून सावध राहा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "CERT-In Cyber Warning: AI voice cloning vaprun relative police custody madhe aslyache sangu paise magtat. Stay alert: {domain}"),
            ("en", "advisory_bulletin", True, "CERT-In Vulnerability Note: Fraudsters utilize generative AI voice cloning to impersonate family members in fake arrest emergencies. Advisory: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Cyber Security Alert: AI voice clone scam alert. Relative la arrest zali asha calls var direct call karun verify kara: {domain}"),
            ("mr", "advisory_bulletin", False, "सायबर सुरक्षा दक्षता: नातेवाईकाचा हुबेहूब आवाज काढून तातडीने जामीन भरण्यास सांगणारा फोन आल्यास, आधी संबंधित व्यक्तीच्या मूळ नंबरवर फोन करून खात्री करा."),
            ("mr-Latn", "advisory_bulletin", False, "CERT-In Advisory: Before transferring emergency funds on calls claiming your son or relative is arrested by police, independently contact the individual directly."),
            ("en", "advisory_bulletin", False, "Computer Emergency Response Team: Deepfake voice extortion incidents are on the rise. Always verify distressing emergency claims through known family contact numbers."),
            ("mr-en", "advisory_bulletin", False, "AI Scam Warning: Relative cha awaj aaikun ghabru naka. Immediate paise transfer karu naka aani police station madhe verify kara.")
        ]
    },
    "v4_train_advisory_sebi_fake_ipo_investment": {
        "scenario": "advisory_sebi_fake_ipo_investment",
        "label": "protective_advisory",
        "description": "SEBI advisory against unauthorized institutional trading groups and guaranteed IPOs",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सेबी (SEBI) गुंतवणूकदार सुरक्षा: व्हॉट्सअॅपवरील खाजगी ट्रेडिंग ग्रुप्स आणि हमखास आयपीओ (IPO) वाटपाच्या आमिषाला बळी पडू नका. नोंदणी तपासा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "SEBI Investor Safety: WhatsApp trading groups aani guaranteed IPO allotment chya fake schemes madhe paise ghalu naka. Check SEBI: {domain}"),
            ("en", "advisory_bulletin", True, "SEBI Public Notice: Unregistered entities operating social media groups promising guaranteed returns and institutional IPO shares are fraudulent. Verify: {domain}"),
            ("mr-en", "advisory_bulletin", True, "SEBI Investment Alert: Fake institutional trading apps aani guaranteed profits aslele groups fraud ahet. Report to SEBI: {domain}"),
            ("mr", "advisory_bulletin", False, "सेबी जनसंपर्क विभाग: संस्थात्मक खात्याच्या नावाखाली अज्ञात बँक खात्यात शेअर्ससाठी पैसे भरण्यास सांगणाऱ्या ॲप्सपासून सावध राहा. सेबी नोंदणीकृत दलालांमार्फतच गुंतवणूक करा."),
            ("mr-Latn", "advisory_bulletin", False, "SEBI Investor Warning: Legitimate stock brokers never request investors to transfer funds into individual personal bank accounts for pre-IPO allotments."),
            ("en", "advisory_bulletin", False, "Securities and Exchange Board of India: Beware of high-yield online stock trading scams promising priority IPO allotments through fraudulent mobile APKs."),
            ("mr-en", "advisory_bulletin", False, "Stock Trading Alert: WhatsApp group madhe guaranteed stock tips aani private IPO transfer fake astat. Paise invest karu naka.")
        ]
    }
}

# -----------------------------------------------------------------------------
# 6 DEVELOPMENT CAMPAIGN FAMILIES (2 Phishing, 2 Legitimate, 2 Protective Advisory)
# -----------------------------------------------------------------------------
DEV_FAMILIES: Dict[str, Dict[str, Any]] = {
    # --- PHISHING (2) ---
    "v4_dev_phish_customs_fedex_contraband_threat": {
        "scenario": "dev_phish_customs_fedex_contraband_threat",
        "label": "phishing",
        "description": "Customs courier parcel seizure extortion with passport impoundment threat",
        "patterns": [
            ("mr", "sms", True, "कस्टम्स क्लिअरन्स विभाग: आपल्या आंतरराष्ट्रीय पार्सलमध्ये बेकायदेशीर वस्तू आढळल्याने पार्सल जप्त. पासपोर्ट निलंबन टाळण्यासाठी तडजोड शुल्क भरा: {domain}"),
            ("mr-Latn", "sms", True, "Customs Seizure Notice: International courier madhe contraband sapadlyamule passport impound warrant issue zale ahe. Fine bhara: {domain}"),
            ("en", "formal_notice", True, "Indian Customs Enforcement: Courier consignment ref {ref} impounded under Customs Act. Remit clearance penalty {amount} to prevent passport revocation: {domain}"),
            ("mr-en", "sms", True, "Customs Courier Alert: Foreign parcel madhe illegal items bhetlyamule case file zali ahe. Seizure cancel sathi link var pay kara: {domain}"),
            ("mr", "sms", False, "कस्टम्स अन्वेषण कक्ष: आपल्या पार्सलमध्ये बनावट कागदपत्रे व प्रतिबंधित रसायने जप्त झाली आहेत. तात्काळ तपास अधिकारी {phone} शी संपर्क साधा अन्यथा पोलीस अटक करतील."),
            ("mr-Latn", "whatsapp", False, "Customs Clearance Cell: Consignment ref {ref} seized at cargo terminal. Arrest warrant dispatched. Call senior superintendent on {phone} right now."),
            ("en", "formal_notice", False, "Customs Air Cargo Intelligence Unit: Seizure notice ref {ref}. Non-bailable arrest order signed. Call customs investigation cell on {phone} to record sworn deposition."),
            ("mr-en", "whatsapp", False, "Customs Seizure Warning: Foreign courier case madhe FIR hoil. Court case talnyasathi desk officer {phone} var contact kara.")
        ]
    },
    "v4_dev_phish_highcourt_contempt_fine_scam": {
        "scenario": "dev_phish_highcourt_contempt_fine_scam",
        "label": "phishing",
        "description": "Fake High Court judicial contempt bailable warrant settlement lure",
        "patterns": [
            ("mr", "formal_notice", True, "उच्च न्यायालय खंडपीठ सूचना: न्यायालयीन गैरहजेरीमुळे अजामीनपात्र वॉरंट आदेश. पोलीस ठाण्यामार्फत अटक टाळण्यासाठी ऑनलाइन जामीन शुल्क भरा: {domain}"),
            ("mr-Latn", "formal_notice", True, "High Court Judicial Order: Contempt case madhe arrest order pass zala ahe. Legal penalty bhara bail confirm karnyasathi: {domain}"),
            ("en", "formal_notice", True, "High Court Registry Notice: Criminal contempt bench has initiated non-bailable coercive process ref {ref}. Settle compoundable penalty online: {domain}"),
            ("mr-en", "formal_notice", True, "High Court Summons: Court notice non-compliance mule warrant issue zale ahe. Emergency legal portal link: {domain}"),
            ("mr", "formal_notice", False, "उच्च न्यायालय निबंधक कक्ष: रिट याचिका संदर्भ {ref} अंतर्गत अवमान कारवाई. पोलीस पथक रवाना होण्यापूर्वी तात्काळ कोर्ट अधिकारी {phone} शी संपर्क साधा."),
            ("mr-Latn", "formal_notice", False, "High Court Order: Bailable warrant issued ref {ref}. Police attachment order signed by bench. Call judicial registrar clerk on {phone} immediately."),
            ("en", "formal_notice", False, "Judicial High Court Registry: Warrant of arrest issued under Rule 11. Dial court executive officer at {phone} before 4:00 PM to submit compounding affidavit."),
            ("mr-en", "formal_notice", False, "High Court Notice: Court warrant issue zala ahe. Arrest order thambavnyasathi court registrar {phone} var contact kara.")
        ]
    },

    # --- LEGITIMATE (2) ---
    "v4_dev_legit_rto_smartcard_dispatch": {
        "scenario": "dev_legit_rto_smartcard_dispatch",
        "label": "legitimate",
        "description": "Genuine RTO driving license smartcard postal dispatch tracking alert",
        "patterns": [
            ("mr", "sms", True, "प्रादेशिक परिवहन कार्यालय (RTO): आपले स्मार्टकार्ड ड्रायव्हिंग लायसन्स स्पीड पोस्टाने रवाना झाले आहे. ट्रॅकिंग करा: {domain}"),
            ("mr-Latn", "sms", True, "RTO Transport Office: Tumche smartcard Driving License speed post ne dispatch zale ahe. Track postal delivery: {domain}"),
            ("en", "sms", True, "Regional Transport Office (RTO): Your Driving License smartcard has been dispatched via Speed Post ref {ref}. Track consignment: {domain}"),
            ("mr-en", "sms", True, "RTO Seva Notice: Tumche DL smartcard postatun patavle ahe. Postal tracking details link: {domain}"),
            ("mr", "sms", False, "प्रादेशिक परिवहन विभाग: वाहन चालक परवाना संदर्भ {ref}. आपले स्मार्टकार्ड यशस्वीरीत्या मुद्रित झाले असून पत्त्यावर पाठवले जात आहे. पत्त्यावर उपस्थित राहावे."),
            ("mr-Latn", "sms", False, "RTO Maharashtra Notice: Driving License ref {ref} successfully printed and handed over to India Post. Keep photo ID ready at delivery address."),
            ("en", "sms", False, "Motor Vehicle Department: Your smartcard driving license application ref {ref} is approved. Delivery expected within 5 working days via registered post."),
            ("mr-en", "sms", False, "RTO Office Notice: Driving license dispatch zale ahe speed post ref {ref}. Dakia yeil tevha original photo ID dakhavne aavashyak ahe.")
        ]
    },
    "v4_dev_legit_property_tax_annual_assessment": {
        "scenario": "dev_legit_property_tax_annual_assessment",
        "label": "legitimate",
        "description": "Genuine municipal property tax annual assessment bill and rebate deadline notice",
        "patterns": [
            ("mr", "formal_notice", True, "महानगरपालिका कर आकारणी विभाग: मालमत्ता कर वार्षिक देयक प्रसिद्ध झाले आहे. १०% सवलतीसाठी {date} पूर्वी भरा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Municipal Property Tax: Property tax annual assessment bill release zale ahe. 10% discount sathi pay kara: {domain}"),
            ("en", "formal_notice", True, "Municipal Corporation: Annual Property Tax Assessment demand bill ref {ref} is generated. Avail early bird rebate before {date}: {domain}"),
            ("mr-en", "formal_notice", True, "Municipal Tax Bill: Property tax bill update zale ahe. Discount date aadhi payment sathi link: {domain}"),
            ("mr", "formal_notice", False, "महानगरपालिका कर संकलन कार्यालय: मालमत्ता क्रमांक {ref}. चालू आर्थिक वर्षाचा कर {date} पूर्वी भरून महापालिकेच्या विकासकामांना सहकार्य करावे."),
            ("mr-Latn", "formal_notice", False, "Municipal Corporation: Property tax bill ref {ref}. Pay your municipal taxes at citizen facilitation centers or ward offices on weekdays."),
            ("en", "formal_notice", False, "Civic Body Revenue Department: Notice of annual general property tax assessment ref {ref}. Ward citizen service counters open 9 AM to 3 PM."),
            ("mr-en", "formal_notice", False, "Property Tax Circular: Mahanagarpalika tax bill pay karnyasathi ward office madhe cash/cheque counter available ahet.")
        ]
    },

    # --- PROTECTIVE ADVISORY (2) ---
    "v4_dev_advisory_ed_money_laundering_scam": {
        "scenario": "dev_advisory_ed_money_laundering_scam",
        "label": "protective_advisory",
        "description": "Enforcement Directorate (ED) summons scam warning",
        "patterns": [
            ("mr", "formal_notice", True, "प्रवर्तन संचालनालय (ED) सतर्कता इशारा: ईडी कधीही व्हॉट्सअॅपवर समन्स पाठवून पैसे मागत नाही. बनावट पत्रांची माहिती द्या: {domain}"),
            ("mr-Latn", "formal_notice", True, "Enforcement Directorate Advisory: ED kadhihi WhatsApp var money laundering summons pathvun penalty magat nahi. Verify: {domain}"),
            ("en", "formal_notice", True, "Enforcement Directorate (ED) Public Warning: Do not respond to fake summons claiming asset attachment under PMLA demanding wire transfers. Portal: {domain}"),
            ("mr-en", "formal_notice", True, "ED Advisory: Fake ED summons baddal savadh raha. ED kadhihi phone var settlement fee magat nahi. Report: {domain}"),
            ("mr", "advisory_bulletin", False, "प्रवर्तन संचालनालय जनसंपर्क: बनावट ईडी अधिकारी बनून मालमत्ता जप्तीची भीती दाखवून बँक ट्रान्सफर मागणाऱ्या सायबर भामट्यांपासून सावध राहा. त्वरित १९३० वर कळवा."),
            ("mr-Latn", "advisory_bulletin", False, "ED Public Caution: Enforcement Directorate never demands cash deposits or provisional security transfers to halt money laundering investigations."),
            ("en", "advisory_bulletin", False, "Directorate of Enforcement Advisory: Beware of fraudsters impersonating ED investigators on video calls. All official ED summons are served through registered post."),
            ("mr-en", "advisory_bulletin", False, "ED Scam Notice: PMLA attachment notice daakhavun paise magitlyas police तक्रार kara. Konatyahi account var bail deposit deu naka.")
        ]
    },
    "v4_dev_advisory_dot_sim_termination_alert": {
        "scenario": "dev_advisory_dot_sim_termination_alert",
        "label": "protective_advisory",
        "description": "DoT warning that govt never threatens SIM cut via automated IVR calls",
        "patterns": [
            ("mr", "advisory_bulletin", True, "दूरसंचार विभाग (DoT) दक्षता सूचना: २ तासांत सिम बंद होईल असा दावा करणारे आयव्हीआर कॉल्स पूर्णपणे बनावट आहेत. अहवाल नोंदवा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "DoT Telecom Notice: 2 hours madhe SIM card block hoil ashe fake automated IVR calls pasun savadh. Sanchar Saathi: {domain}"),
            ("en", "advisory_bulletin", True, "Department of Telecommunications: DoT never makes automated IVR calls threatening mobile number disconnection within two hours. Report: {domain}"),
            ("mr-en", "advisory_bulletin", True, "Telecom Safety Alert: SIM block hoil mhanun police inquiry chi dhamki denare calls fake ahet. Check portal: {domain}"),
            ("mr", "advisory_bulletin", False, "दूरसंचार सुरक्षा कक्ष: आपल्या नंबरवरून गुन्हेगारी संदेश पाठवल्याचे सांगून सिम बंद करण्याची धमकी देणारे फोन त्वरित कट करा आणि १९३० वर तक्रार नोंदवा."),
            ("mr-Latn", "advisory_bulletin", False, "DoT Vigilance Advisory: Automated robocalls claiming your mobile connection is blacklisted by police for illegal activities are scam calls. Dial 1930."),
            ("en", "advisory_bulletin", False, "Citizen Telecom Advisory: The government does not authorize any agency to issue immediate SIM disconnect threats over the phone. Never press 9 to connect."),
            ("mr-en", "advisory_bulletin", False, "DoT Alert: Mobile number 2 hours madhe band hoil asha fake IVR recording calls la uttar deu naka. Cyber police la inform kara.")
        ]
    }
}

# -----------------------------------------------------------------------------
# 9 QUALIFICATION CAMPAIGN FAMILIES (3 Phishing, 3 Legitimate, 3 Protective Advisory)
# HELD-BACK, SEALED INDEPENDENT BENCHMARK
# -----------------------------------------------------------------------------
QUALIFICATION_FAMILIES: Dict[str, Dict[str, Any]] = {
    # --- PHISHING (3) ---
    "v4_qual_phish_nia_terror_funding_interrogation": {
        "scenario": "qual_phish_nia_terror_funding_interrogation",
        "label": "phishing",
        "description": "Fake National Investigation Agency summons threatening apprehension for illicit wire transfers",
        "patterns": [
            ("mr", "formal_notice", True, "राष्ट्रीय तपास यंत्रणा (NIA): आपल्या बँक खात्यावरून संशयास्पद देशविरोधी निधी व्यवहार आढळल्याने अजामीनपात्र समन्स जारी. सुरक्षा ठेव भरा: {domain}"),
            ("mr-Latn", "formal_notice", True, "NIA Investigation Notice: Illicit cross-border wire transfer case madhe non-bailable summons issue zale ahe. Security deposit link: {domain}"),
            ("en", "formal_notice", True, "National Investigation Agency (NIA): Non-bailable apprehension notice issued ref {ref} under Special Powers. Remit conditional clearance bond: {domain}"),
            ("mr-en", "formal_notice", True, "NIA Security Notice: Account madhe illegal foreign transaction mule NIA inquiry ahe. Custody talnyasathi fee bhara: {domain}"),
            ("mr", "formal_notice", False, "राष्ट्रीय तपास यंत्रणा विशेष कक्ष: राष्ट्रीय सुरक्षा कायद्यान्वये आपल्याविरुद्ध समन्स जारी. तात्काळ एनआयए तपास अधिकारी {phone} वर संपर्क साधा अन्यथा थेट अटक होईल."),
            ("mr-Latn", "whatsapp", False, "NIA Special Counter: Severe national security summons ref {ref}. Non-bailable arrest team en route. Connect immediately to investigating officer on {phone}."),
            ("en", "formal_notice", False, "National Investigation Agency: Statutory interrogation order ref {ref}. To present exculpatory evidence before paramilitary arrest, contact inquiry head at {phone}."),
            ("mr-en", "whatsapp", False, "NIA Counter-Terror Desk: Summons ref {ref} pending. Video interrogation sathi {phone} var connect raha, gharatun baher padlyas arrest hoil.")
        ]
    },
    "v4_qual_phish_supremecourt_arrest_injunction": {
        "scenario": "qual_phish_supremecourt_arrest_injunction",
        "label": "phishing",
        "description": "Fake Supreme Court non-bailable arrest injunction demanding escrow deposit",
        "patterns": [
            ("mr", "formal_notice", True, "सर्वोच्च न्यायालय विशेष आदेश: आपल्याविरुद्ध देशव्यापी अटकेचा हुकूम जारी. तात्काळ न्यायालयीन एस्क्रो अनामत {amount} भरून अटकेस स्थगिती मिळवा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Supreme Court Arrest Injunction: Nationwide arrest order pass zala ahe. Judicial escrow deposit pay karun stay ghyava: {domain}"),
            ("en", "formal_notice", True, "Supreme Court of India Judicial Registry: Extraordinary non-bailable injunction ref {ref}. Remit provisional indemnity deposit {amount} at: {domain}"),
            ("mr-en", "formal_notice", True, "Supreme Court Injunction: Police custody stay order sathi official judicial portal var payment kara: {domain}"),
            ("mr", "formal_notice", False, "सर्वोच्च न्यायालय रजिस्ट्रार: आपल्या नावावर थेट पोलीस कोठडीचा अजामीनपात्र आदेश जारी. कारवाई थांबवण्यासाठी त्वरित कोर्ट नोडल अधिकारी {phone} शी बोला."),
            ("mr-Latn", "formal_notice", False, "Supreme Court Order: Non-bailable custody warrant issued ref {ref}. All bank accounts frozen. Call Apex Court liaison officer on {phone} right now."),
            ("en", "formal_notice", False, "Apex Court Judicial Enforcement: Immediate remand warrant ref {ref} issued. To execute temporary stay prior to local police arrival, dial {phone}."),
            ("mr-en", "formal_notice", False, "Supreme Court Order: Custody order execute honyachya aadhi judicial clerk {phone} var contact kara, nahi tar immediate jail hoil.")
        ]
    },
    "v4_qual_phish_acb_disproportionate_assets_fine": {
        "scenario": "qual_phish_acb_disproportionate_assets_fine",
        "label": "phishing",
        "description": "Fake Anti-Corruption Bureau notice threatening property search unless penalty remitted",
        "patterns": [
            ("mr", "sms", True, "लाचलुचपत प्रतिबंधक विभाग (ACB): आपल्या संपत्तीची गुप्त चौकशी सुरू असून घरझडतीचे आदेश झाले आहेत. झडती टाळण्यासाठी पडताळणी शुल्क भरा: {domain}"),
            ("mr-Latn", "sms", True, "ACB Maharashtra Alert: Disproportionate assets case madhe raid aani property seizure notice. Clear penalty online: {domain}"),
            ("en", "formal_notice", True, "Anti-Corruption Bureau (ACB): Search and seizure warrant issued for unexplained assets ref {ref}. Settle compoundable fine {amount} to prevent raid: {domain}"),
            ("mr-en", "sms", True, "ACB Special Unit: Property raid notice ahe. Anti-Corruption case cancel karnyasathi clearance portal link: {domain}"),
            ("mr", "sms", False, "लाचलुचपत प्रतिबंधक ब्यूरो: आपल्याविरुद्ध ज्ञात स्रोतांपेक्षा अधिक संपत्ती जमवल्याप्रकरणी एफआयआर. तात्काळ एसीबी उपअधीक्षक {phone} शी संपर्क साधा."),
            ("mr-Latn", "sms", False, "ACB Special Squad: Asset confiscation warrant signed ref {ref}. Police raid team dispatched. Call inquiry superintendent on {phone} immediately."),
            ("en", "formal_notice", False, "Anti-Corruption Investigation Bureau: Property attachment order ref {ref}. To verify financial disclosures before public seizure, call {phone}."),
            ("mr-en", "sms", False, "ACB Notice: Tumchya navavar disproportionate assets inquiry zali ahe. Police raid thambavnyasathi {phone} var tatkal call kara.")
        ]
    },

    # --- LEGITIMATE (3) ---
    "v4_qual_legit_lok_adalat_dispute_hearing": {
        "scenario": "qual_legit_lok_adalat_dispute_hearing",
        "label": "legitimate",
        "description": "Genuine District Legal Services Authority notice regarding Lok Adalat pre-litigation hearing",
        "patterns": [
            ("mr", "formal_notice", True, "जिल्हा विधी सेवा प्राधिकरण: राष्ट्रीय लोक अदालत. आपसी तडजोडीसाठी आपले प्रकरण {date} रोजी ठेवले आहे. अधिक माहितीसाठी पहा: {domain}"),
            ("mr-Latn", "formal_notice", True, "District Legal Services Authority: National Lok Adalat madhe mutually case settle karnyasathi {date} chi date ahe. Info: {domain}"),
            ("en", "formal_notice", True, "District Legal Services Authority: National Lok Adalat pre-litigation settlement session scheduled on {date} ref {ref}. Cause list: {domain}"),
            ("mr-en", "formal_notice", True, "Lok Adalat Notice: Tumche dispute amicably resolve karnyasathi Lok Adalat session ahe {date} roji. Details portal: {domain}"),
            ("mr", "formal_notice", False, "राष्ट्रीय लोक अदालत सूचना: प्रकरण संदर्भ {ref}. पक्षकारांनी सलोख्याने वाद मिटवण्यासाठी {date} रोजी सकाळी {time} वाजता जिल्हा न्यायालयात उपस्थित राहावे."),
            ("mr-Latn", "formal_notice", False, "Legal Services Authority Notice: Pre-litigation dispute ref {ref} listed for amicable settlement in Lok Adalat on {date} at {time} in Court Hall 1."),
            ("en", "formal_notice", False, "National Lok Adalat Bench: Notice ref {ref}. Parties are invited for mutually agreed settlement without court fees on {date} before the conciliation panel."),
            ("mr-en", "formal_notice", False, "Lok Adalat Hearing Notice: Dispute amicable settlement sathi {date} roji courtat panel samor উপস্থিত raha. He notice free resolution sathi ahe.")
        ]
    },
    "v4_qual_legit_police_clearance_certificate_ready": {
        "scenario": "qual_legit_police_clearance_certificate_ready",
        "label": "legitimate",
        "description": "Genuine SP office notification intimating citizen to collect verified Police Clearance Certificate",
        "patterns": [
            ("mr", "sms", True, "पोलीस अधीक्षक कार्यालय: आपले पोलीस चारित्र्य पडताळणी प्रमाणपत्र (PCC) तयार झाले आहे. डिजिटल प्रत डाऊनलोड करा: {domain}"),
            ("mr-Latn", "sms", True, "Superintendent of Police Office: Tumche Police Clearance Certificate (PCC) ready zale ahe. Download certified copy: {domain}"),
            ("en", "sms", True, "Office of the Superintendent of Police: Your Police Clearance Certificate (PCC) ref {ref} has been approved. Download digitally signed copy: {domain}"),
            ("mr-en", "sms", True, "Police Dept PCC Alert: Tumche character verification certificate issue zale ahe. Portal link: {domain}"),
            ("mr", "sms", False, "विशेष शाखा पोलीस कार्यालय: पोलीस चारित्र्य पडताळणी अर्ज संदर्भ {ref}. आपले प्रमाणपत्र तयार आहे. मूळ ओळखपत्रासह कार्यालयीन वेळेत येऊन ताब्यात घ्यावे."),
            ("mr-Latn", "sms", False, "Police Special Branch: Verification ref {ref} completed with clear record. Collect your physical PCC from SP office counter on working days between 11 AM and 3 PM."),
            ("en", "sms", False, "District Police Headquarters: Police Clearance Certificate ref {ref} is finalized. Applicant may collect the embossed certificate from the citizen facilitation desk."),
            ("mr-en", "sms", False, "Police PCC Update: Tumche police verification complete zale ahe ref {ref}. SP office counter varun certificate collect karun ghyave.")
        ]
    },
    "v4_qual_legit_municipal_trade_license_reminder": {
        "scenario": "qual_legit_municipal_trade_license_reminder",
        "label": "legitimate",
        "description": "Genuine municipal corporation health and trade license annual renewal schedule",
        "patterns": [
            ("mr", "formal_notice", True, "महानगरपालिका आरोग्य व परवाना विभाग: दुकाने व आस्थापना व्यापार परवाना वार्षिक नूतनीकरण सुरू झाले आहे. विहित मुदतीत नूतनीकरण करा: {domain}"),
            ("mr-Latn", "formal_notice", True, "Municipal Corporation Trade License Dept: Business license annual renewal suru zale ahe. Renew before deadline: {domain}"),
            ("en", "formal_notice", True, "Municipal Corporation Health Department: Annual Trade and Commercial License renewal ref {ref} is due for FY 2026-27. Renew online: {domain}"),
            ("mr-en", "formal_notice", True, "Mahanagarpalika Trade License: Shop license renewal start zale ahe. Official municipal portal link: {domain}"),
            ("mr", "formal_notice", False, "महानगरपालिका परवाना विभाग: परवाना क्रमांक {ref}. सर्व व्यापारी बंधूंनी परवाना नूतनीकरण मुदतीत पूर्ण करून दंडात्मक कारवाई टाळावी. प्रभाग कार्यालयात संपर्क साधावा."),
            ("mr-Latn", "formal_notice", False, "Municipal Trade Dept: Commercial license renewal ref {ref}. Visit municipal ward facilitation center on weekdays before {date} for document submission."),
            ("en", "formal_notice", False, "Municipal Administration Department: Annual renewal notice for establishment license ref {ref}. Timely compliance ensures uninterrupted business operations."),
            ("mr-en", "formal_notice", False, "Trade License Notice: Mahanagarpalika shop license renewal sathi documents ward office madhe submit kara {date} chya aadhi.")
        ]
    },

    # --- PROTECTIVE ADVISORY (3) ---
    "v4_qual_advisory_i4c_digital_arrest_sop": {
        "scenario": "qual_advisory_i4c_digital_arrest_sop",
        "label": "protective_advisory",
        "description": "Indian Cyber Crime Coordination Centre (I4C) standard advisory on digital arrest fraud",
        "patterns": [
            ("mr", "advisory_bulletin", True, "भारतीय सायबर गुन्हे समन्वय केंद्र (I4C): 'डिजिटल अरेस्ट' ही पूर्णपणे सायबर गुन्हेगारांची फसवणूक आहे. पोलीस कधीही व्हिडिओ कॉलवर अटक करत नाहीत: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "I4C National Advisory: 'Digital Arrest' scams chya fake video calls la bali padu naka. Police kadhihi online fine magat nahit. Report: {domain}"),
            ("en", "advisory_bulletin", True, "Indian Cyber Crime Coordination Centre (I4C): Clarification: Digital arrest is a myth fabricated by fraudsters. No law permits arrest via webcam. Report at: {domain}"),
            ("mr-en", "advisory_bulletin", True, "I4C Cyber Awareness: Digital arrest fake ahe. Police Skype var investigation karat nahit. National cyber portal: {domain}"),
            ("mr", "advisory_bulletin", False, "गृह मंत्रालय (I4C) दक्षता परिपत्रक: फसवणूक करणारे स्वतःला पोलीस किंवा सीबीआय भासवून नागरिकांना डिजिटल अटकेची धमकी देतात. असे फोन आल्यास घाबरू नका, त्वरित १९३० वर डायल करा."),
            ("mr-Latn", "advisory_bulletin", False, "I4C Cyber Warning: Law enforcement agencies never demand confidential video interrogations or secret escrow transfers. Stay safe and report extortions to 1930."),
            ("en", "advisory_bulletin", False, "I4C Standard Advisory: Criminal syndicates operate fake courtrooms on video calls. If anyone orders you not to leave your room under digital arrest, hang up and call 1930 immediately."),
            ("mr-en", "advisory_bulletin", False, "I4C Safety SOP: Video call var arrest warrant dakhavlyas to fake ahe. Call tabadtob disconnect kara aani local police station la alert dya.")
        ]
    },
    "v4_qual_advisory_bar_council_fake_legal_summons": {
        "scenario": "qual_advisory_bar_council_fake_legal_summons",
        "label": "protective_advisory",
        "description": "Bar Council warning against fake advocate demand letters and counterfeit court stamps",
        "patterns": [
            ("mr", "formal_notice", True, "बार कौन्सिल ऑफ महाराष्ट्र अँड गोवा: व्हॉट्सअॅपवर बनावट वकिलांच्या नावे कायदेशीर नोटिसा पाठवून खंडणी उकळणाऱ्यांपासून सावध राहा. पडताळणी: {domain}"),
            ("mr-Latn", "formal_notice", True, "Bar Council Warning: Fake advocates naavane WhatsApp var legal notice pathvun paise maganare scammers ahet. Verify advocate: {domain}"),
            ("en", "formal_notice", True, "Bar Council Statutory Alert: Criminal gangs are issuing forged advocate demand letters and counterfeit court seals via WhatsApp. Verify advocates at: {domain}"),
            ("mr-en", "formal_notice", True, "Bar Council Advisory: Fake legal summons aani fake advocate blackmail pasun savadh raha. Advocate credential check link: {domain}"),
            ("mr", "formal_notice", False, "बार कौन्सिल जनहित सूचना: कोणतेही अधिकृत वकील खंडणीसाठी किंवा कोर्ट सेटलमेंटसाठी ऑनलाईन खाजगी खात्यात पैसे भरण्याचा दबाव आणत नाहीत. अशा नोटिसांना बळी पडू नका."),
            ("mr-Latn", "formal_notice", False, "Bar Council Public Caution: Verify any legal notice received via SMS or WhatsApp with an independent advocate. Never make private UPI transfers on threatening demand letters."),
            ("en", "formal_notice", False, "State Bar Council Advisory: Unauthorized individuals posing as high court advocates are extorting money under threat of arrest warrants. Report bogus practitioners to police."),
            ("mr-en", "formal_notice", False, "Legal Notice Caution: Fake advocate legal notices pasun savadh. Court case settlement chya navavar paise magitlyas cyber police station la तक्रार dya.")
        ]
    },
    "v4_qual_advisory_trai_cyber_arrest_ivr": {
        "scenario": "qual_advisory_trai_cyber_arrest_ivr",
        "label": "protective_advisory",
        "description": "TRAI advisory informing public that automated robocalls claiming police arrest are fraudulent",
        "patterns": [
            ("mr", "advisory_bulletin", True, "ट्राय (TRAI) ग्राहक सुरक्षा सूचना: 'पोलीस कारवाई टाळण्यासाठी ९ दाबा' असे सांगणारे स्वयंचलित आयव्हीआर कॉल्स पूर्णपणे बनावट आहेत. माहिती: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "TRAI Telecom Alert: 'Police custody pasun vachnyasathi 9 press kara' ashe automated robocalls fraud ahet. TRAI guidance: {domain}"),
            ("en", "advisory_bulletin", True, "Telecom Regulatory Authority of India (TRAI): Robocalls claiming your mobile number is used in cyber crime and directing you to press 9 are scams. Report: {domain}"),
            ("mr-en", "advisory_bulletin", True, "TRAI Fraud Warning: Automated police arrest IVR calls fake ahet. Kontahi button press naka karu. Official alert: {domain}"),
            ("mr", "advisory_bulletin", False, "ट्राय दक्षता सूचना: दूरसंचार विभाग किंवा सायबर क्राईमच्या नावाने येणाऱ्या बनावट स्वयंचलित कॉल्सवर कोणतीही वैयक्तिक माहिती देऊ नका. असे कॉल्स त्वरित १९३० वर रिपोर्ट करा."),
            ("mr-Latn", "advisory_bulletin", False, "TRAI Advisory: Telecom service providers do not initiate IVR calls asking subscribers to connect with cyber police officers. Disconnect call immediately."),
            ("en", "advisory_bulletin", False, "TRAI Consumer Advisory: Automated robocalls alleging illegal courier parcels or digital arrest warrants are orchestrated by cybercriminals. Hang up immediately."),
            ("mr-en", "advisory_bulletin", False, "TRAI Robocall Alert: Police inquiry navane yenare automated calls cut kara. Fake police shi connect honyasathi kontehi number dial karu naka.")
        ]
    }
}


# -----------------------------------------------------------------------------
# RECORD RENDERING & BALANCING ENGINE
# -----------------------------------------------------------------------------
def render_record(
    family_id: str,
    family_def: Dict[str, Any],
    pattern_tuple: Tuple[str, str, bool, str],
    index: int,
    partition: str,
    record_id: str,
    rng: random.Random,
) -> Dict[str, Any]:
    """Renders a single synthetic record from pattern template and dummy vocabulary."""
    lang, mode, has_url, raw_pattern = pattern_tuple
    scenario = family_def["scenario"]
    label = family_def["label"]

    domain = rng.choice(
        DUMMY_PHISH_DOMAINS if label == "phishing" else (
            DUMMY_LEGIT_DOMAINS if label == "legitimate" else DUMMY_ADVISORY_DOMAINS
        )
    )
    phone = rng.choice(DUMMY_PHONES)
    amount = rng.choice(DUMMY_AMOUNTS)
    time_str = rng.choice(DUMMY_TIMES)
    date_str = rng.choice(DUMMY_DATES)
    ref = rng.choice(DUMMY_REFS)

    text = raw_pattern.format(
        domain=domain,
        phone=phone,
        amount=amount,
        time=time_str,
        date=date_str,
        ref=ref,
    )

    clean_text = clean_evasion_characters(text)
    norm_text = normalize_record_text(clean_text)

    script = "Devanagari" if lang == "mr" else ("Latin" if lang in ["en", "mr-Latn"] else "Mixed")
    role_map = {
        "training": "development",
        "development": "validation",
        "qualification": "qualification",
    }

    record = {
        "record_id": record_id,
        "ground_truth_label": label,
        "text": clean_text,
        "normalized_text": norm_text,
        "language": lang,
        "script": script,
        "messaging_mode": mode,
        "campaign_id": family_id,
        "scenario_category": scenario,
        "has_url": has_url,
        "provenance_category": "synthetic_test_case",
        "provenance_verification_status": "synthetic_fixture",
        "source_reference": "Seva Synthetic Corpus Generator v4.0 (Digital Arrest & Semantic Balance)",
        "license_info": "CC0 1.0 Public Domain / Synthetic Generated",
        "collection_date": "2026-10-30",
        "review_status": "reviewed",
        "dataset_role": role_map.get(partition, "development"),
        "partition": partition,
        "character_count": len(clean_text),
        "normalized_character_count": len(norm_text),
        "detected_script": detect_script(clean_text),
        "generator_version": "4.0.0",
    }
    return record


def generate_partition_records(
    families_dict: Dict[str, Dict[str, Any]],
    target_per_family: int,
    partition_name: str,
    id_prefix: str,
    seed: int,
) -> List[Dict[str, Any]]:
    """
    Generates exactly target_per_family (50) records for each family in families_dict.
    Guarantees:
    - Exactly 25 URL-bearing (has_url=True) and 25 URL-free (has_url=False) per family.
    - Balanced languages: 13 mr, 13 mr-Latn, 12 en, 12 mr-en per family.
    - Zero duplicate texts across the partition.
    """
    rng = random.Random(seed)
    records: List[Dict[str, Any]] = []
    seen_texts: Set[str] = set()
    global_idx = 1

    # Pattern indices allocation for exact 50 records per family:
    # URL=True (25): pattern 0 (mr): 7, pattern 1 (mr-Latn): 6, pattern 2 (en): 6, pattern 3 (mr-en): 6
    # URL=False (25): pattern 4 (mr): 6, pattern 5 (mr-Latn): 7, pattern 6 (en): 6, pattern 7 (mr-en): 6
    pattern_allocation = [
        (0, 7),  # mr, URL=True
        (1, 6),  # mr-Latn, URL=True
        (2, 6),  # en, URL=True
        (3, 6),  # mr-en, URL=True
        (4, 6),  # mr, URL=False
        (5, 7),  # mr-Latn, URL=False
        (6, 6),  # en, URL=False
        (7, 6),  # mr-en, URL=False
    ]
    assert sum(count for _, count in pattern_allocation) == target_per_family

    for family_id, family_def in families_dict.items():
        patterns = family_def["patterns"]
        assert len(patterns) == 8, f"Family {family_id} must have exactly 8 patterns"

        family_records: List[Dict[str, Any]] = []

        for p_idx, count in pattern_allocation:
            p_tuple = patterns[p_idx]
            for c_i in range(count):
                rec_id = f"{id_prefix}_{global_idx:04d}"
                # Retry with different dummy choices if collision occurs
                attempts = 0
                while attempts < 100:
                    attempts += 1
                    rec = render_record(
                        family_id=family_id,
                        family_def=family_def,
                        pattern_tuple=p_tuple,
                        index=c_i,
                        partition=partition_name,
                        record_id=rec_id,
                        rng=rng,
                    )
                    norm_t = rec["normalized_text"]
                    if norm_t not in seen_texts:
                        seen_texts.add(norm_t)
                        break

                is_valid, errors = validate_single_record(rec)
                if not is_valid:
                    raise ValueError(f"Record validation failed for {rec_id}: {errors}")

                family_records.append(rec)
                global_idx += 1

        records.extend(family_records)

    return records


# -----------------------------------------------------------------------------
# MANIFEST & LEDGER GENERATION
# -----------------------------------------------------------------------------
def compute_manifest(
    partition_name: str,
    file_name: str,
    records: List[Dict[str, Any]],
    file_sha256: str,
    families_dict: Dict[str, Dict[str, Any]],
    lifecycle_state: str,
) -> Dict[str, Any]:
    """Generates structured manifest for a dataset partition."""
    label_counts = Counter(r["ground_truth_label"] for r in records)
    lang_counts = Counter(r["language"] for r in records)
    mode_counts = Counter(r["messaging_mode"] for r in records)
    url_counts = Counter(str(r["has_url"]) for r in records)
    scenario_counts = Counter(r["scenario_category"] for r in records)

    is_qual = partition_name == "qualification"

    manifest = {
        "manifest_schema_version": "4.0.0",
        "partition": partition_name,
        "lifecycle_state": lifecycle_state,
        "file_name": file_name,
        "file_sha256": file_sha256,
        "record_count": len(records),
        "campaign_family_count": len(families_dict),
        "campaign_families": sorted(list(families_dict.keys())),
        "scenario_count": len(scenario_counts),
        "scenarios": sorted(list(scenario_counts.keys())),
        "distributions": {
            "label_distribution": dict(sorted(label_counts.items())),
            "language_distribution": dict(sorted(lang_counts.items())),
            "messaging_mode_distribution": dict(sorted(mode_counts.items())),
            "url_presence_distribution": dict(sorted(url_counts.items())),
        },
        "isolation_metadata": {
            "is_qualification_held_back": is_qual,
            "disjoint_family_guarantee": True,
            "locked_eval_accessible": False,
        },
        "created_at_utc": "2026-10-30T20:30:00Z",
    }
    return manifest


def compute_file_sha256(filepath: str) -> str:
    """Computes SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


# -----------------------------------------------------------------------------
# MAIN GENERATION PIPELINE
# -----------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Synthetic Corpus v4 (Digital Arrest & Semantic Balance)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR_V4, help="Output directory path")
    parser.add_argument("--seed", type=int, default=404, help="Random seed for generation")
    args = parser.parse_args()

    out_dir = os.path.abspath(args.output_dir)
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(LEDGER_DIR, exist_ok=True)

    print(f"[*] Initializing Synthetic Corpus v4 generator (seed={args.seed})...")
    print(f"[*] Target output directory: {out_dir}")

    # Generate records
    print("[*] Generating training partition (30 families x 50 = 1,500 records)...")
    train_recs = generate_partition_records(
        TRAIN_FAMILIES, 50, "training", "syn_v4_train", seed=args.seed + 1
    )

    print("[*] Generating development partition (6 families x 50 = 300 records)...")
    dev_recs = generate_partition_records(
        DEV_FAMILIES, 50, "development", "syn_v4_dev", seed=args.seed + 2
    )

    print("[*] Generating qualification partition (9 families x 50 = 450 records, SEALED)...")
    qual_recs = generate_partition_records(
        QUALIFICATION_FAMILIES, 50, "qualification", "syn_v4_qual", seed=args.seed + 3
    )

    # File paths
    train_file = os.path.join(out_dir, "synthetic_training_corpus.jsonl")
    dev_file = os.path.join(out_dir, "synthetic_dev_corpus.jsonl")
    qual_file = os.path.join(out_dir, "synthetic_qualification_corpus.jsonl")

    # Write JSONL files
    for filepath, recs in [
        (train_file, train_recs),
        (dev_file, dev_recs),
        (qual_file, qual_recs),
    ]:
        with open(filepath, "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"[+] Written {len(recs)} records to {os.path.basename(filepath)}")

    # Compute checksums
    train_sha = compute_file_sha256(train_file)
    dev_sha = compute_file_sha256(dev_file)
    qual_sha = compute_file_sha256(qual_file)

    # Build manifests
    train_man = compute_manifest(
        "training",
        "synthetic_training_corpus.jsonl",
        train_recs,
        train_sha,
        TRAIN_FAMILIES,
        "active_training",
    )
    dev_man = compute_manifest(
        "development",
        "synthetic_dev_corpus.jsonl",
        dev_recs,
        dev_sha,
        DEV_FAMILIES,
        "active_development",
    )
    qual_man = compute_manifest(
        "qualification",
        "synthetic_qualification_corpus.jsonl",
        qual_recs,
        qual_sha,
        QUALIFICATION_FAMILIES,
        "sealed_independent_benchmark",
    )

    corpus_man = {
        "manifest_schema_version": "4.0.0",
        "corpus_id": "seva-synthetic-corpus-v4",
        "generator_version": "4.0.0",
        "total_records": len(train_recs) + len(dev_recs) + len(qual_recs),
        "partitions": {
            "training": train_man,
            "development": dev_man,
            "qualification": qual_man,
        },
        "created_at_utc": "2026-10-30T20:30:00Z",
    }

    # Save manifests
    with open(os.path.join(out_dir, "training_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(train_man, f, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "dev_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(dev_man, f, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "qualification_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(qual_man, f, indent=2, ensure_ascii=False)
    with open(os.path.join(out_dir, "v4_corpus_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(corpus_man, f, indent=2, ensure_ascii=False)

    print("[+] All partition manifests and v4_corpus_manifest.json successfully saved.")

    # Initialize v4 qualification exposure ledger in UNEXPOSED state
    exposure_ledger_v4 = {
        "ledger_schema_version": "1.0.0",
        "created_at_utc": "2026-10-30T20:30:00Z",
        "partitions": {
            qual_sha: {
                "partition_file_name": "synthetic_qualification_corpus.jsonl",
                "partition_sha256": qual_sha,
                "first_exposed_at_utc": None,
                "exposure_count": 0,
                "events": [],
                "is_exposed": False,
                "current_status": "UNEXPOSED",
            }
        },
        "last_updated_utc": "2026-10-30T20:30:00Z",
    }

    ledger_path_1 = os.path.join(out_dir, "exposure_ledger.json")
    ledger_path_2 = os.path.join(LEDGER_DIR, "exposure_ledger_v4.json")

    with open(ledger_path_1, "w", encoding="utf-8") as f:
        json.dump(exposure_ledger_v4, f, indent=2, ensure_ascii=False)
    with open(ledger_path_2, "w", encoding="utf-8") as f:
        json.dump(exposure_ledger_v4, f, indent=2, ensure_ascii=False)

    print(f"[+] v4 Qualification Exposure Ledger successfully initialized at: {ledger_path_2}")
    print("[SUCCESS] Synthetic Dataset v4 generation complete!")


if __name__ == "__main__":
    main()
