#!/usr/bin/env python3
"""
Deterministic Offline Synthetic Vernacular Phishing & Benign Corpus Generator.
Part of Seva Cyber Sandbox (Phase 2).

PURPOSE & DESIGN GOALS:
1. Strict ₹0 Budget & Zero External Network Requests:
   - Completely local, offline, deterministic generation using reviewed templates
     and controlled synthetic substitutions.
   - Zero pretrained models, external AI APIs, or downloaded datasets.
2. Multilingual Support for Maharashtra Context:
   - Marathi in Devanagari script ('mr')
   - Romanized Marathi in Latin script ('mr-Latn')
   - Indian English ('en')
   - Code-switched Mixed Marathi-English ('mr-en')
3. Rigorous Campaign / Template Separation (Zero Leakage):
   - Training template families and Validation template families are 100% disjoint.
   - No variant of any training template is placed into the validation corpus.
   - The original locked evaluation partition ('locked_test') is strictly isolated.
4. Privacy & Synthetic Realism:
   - Never uses real personal information, real phone numbers, or real credentials.
   - Uses reserved/non-functional domains (e.g. '.invalid', '.test') and fictitious identifiers.
   - Does NOT embed self-identifying labels (e.g. a phishing message never calls itself a scam).
5. Determinism:
   - Seeding guarantee: Running with the same seed produces byte-for-byte identical output.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
import random
import re
import sys
from typing import Any, Dict, List, Set, Tuple

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.dataset_preprocessing import (
    check_cross_partition_leakage,
    detect_exact_duplicates,
    detect_near_duplicates_in_corpus,
    normalize_record_text,
    run_preprocessing_pipeline,
)

# ---------------------------------------------------------------------------
# SYNTHETIC PLACEHOLDERS & SUBSTITUTION VOCABULARY
# ---------------------------------------------------------------------------

DUMMY_DOMAINS = [
    "http://bill-update.invalid",
    "https://mahabill-support.invalid",
    "http://secure-kyc-portal.invalid",
    "https://quick-reward.invalid",
    "http://dispatch-notice.invalid",
    "https://pm-subsidy-portal.invalid",
    "http://traffic-challan-pay.invalid",
    "https://speedy-delivery.invalid",
    "http://hotel-rewards-job.invalid",
    "https://mudra-loan-sanction.invalid",
]

DUMMY_PHONES = [
    "9800000001",
    "9800000002",
    "9800000003",
    "9800000004",
    "9800000005",
    "022-55550111",
    "022-55550122",
    "1800-555-0199",
]

DUMMY_APKS = [
    "MSEDCL_Support_v3.apk",
    "MahaBijlee_Assistant.apk",
    "eKYC_Verification.apk",
    "FastChallan_Pay.apk",
    "RationSeva_Portal.apk",
    "PM_Kisan_Direct.apk",
    "SpeedyDispatch.apk",
    "QuickLoan_Approval.apk",
]

DUMMY_ORGANIZATIONS = [
    "महावितरण (MSEDCL)",
    "महाबिजली महामंडळ",
    "सह्याद्री बँक",
    "विदर्भ को-ऑप बँक",
    "महाराष्ट्र ग्रामीण बँक",
    "कोकण जनता बँक",
]

DUMMY_ORGANIZATIONS_ROMAN = [
    "MSEDCL",
    "MahaBijlee",
    "Sahyadri Bank",
    "Vidarbha Bank",
    "Maharashtra Gramin Bank",
    "Konkan Janata Bank",
]

DUMMY_AMOUNTS = [
    "₹1,250",
    "₹2,480",
    "₹3,150",
    "₹4,890",
    "₹5,000",
    "₹12,500",
    "₹25,000",
]

DUMMY_TIMES = [
    "आज रात्री ९:३० वाजता",
    "आज रात्री ८:०० वाजता",
    "रात्री १०:१५ वाजता",
    "२४ तासांच्या आत",
    "पुढील २ तासांत",
]

DUMMY_TIMES_ROMAN = [
    "aaj ratri 9:30 PM",
    "aaj ratri 8:00 PM",
    "tonight 10:15 PM",
    "within 24 hours",
    "next 2 hours",
]

DUMMY_CITIZEN_NAMES = [
    "रमेश पाटील",
    "सुनीता जोशी",
    "सचिन पवार",
    "प्रियांका देशमुख",
    "तुकाराम शिंदे",
    "अनीता कुलकर्णी",
]

DUMMY_CITIZEN_NAMES_ROMAN = [
    "Ramesh Patil",
    "Sunita Joshi",
    "Sachin Pawar",
    "Priyanka Deshmukh",
    "Tukaram Shinde",
    "Anita Kulkarni",
]

DUMMY_DEPTS = [
    "महाराष्ट्र सायबर विभाग (MahaCyber)",
    "मुंबई पोलीस सायबर सेल",
    "पुणे ग्रामीण सायबर पोलीस",
    "रिझर्व्ह बँक ऑफ इंडिया (RBI) ग्राहक सुरक्षा",
    "महावितरण दक्षता पथक",
]

DUMMY_DEPTS_ROMAN = [
    "MahaCyber Maharashtra",
    "Mumbai Cyber Crime Cell",
    "Pune Rural Police",
    "RBI Consumer Protection",
    "MSEDCL Vigilance Team",
]

DUMMY_SCAM_TYPES = [
    "वीज बिल वीज पुरवठा खंडित करण्याची भीती दाखवून",
    "बँक खाते पॅन कार्ड केवायसी ब्लॉक करण्याचे सांगून",
    "लाडकी बहीण योजनेच्या खोट्या ॲपद्वारे",
    "घरबसल्या पार्ट टाईम जॉब आणि युट्यूब लाईकच्या बहाण्याने",
    "लॉटरी रिवॉर्ड आणि कॅशबॅकच्या आमिषाने",
]

DUMMY_SCAM_TYPES_ROMAN = [
    "electricity bill power cut threat",
    "bank account KYC suspension warning",
    "welfare scheme registration app",
    "part-time YouTube video like task",
    "lottery reward and cashback lure",
]

DUMMY_VAL_DEPTS = [
    "राज्य वाहतूक नियंत्रण कक्ष",
    "CERT-In सायबर सुरक्षा केंद्र",
    "नागरी ग्राहक संरक्षण मंच",
    "आरोग्य विभाग महाराष्ट्र शासन",
]

DUMMY_VAL_DEPTS_ROMAN = [
    "State Traffic Control",
    "CERT-In Cyber Security Center",
    "Consumer Protection Forum",
    "Public Health Department Maharashtra",
]

DUMMY_QUERIES = [
    "कृपया या संदर्भात तपासा",
    "या लिंकबद्दल काय मत आहे",
    "हे खरे आहे की खोटे तपासा",
    "मित्राने पाठवले आहे, सुरक्षित आहे का",
    "यावर क्लिक करावे का सांगा",
    "या मेसेजची सत्यता पडताळा",
]

DUMMY_QUERIES_ROMAN = [
    "Krupaya check kara",
    "Is this link safe or fake",
    "Friend sent this to me, please review",
    "Should I open this link or ignore",
    "Please verify this forwarded message",
    "Urgent check needed for this",
]


# ---------------------------------------------------------------------------
# TEMPLATE DEFINITIONS (STRICTLY DISJOINT BY CAMPAIGN FAMILY)
# ---------------------------------------------------------------------------

# PARTITION A: DEVELOPMENT / TRAINING TEMPLATES
TRAINING_TEMPLATE_FAMILIES = [
    # 1. MSEDCL Urgent Powercut Threat
    {
        "campaign_id": "syn_camp_msedcl_powercut_train",
        "scenario": "msedcl_powercut_threat",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "प्रिय ग्राहक, तुमचे चालू महिन्याचे {org} वीज बिल अपडेट झालेले नाही. {time} तुमचे वीज कनेक्शन खंडित केले जाईल. त्वरित {domain} वर जाऊन बिल भरा किंवा {phone} वर संपर्क साधा.",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण तातडीची नोटीस: मागील बिल थकीत असल्याने आज {time} वीज पुरवठा खंडित केला जाईल. कनेक्शन चालू ठेवण्यासाठी {apk} डाउनलोड करा: {domain} किंवा संपर्क: {phone}.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Alert: Tumche {org_roman} light bill update zale nahi. {time_roman} connection cut honar. Laglich {domain} var jaun bill bhara kinva {phone} var call kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Dear Consumer, your electricity bill for {org_roman} is pending. Power disconnection scheduled for {time_roman}. Settle immediately at {domain} or call {phone}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Notice from {org_roman}: Light bill payment overdue aahe. Disconnection avoid karnyasathi visit {domain} or install {apk}. Help desk: {phone}.",
            },
        ],
    },
    # 2. Bank PAN / KYC Suspension Threat
    {
        "campaign_id": "syn_camp_bank_pan_kyc_train",
        "scenario": "bank_kyc_suspension",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महत्त्वाची सूचना: तुमच्या {org} खात्याचे पॅन कार्ड केवायसी प्रलंबित आहे. २४ तासांत तुमचे खाते ब्लॉक होईल. तात्काळ {domain} वर लॉगइन करून तुमचा OTP आणि पिन प्रविष्ट करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Suchana: Tumche {org_roman} bank account block honar aahe karan PAN KYC pending aahe. Lagech {domain} var click karun tumcha OTP aani ATM PIN takun khate chalu theva.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Alert: Your {org_roman} bank account will be suspended within 24 hours due to unverified PAN. Update your credentials and verify OTP at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Alert: Tumche {org_roman} account block hoil if KYC not completed today. Login at {domain} and verify OTP to keep account active.",
            },
        ],
    },
    # 3. UPI Cashback & Reward Lure
    {
        "campaign_id": "syn_camp_upi_cashback_train",
        "scenario": "upi_cashback_lure",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "अभिनंदन! तुम्हाला {amount} चा कॅशबॅक रिवॉर्ड मिळाला आहे. रक्कम थेट बँक खात्यात जमा करण्यासाठी {domain} वर क्लिक करा आणि तुमचा UPI PIN टाका.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Congratulation! Tumhala {amount} cha cashback lagla aahe. Bank khate madhe paise jama karnyasathi click kara {domain} aani PIN enter kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Congratulations! You have been awarded a cashback reward of {amount}. Visit {domain} now to confirm your UPI PIN and credit the funds.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Special Offer: Tumhala {amount} cashback approve zala aahe. Direct bank credit sathi open {domain} and verify PIN.",
            },
        ],
    },
    # 4. Part-Time Video Rating Job Scam
    {
        "campaign_id": "syn_camp_part_time_job_train",
        "scenario": "part_time_job_scam",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "घरबसल्या दररोज कमवा {amount}! फक्त व्हिडिओ लाईक करा आणि त्वरित मोबदला मिळवा. नावनोंदणीसाठी {domain} वर संपर्क साधा. कोणतीही फी नाही.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Ghari basun rojana {amount} kamva. Fakta video like kara aani paise ghya. Aajch join kara: {domain}. Telegram support chalu aahe.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Work from home opportunity: Earn up to {amount} daily by liking short videos online. Register immediately at {domain}. No prior experience required.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Part-time job alert: Daily income of {amount} shilpakara through simple rating tasks. Register via {domain}.",
            },
        ],
    },
    # 5. Failed Parcel Delivery Lure
    {
        "campaign_id": "syn_camp_parcel_delivery_train",
        "scenario": "courier_parcel_delivery",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "तुमचे पार्सल चुकीच्या पत्त्यामुळे वितरित होऊ शकले नाही. डिलिव्हरी पुन्हा शेड्युल करण्यासाठी आणि नाममात्र ₹२५ फी भरण्यासाठी {domain} वर क्लिक करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Tumche courier parcel address incorrect aslyamule deliver hou shakle nahi. Re-delivery sathi {domain} var click karun address update kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Delivery Notice: Your shipment could not be dispatched due to an incomplete delivery address. Update details and reschedule delivery at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Courier Alert: Tumche parcel delivery pending aahe. Please visit {domain} to confirm correct address and arrange delivery.",
            },
        ],
    },
    # 6. Government Welfare Scheme Sideloading Lure
    {
        "campaign_id": "syn_camp_welfare_pmkisan_train",
        "scenario": "govt_scheme_lure",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "मुख्यमंत्री लाडकी बहीण आणि पीएम किसान योजनेचा नवीन हप्ता {amount} मंजूर झाला आहे. खात्यात पैसे मिळवण्यासाठी {apk} डाउनलोड करा आणि e-KYC फॉर्म भरा: {domain}.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Sarkari yojana update: Ladki Bahin yojna cha {amount} cha hafta prapt karnyasathi {domain} var {apk} download kara aani form bhara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Welfare Portal Notice: Your beneficiary instalment of {amount} is awaiting approval. Install {apk} from {domain} to complete registration.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Kisan Yojana Alert: Tumcha installment of {amount} is ready for transfer. Complete biometric verification at {domain}.",
            },
        ],
    },
    # 7. Digital Ration Card APK Dropper
    {
        "campaign_id": "syn_camp_apk_ration_train",
        "scenario": "apk_sideload_utility",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महाराष्ट्र डिजिटल रेशन कार्ड आणि अन्न सुरक्षा यादीत नाव तपासण्यासाठी {apk} ॲप त्वरित इन्स्टॉल करा. डाउनलोड लिंक: {domain}.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Ration card e-service: Navin yadi madhe nav check karnyasathi {apk} install kara ya link varun: {domain}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Citizen Public Notice: Access your digital ration entitlements and subsidy allocation by installing {apk} available at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Public Alert: Navin ration card list declare zali aahe. Install {apk} from {domain} to verify your status.",
            },
        ],
    },
    # 8. Protective Advisories (Safety Warnings)
    {
        "campaign_id": "syn_camp_protective_advisories_train",
        "scenario": "official_safety_warning",
        "label": "protective_advisory",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} सायबर सुरक्षा सूचना: {scam_type} फसवणूक करणाऱ्यांपासून सावध राहा. कोणतीही बँक किंवा संस्था व्हॉट्सॲपवर .apk फाईल पाठवत नाही किंवा फोनवर OTP मागत नाही. अशा लिंकवर कधीही क्लिक करू नका. सायबर तक्रारीसाठी १९३० वर संपर्क साधा.",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} जनजागृती: {scam_type} अशा प्रकारच्या भूलथापांना बळी पडू नका. अनधिकृत ॲप्स डाऊनलोड करू नका किंवा अज्ञात लिंक उघडू नका. सायबर तक्रार पोर्टल: cybercrime.gov.in किंवा १९३०.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{dept_roman} Warning: {scam_type_roman} pasun savadh raha. Kontehi sarkari karyalay kinva bank phone var OTP kinva PIN magat nahi. Anolkhi link var click karu naka. Cyber fraud complaint sathi 1930 dial kara.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{dept_roman} Advisory: {scam_type_roman} messages var vishvas thevu naka. Do not install unknown APK files or share OTP. Cyber helpline: 1930.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "{dept_roman} Cyber Crime Advisory: Legitimate utility departments and banks never solicit your OTP, UPI PIN, or passwords over chat. Beware of scams involving {scam_type_roman}. Never install .apk files received from unknown senders. Report cyber fraud to 1930.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Public Safety Alert from {dept_roman}: Fraudsters are targeting citizens using {scam_type_roman}. Never click on unsolicited links or share confidential information. Dial 1930 for immediate cyber assistance.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{dept_roman} Safety Alert: {scam_type_roman} claims sathi konalahi OTP or password sangu naka. Do not download unknown APK files. Help line: 1930.",
            },
        ],
    },
    # 9. Legitimate Receipts & Confirmations
    {
        "campaign_id": "syn_camp_legitimate_receipts_train",
        "scenario": "genuine_receipt_transaction",
        "label": "legitimate",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{org} पावती: {name} यांच्या ग्राहक क्रमांकासाठी {amount} रुपयांचे बिल यशस्वीरीत्या भरले गेले आहे. अधिकृत संकेतस्थळ: mahadiscom.in. सहकार्याबद्दल धन्यवाद.",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{org} खाते अलर्ट: {name} यांच्या खात्यात {amount} जमा झाले आहेत. संदर्भ क्र. {consumer_no}. अधिकृत नेटबँकिंग वापरा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{org_roman} Receipt: {name_roman} sathi {amount} payment successful zale. Reference: {consumer_no}. Official portal mahadiscom.in var receipt download kara. Dhanyavad.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{org_roman} Alert: {name_roman} yanchya account madhe {amount} credit zale. Ref No {consumer_no}. Official banking use kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Payment Confirmation: Bill payment of {amount} for consumer account of {name_roman} at {org_roman} has been credited successfully. Official website: mahadiscom.in.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Transaction Alert: Your account at {org_roman} has been credited with {amount} for reference {consumer_no}. Thank you for banking with us.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{org_roman} Acknowledgement: Payment of {amount} received for account {consumer_no}. Download official receipt from portal. Thank you.",
            },
        ],
    },
    # 10. Ambiguous / Incomplete Submissions (For Quarantine & Review Testing)
    {
        "campaign_id": "syn_camp_ambiguous_short_train",
        "scenario": "ambiguous_incomplete",
        "label": "ambiguous_needs_review",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{query}: {domain}",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{query} आणि {phone} वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{query_roman}: {domain}",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{query_roman} - contact: {phone}",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Forwarded query: {query_roman} regarding {domain}",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Citizen check request: {domain}",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{query_roman} for {domain}",
            },
        ],
    },
]

# PARTITION B: VALIDATION TEMPLATES (COMPLETELY DISJOINT THEMES & CAMPAIGNS)
VALIDATION_TEMPLATE_FAMILIES = [
    # 11. MSEDCL Solar Subsidy & Meter Replacement Lure
    {
        "campaign_id": "syn_camp_msedcl_solar_val",
        "scenario": "msedcl_solar_subsidy",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण रूफटॉप सोलर योजना: केंद्र सरकारच्या अनुदानांतर्गत तुमच्या छतावर मोफत सोलर पॅनेल बसवण्यासाठी {domain} वर नावनोंदणी करा आणि ₹५०० नोंदणी फी भरा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "MahaVitaran Solar Scheme: Rooftop solar sathi nav nondani chalu aahe. Subsidised solar milvnyasathi {domain} var form bhara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "MahaVitaran Rooftop Solar Portal: Register at {domain} to avail 80% government subsidy on solar installation. Registration closing soon.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Solar Yojana Update: Tumchya gharasathi solar panel subsidy approve zali aahe. Check status at {domain}.",
            },
        ],
    },
    # 12. Credit Card Reward Points Expiry Lure
    {
        "campaign_id": "syn_camp_credit_card_points_val",
        "scenario": "credit_card_rewards",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "सूचना: तुमच्या {org} क्रेडिट कार्डचे ९,८५० रिवॉर्ड पॉइंट्स आज संपत आहेत. पॉइंट्सचे {amount} रोख रकमेत रूपांतर करण्यासाठी {domain} वर क्लेम करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Alert: Tumchya {org_roman} card che reward points expire hot aahet. Cash madhe convert karnyasathi {domain} var login kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Reminder: Your accumulated {org_roman} reward points worth {amount} will expire today. Redeem immediately to your bank account at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Reward Alert: {org_roman} credit points expire honar aahet. Redeem into cash instantly at {domain}.",
            },
        ],
    },
    # 13. RTO Traffic E-Challan Threat
    {
        "campaign_id": "syn_camp_rto_echallan_val",
        "scenario": "rto_echallan_fine",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महाराष्ट्र वाहतूक पोलीस ई-चलन: तुमच्या वाहनावरील {amount} रुपयांचे प्रलंबित दंड तात्काळ भरा अन्यथा वाहन परवाना निलंबित केला जाईल. अधिकृत ॲप: {apk} {domain} वरून डाउनलोड करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "RTO E-Challan Notice: Tumchya gadi var {amount} cha fine baki aahe. Court action avoid karnyasathi {domain} var fine bhara kinva {apk} install kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Maharashtra Traffic Police: Unpaid traffic violation challan of {amount} pending against your vehicle. Pay fine online or download {apk} at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "E-Challan Notice: Fine of {amount} pending aahe. License suspension avoid karnyasathi download {apk} from {domain}.",
            },
        ],
    },
    # 14. Hotel Review Rating Task Scam
    {
        "campaign_id": "syn_camp_hotel_rating_task_val",
        "scenario": "hotel_rating_scam",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "पार्ट टाईम काम: Google Maps वर हॉटेल आणि रिसॉर्ट्सना ५ स्टार रेटिंग द्या आणि दररोज {amount} थेट कमवा. आजच काम सुरू करण्यासाठी {domain} वर मेसेज करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Work from home opportunity: Hotel review kara aani darroj {amount} kamva. Quick payout via UPI. Contact {domain}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Flexible online part-time job: Rate popular hotels and tourist places to earn {amount} per day. No deposit needed. Apply at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Hotel rating task: Daily {amount} payout guaranteed. Join our verified review team at {domain}.",
            },
        ],
    },
    # 15. Telecom 5G SIM Deactivation Lure
    {
        "campaign_id": "syn_camp_telecom_5g_sim_val",
        "scenario": "telecom_sim_block",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "तातडीची सूचना: तुमचे सिम कार्ड ५G नेटवर्कमध्ये अपग्रेड न केल्यास आज रात्री १२ वाजता बंद केले जाईल. सेवा अखंडित ठेवण्यासाठी {domain} वर e-KYC पूर्ण करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Important: Tumche 4G SIM block honar aahe. 5G upgrade aani KYC sathi lagech {domain} var documents upload kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Telecom Service Alert: Your 4G SIM card will be deactivated tonight due to mandatory 5G migration. Complete your e-KYC verification at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "SIM Update Alert: 5G upgrade sathi e-KYC mandatory aahe. Service discontinuation avoid karnyasathi visit {domain}.",
            },
        ],
    },
    # 16. PM Mudra Loan Processing Fee Scam
    {
        "campaign_id": "syn_camp_pm_mudra_loan_val",
        "scenario": "pm_mudra_loan_lure",
        "label": "phishing",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "पीएम मुद्रा कर्ज योजना: तुमचा {amount} चा व्यवसाय कर्ज अर्ज मंजूर झाला आहे. मंजुरी पत्र मिळवण्यासाठी आणि प्रक्रिया शुल्क भरण्यासाठी {domain} वर जा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Pradhan Mantri Mudra Loan: Tumche {amount} loan approve zale aahe. Approval letter sathi {domain} var form bhara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "PM Mudra Yojana: Your business loan application of {amount} is approved at 2% interest. Download approval letter and verify at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Mudra Loan Update: Tumche loan of {amount} sanction zale aahe. Confirm acceptance at {domain}.",
            },
        ],
    },
    # 17. Validation Protective Advisories
    {
        "campaign_id": "syn_camp_protective_advisories_val",
        "scenario": "rto_banking_advisory",
        "label": "protective_advisory",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{val_dept} जनजागृती सूचना: ट्रॅफिक ई-चलन किंवा वीज बिलाच्या नावाखाली व्हॉट्सॲपवर पाठवलेले {apk} कधीही इन्स्टॉल करू नका. अधिकृत व्यवहार फक्त अधिकृत सरकारी संकेतस्थळांवरच करा. तक्रार: १९३०.",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{val_dept} इशारा: बँक केवायसी किंवा लॉटरीच्या नावाखाली {domain} सारख्या अनोळखी लिंकवर जाऊन वैयक्तिक माहिती भरू नका. सतर्क राहा, १९३० वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{val_dept_roman} Warning: Traffic challan kinva utility bill sathi anolkhi {apk} kadhihi install karu naka. Official portal vapra. Helpline: 1930.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{val_dept_roman} Advisory: Bank KYC update sathi {domain} link var OTP share karu naka. Cyber complaint 1930 dial kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "{val_dept_roman} Public Bulletin: Beware of fraudulent traffic challan and electricity bill links requesting installation of {apk}. Never enter your UPI PIN or download unverified apps. Dial 1930.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "{val_dept_roman} Consumer Safety Notice: Unsolicited messages linking to {domain} are deceptive. Do not share credentials or OTP. Report cyber crime to 1930.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{val_dept_roman} Alert: Konalahi OTP deu naka. Do not install {apk} received on messaging apps. E-Challan payment sathi only use official portal. Helpline: 1930.",
            },
        ],
    },
    # 18. Validation Legitimate Appointments
    {
        "campaign_id": "syn_camp_legitimate_appointments_val",
        "scenario": "genuine_appointment_booking",
        "label": "legitimate",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "नागरी रुग्णालय अपॉइंटमेंट: {name} यांची तपासणी {time} निश्चित झाली आहे. टोकन क्रमांक: {consumer_no}. अधिकृत पोर्टल: arogya.maharashtra.gov.in.",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण अधिकृत सूचना: {name} यांच्या परिसरातील वीज दुरुस्तीचे काम {time} पूर्ण झाले आहे. ग्राहक सेवा: १९१२.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Civil Hospital Appointment: {name_roman} yanchi OPD checkup {time_roman} confirm zali aahe. Token number: {consumer_no}.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "MahaVitaran Service Notice: {name_roman} yanchya bhagathil line maintenance {time_roman} complete zale aahe. Helpline: 1912.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Appointment Confirmation: Scheduled consultation for {name_roman} is confirmed for {time_roman} at Civil Hospital OPD. Token: {consumer_no}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Service Update: Power grid maintenance affecting {name_roman} has been completed as of {time_roman}. Contact 1912 for queries.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Appointment Alert: Consultation for {name_roman} is confirmed for {time_roman}. Token: {consumer_no}. Venue: Civil Hospital OPD.",
            },
        ],
    },
    # 19. Validation Ambiguous Submissions
    {
        "campaign_id": "syn_camp_ambiguous_forward_val",
        "scenario": "ambiguous_forward",
        "label": "ambiguous_needs_review",
        "templates": [
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "फॉरवर्ड मेसेज: {query} - {domain}",
            },
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "नागरिक विचारणा: {query} {phone}.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Forwarded message: {query_roman} {domain}",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Citizen question: {query_roman} contact {phone}",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Forwarded context: {query_roman} regarding {domain}",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Fwd: {query_roman} link {domain}",
            },
        ],
    },
]


def generate_family_records(
    family_def: Dict[str, Any],
    dataset_role: str,
    target_count: int,
    rng: random.Random,
    id_prefix: str,
    start_index: int,
) -> List[Dict[str, Any]]:
    """
    Generates synthetic records for a template family by sampling templates and substitution slots.
    Guarantees zero exact duplicate texts within the generated family.
    """
    records: List[Dict[str, Any]] = []
    seen_texts: Set[str] = set()
    camp_id = family_def["campaign_id"]
    scenario = family_def["scenario"]
    label = family_def["label"]
    templates = family_def["templates"]

    attempts = 0
    max_attempts = target_count * 10
    idx = start_index

    while len(records) < target_count and attempts < max_attempts:
        attempts += 1
        t = rng.choice(templates)
        org = rng.choice(DUMMY_ORGANIZATIONS)
        org_roman = rng.choice(DUMMY_ORGANIZATIONS_ROMAN)
        domain = rng.choice(DUMMY_DOMAINS)
        phone = rng.choice(DUMMY_PHONES)
        apk = rng.choice(DUMMY_APKS)
        amount = rng.choice(DUMMY_AMOUNTS)
        time = rng.choice(DUMMY_TIMES)
        time_roman = rng.choice(DUMMY_TIMES_ROMAN)
        name = rng.choice(DUMMY_CITIZEN_NAMES)
        name_roman = rng.choice(DUMMY_CITIZEN_NAMES_ROMAN)
        dept = rng.choice(DUMMY_DEPTS)
        dept_roman = rng.choice(DUMMY_DEPTS_ROMAN)
        scam_type = rng.choice(DUMMY_SCAM_TYPES)
        scam_type_roman = rng.choice(DUMMY_SCAM_TYPES_ROMAN)
        val_dept = rng.choice(DUMMY_VAL_DEPTS)
        val_dept_roman = rng.choice(DUMMY_VAL_DEPTS_ROMAN)
        query = rng.choice(DUMMY_QUERIES)
        query_roman = rng.choice(DUMMY_QUERIES_ROMAN)

        filled_text = t["pattern"].format(
            org=org,
            org_roman=org_roman,
            domain=domain,
            phone=phone,
            apk=apk,
            amount=amount,
            time=time,
            time_roman=time_roman,
            name=name,
            name_roman=name_roman,
            dept=dept,
            dept_roman=dept_roman,
            scam_type=scam_type,
            scam_type_roman=scam_type_roman,
            val_dept=val_dept,
            val_dept_roman=val_dept_roman,
            query=query,
            query_roman=query_roman,
            consumer_no=f"028{rng.randint(100000, 999999)}",
        )

        norm_check = normalize_record_text(filled_text)
        if norm_check in seen_texts:
            continue
        seen_texts.add(norm_check)

        rec_id = f"{id_prefix}_{idx:04d}"
        idx += 1

        rec = {
            "record_id": rec_id,
            "text": filled_text,
            "ground_truth_label": label,
            "language": t["lang"],
            "script": t["script"],
            "provenance_category": "synthetic_test_case",
            "provenance_verification_status": "synthetic_fixture",
            "source_reference": "Seva Synthetic Corpus Generator v1.0",
            "license_info": "CC0 1.0 Public Domain / Synthetic Generated",
            "collection_date": "2026-10-29",
            "review_status": "reviewed" if label != "ambiguous_needs_review" else "provisional",
            "campaign_id": camp_id,
            "dataset_role": dataset_role,
            "scenario_category": scenario,
        }
        records.append(rec)

    return records


def generate_full_synthetic_corpus(
    seed: int = 42,
    train_target_per_family: int = 35,
    val_target_per_family: int = 15,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Generates training and validation synthetic corpora deterministically.
    """
    rng = random.Random(seed)

    all_train_records: List[Dict[str, Any]] = []
    train_idx = 1
    for fam in TRAINING_TEMPLATE_FAMILIES:
        recs = generate_family_records(
            family_def=fam,
            dataset_role="development",
            target_count=train_target_per_family,
            rng=rng,
            id_prefix="syn_train",
            start_index=train_idx,
        )
        train_idx += len(recs)
        all_train_records.extend(recs)

    all_val_records: List[Dict[str, Any]] = []
    val_idx = 1
    for fam in VALIDATION_TEMPLATE_FAMILIES:
        recs = generate_family_records(
            family_def=fam,
            dataset_role="validation",
            target_count=val_target_per_family,
            rng=rng,
            id_prefix="syn_val",
            start_index=val_idx,
        )
        val_idx += len(recs)
        all_val_records.extend(recs)

    return all_train_records, all_val_records


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deterministic Offline Synthetic Vernacular Phishing & Benign Corpus Generator"
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed (default: 42)")
    parser.add_argument("--output-dir", type=str, default="data/generated", help="Output directory for generated files")
    parser.add_argument("--train-per-family", type=int, default=35, help="Target samples per training family (default: 35)")
    parser.add_argument("--val-per-family", type=int, default=15, help="Target samples per validation family (default: 15)")
    args = parser.parse_args()

    out_dir = os.path.abspath(os.path.join(PROJECT_ROOT, args.output_dir))
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 76)
    print("SEVA CYBER SANDBOX — SYNTHETIC VERNACULAR CORPUS GENERATOR")
    print("=" * 76)
    print(f"[*] Deterministic Seed: {args.seed}")
    print(f"[*] Output Directory: {out_dir}")

    # Generate raw synthetic records
    raw_train, raw_val = generate_full_synthetic_corpus(
        seed=args.seed,
        train_target_per_family=args.train_per_family,
        val_target_per_family=args.val_per_family,
    )
    total_raw = len(raw_train) + len(raw_val)
    print(f"[+] Raw Generated Records: {total_raw} (Train: {len(raw_train)}, Val: {len(raw_val)})")

    # Run preprocessing & quality validation pipeline
    quarantine_path = os.path.join(out_dir, "quarantine_records.jsonl")
    combined_raw = raw_train + raw_val
    pipe_res = run_preprocessing_pipeline(combined_raw, quarantine_output_path=quarantine_path)

    clean_train = pipe_res["training_records"]
    clean_val = pipe_res["validation_records"]
    quarantined = pipe_res["quarantined_records"]
    report = pipe_res["report"]

    # Save JSONL files
    train_file = os.path.join(out_dir, "synthetic_training_corpus.jsonl")
    val_file = os.path.join(out_dir, "synthetic_validation_corpus.jsonl")
    report_file = os.path.join(out_dir, "synthetic_corpus_report.json")

    with open(train_file, "w", encoding="utf-8") as f:
        for r in clean_train:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    with open(val_file, "w", encoding="utf-8") as f:
        for r in clean_val:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Include locked test manifest digest in report
    locked_manifest_path = os.path.join(PROJECT_ROOT, "data", "locked_test_manifest.json")
    if os.path.exists(locked_manifest_path):
        with open(locked_manifest_path, "r", encoding="utf-8") as mf:
            mdata = json.load(mf)
            report["locked_test_manifest_sha256"] = mdata.get("sha256_checksum")

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"[+] Saved Clean Training Corpus: {len(clean_train)} records -> {train_file}")
    print(f"[+] Saved Clean Validation Corpus: {len(clean_val)} records -> {val_file}")
    print(f"[+] Saved Quarantined Records: {len(quarantined)} records -> {quarantine_path}")
    print(f"[+] Saved Quality Report: {report_file}")
    print(f"[*] Leak-Free Partitioning: {report['leak_free_guarantee']}")
    print(f"[*] Label Distribution: {report['label_distribution']}")
    print(f"[*] Language Distribution: {report['language_distribution']}")
    print("=" * 76)


if __name__ == "__main__":
    main()
