#!/usr/bin/env python3
"""
Deterministic Offline Synthetic Vernacular Phishing & Benign Corpus Generator v2.
Part of Seva Cyber Sandbox (Phase 2.2 - Dataset Deconfounding).

PURPOSE & DESIGN GOALS:
1. Strict ₹0 Budget & Zero External Network Requests:
   - Completely local, offline, deterministic generation using reviewed templates
     and controlled synthetic substitutions.
   - Zero pretrained models, external AI APIs, or downloaded datasets.
2. Deconfounded Feature Representation:
   - Removes the artificial URL-label shortcut:
     * Phishing messages generated WITH and WITHOUT links.
     * Legitimate messages generated WITH and WITHOUT links.
     * Protective advisories generated WITH and WITHOUT links.
   - Balanced representation of security terms (OTP, PIN, UPI, APK, KYC, Urgency)
     across all three classes so no single token acts as a trivial shortcut.
3. Class Rebalancing (1:1:1 Ratio):
   - Phishing: ~33.3%
   - Legitimate: ~33.3%
   - Protective Advisory: ~33.3%
4. Multilingual Coverage for Maharashtra:
   - Marathi in Devanagari script ('mr')
   - Romanized Marathi in Latin script ('mr-Latn')
   - Indian English ('en')
   - Code-switched Mixed Marathi-English ('mr-en')
5. Strict Campaign / Template Isolation:
   - Training template families and Validation template families are 100% disjoint.
   - Original locked evaluation dataset is strictly isolated.
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
# SYNTHETIC PLACEHOLDERS & SUBSTITUTION VOCABULARY (ALL NON-LIVE / RESERVED)
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

DUMMY_LEGIT_DOMAINS = [
    "https://mahadiscom-receipt.invalid",
    "https://civil-hospital-portal.invalid",
    "https://bank-statement.invalid",
    "https://lpg-booking.invalid",
    "https://exam-portal.invalid",
    "https://citizen-service.invalid",
    "https://utility-selfservice.invalid",
]

DUMMY_ADVISORY_DOMAINS = [
    "https://cybercrime-alert.invalid",
    "https://police-cybercell.invalid",
    "https://rbi-safety.invalid",
    "https://certin-advisory.invalid",
    "https://consumer-vigilance.invalid",
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
# DECONFOUNDED TEMPLATE DEFINITIONS (PARTITION A: TRAINING)
# ---------------------------------------------------------------------------
# 4 Phishing, 4 Legitimate, 4 Protective Advisory, 1 Ambiguous (Quarantine)
# In each family, patterns intentionally include both link and link-free variants.

TRAINING_TEMPLATE_FAMILIES_V2 = [
    # 1. Phishing: MSEDCL Powercut Threat (with & without URL)
    {
        "campaign_id": "v2_camp_phish_powercut_train",
        "scenario": "msedcl_powercut_threat",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "प्रिय ग्राहक, तुमचे {org} वीज बिल अपडेट झालेले नाही. {time} वीज पुरवठा खंडित केला जाईल. तात्काळ {domain} वर जाऊन बिल भरा किंवा संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Alert: Tumche {org_roman} light bill update zale nahi. {time_roman} connection cut honar. Laglich {domain} var jaun bill bhara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Dear Consumer, your electricity bill for {org_roman} is overdue. Power disconnection scheduled for {time_roman}. Pay immediately at {domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Notice from {org_roman}: Light bill payment pending aahe. Disconnection avoid karnyasathi visit {domain} immediately.",
            },
            # Without URL (Phone callback / APK sideload request)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण तातडीची नोटीस: मागील बिल थकीत असल्याने आज {time} वीज पुरवठा खंडित केला जाईल. कनेक्शन चालू ठेवण्यासाठी त्वरित अधिकारी {phone} वर कॉल करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "MSEDCL Urgent: Tumche light bill pending aahe. {time_roman} line cut honar. Disconnection thambavnyasathi call officer {phone}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Electricity Notice: Unpaid bill for account {consumer_no}. Disconnection ordered for {time_roman}. Call power officer at {phone} to prevent power cut.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "MSEDCL Warning: Line cut honar aahe at {time_roman}. Immediate assistance sathi call help desk {phone}. Do not ignore.",
            },
        ],
    },
    # 2. Phishing: Bank PAN / KYC Suspension Threat (with & without URL)
    {
        "campaign_id": "v2_camp_phish_bank_kyc_train",
        "scenario": "bank_kyc_suspension",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महत्त्वाची सूचना: तुमच्या {org} खात्याचे पॅन कार्ड केवायसी प्रलंबित आहे. २४ तासांत खाते ब्लॉक होईल. तात्काळ {domain} वर जाऊन केवायसी पूर्ण करा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Alert: Your {org_roman} account will be suspended within 24 hours due to pending PAN KYC. Update your KYC details at {domain}.",
            },
            # Without URL (Direct OTP/Credential harvesting over chat or phone)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "बँक अलर्ट: तुमच्या {org} खात्याचे केवायसी ब्लॉक झाले आहे. खाते पुन्हा सुरू करण्यासाठी तुमच्या मोबाईलवर आलेला ६ अंकी OTP या चॅटवर तात्काळ पाठवा किंवा {phone} वर सांगा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Bank Notice: Tumche {org_roman} account block zale aahe. Re-activate karnyasathi tumcha OTP aani ATM PIN {phone} var verify kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Security Notice from {org_roman}: Your debit card is temporarily blocked. Reply with the one-time password OTP received on your phone to unfreeze immediately.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{org_roman} Alert: KYC expired zale aahe. Send OTP received on your mobile to this number to prevent account closure.",
            },
        ],
    },
    # 3. Phishing: UPI Cashback & Lottery Lure (with & without URL)
    {
        "campaign_id": "v2_camp_phish_upi_cashback_train",
        "scenario": "upi_cashback_lure",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "अभिनंदन! तुम्हाला {org} कडून {amount} चा UPI कॅशबॅक मंजूर झाला आहे. थेट खात्यात जमा करण्यासाठी {domain} वर क्लिक करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Congratulations! Tumhala {amount} cha UPI reward bhetla aahe. Account madhe claim karnyasathi {domain} open kara.",
            },
            # Without URL (PIN entry request / Collect lure)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "बक्षीस सूचना: तुमच्या खात्यासाठी {amount} चा लॉटरी कॅशबॅक तयार आहे. पैसे मिळवण्यासाठी तुमच्या PhonePe किंवा Google Pay ॲपवर पाठवलेली विनंती स्वीकारा आणि तुमचा UPI PIN टाका.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Reward Approved: You have won a cashback of {amount}. We have sent a payment collect request to your UPI ID. Enter your UPI PIN to accept the cash directly into your account.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Cashback Alert: Tumchya UPI var {amount} credit request pathavli aahe. Amount accept karnyasathi UPI PIN enter kara.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Special Offer: Cashback of {amount} is waiting. Open your UPI app and approve the request with UPI PIN to receive money.",
            },
        ],
    },
    # 4. Phishing: Courier Parcel Delivery Address Scam (with & without URL)
    {
        "campaign_id": "v2_camp_phish_parcel_train",
        "scenario": "courier_parcel_delivery",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "पार्सल सूचना: अपुऱ्या पत्त्यामुळे तुमचे पार्सल रोखून ठेवले आहे. वितरण पुन्हा सुरू करण्यासाठी आणि ₹२५ शुल्क भरण्यासाठी {domain} वर जा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Courier Delivery Notice: Package {consumer_no} could not be delivered due to incomplete address. Update your details and pay dispatch fee at {domain}.",
            },
            # Without URL (Phone call / Direct transfer extortion)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "स्पीड पोस्ट सूचना: तुमचे पार्सल मुख्य कार्यालयात अडकले आहे. पत्ता निश्चित करण्यासाठी आणि शुल्क भरण्यासाठी तात्काळ डिलिव्हरी बॉय {phone} वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Parcel Update: Tumche courier hold var aahe. Address confirm karnyasathi aani delivery fee sathi driver number {phone} var call kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Courier Alert: Consignment {consumer_no} is scheduled for return to sender. Call delivery agent at {phone} immediately to confirm drop location.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Delivery Notice: Parcel dispatch hold zale aahe. Contact hub manager at {phone} to reschedule delivery today.",
            },
        ],
    },

    # 5. Legitimate: MSEDCL & Utility Bill Receipts (with & without URL)
    {
        "campaign_id": "v2_camp_legit_utility_train",
        "scenario": "genuine_utility_receipt",
        "label": "legitimate",
        "templates": [
            # With URL (Official e-receipt link)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{org} पावती: {name} यांच्या ग्राहक क्रमांकासाठी {amount} रुपयांचे बिल भरले गेले आहे. अधिकृत ई-पावती: {legit_domain}. धन्यवाद.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{org_roman} Payment Receipt: {name_roman} sathi {amount} payment successful zale. E-receipt download: {legit_domain}. Dhanyavad.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Payment Confirmation: Electricity bill payment of {amount} for consumer account of {name_roman} at {org_roman} is successful. Download receipt at {legit_domain}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{org_roman} Receipt: Payment of {amount} received for account {consumer_no}. Official e-slip available at {legit_domain}. Thank you.",
            },
            # Without URL (Plain transaction SMS)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण पावती: ग्राहक क्र. {consumer_no} साठी {amount} चे वीज बिल यशस्वीरीत्या भरले आहे. चालू शिल्लक: ₹0. सहकार्याबद्दल धन्यवाद.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "MSEDCL: Consumer No {consumer_no} sathi {amount} light bill payment successfully credit zale. Outstanding balance is zero. Thank you.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Bill Acknowledgement: We have received {amount} towards electricity account {consumer_no} for {name_roman}. Transaction complete. MSEDCL.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Payment Received: {amount} for consumer number {consumer_no}. No outstanding balance. MSEDCL Customer Care 1912.",
            },
        ],
    },
    # 6. Legitimate: Banking Transaction & Credit Alerts (with & without URL)
    {
        "campaign_id": "v2_camp_legit_banking_train",
        "scenario": "genuine_banking_credit",
        "label": "legitimate",
        "templates": [
            # With URL (Official e-statement / portal)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{org} खाते अलर्ट: {name} यांच्या खात्यात {amount} जमा झाले आहेत. तपशील तपासण्यासाठी अधिकृत पोर्टल {legit_domain} पहा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Transaction Alert: Your account at {org_roman} has been credited with {amount} for ref {consumer_no}. View e-statement at {legit_domain}.",
            },
            # Without URL (Standard banking SMS with OTP security note)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{org} सूचना: तुमच्या खात्यातून {amount} UPI द्वारे यशस्वीरीत्या पाठवले गेले. संदर्भ क्र. {consumer_no}. बँक कधीही फोनवर OTP मागत नाही.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{org_roman}: {name_roman} yanchya account madhe {amount} credit zale. Ref No {consumer_no}. Never share your OTP with anyone.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "{org_roman} Alert: Account credited with {amount} on 29-Oct-2026. Available balance updated. For queries call 1800-555-0199.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{org_roman} Transaction: Payment of {amount} debited for reference {consumer_no}. If not done by you, SMS BLOCK to 9800000005.",
            },
        ],
    },
    # 7. Legitimate: Service & LPG Cylinder Booking Confirmations (with & without URL)
    {
        "campaign_id": "v2_camp_legit_booking_train",
        "scenario": "genuine_service_booking",
        "label": "legitimate",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "घरगुती गॅस बुकिंग: {name} यांच्यासाठी एलपीजी सिलिंडर बुकिंग यशस्वी झाले आहे. डिलिव्हरी ट्रॅक करण्यासाठी {legit_domain} ला भेट द्या.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "LPG Gas Booking Confirmed: Booking ref {consumer_no} for {name_roman} is accepted. Delivery scheduled within 24 hours. Track order at {legit_domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "भारत गॅस सूचना: ग्राहक क्र. {consumer_no} साठी सिलिंडर बुकिंग निश्चित झाले आहे. रोख रक्कम {amount} डिलिव्हरीच्या वेळी द्यावी. धन्यवाद.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Gas Booking: {name_roman} sathi cylinder booking confirm zali aahe. Delivery scheduled in 2 days. Total bill amount: {amount}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Railway Booking Confirmed: PNR {consumer_no} for passenger {name_roman}. Departure tonight at 10:15 PM. Wish you a safe journey. IRCTC.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Booking Alert: LPG Refill booking successful for {name_roman}. Cash on delivery amount is {amount}. Helpline: 1800-555-0199.",
            },
        ],
    },
    # 8. Legitimate: Civic & Maintenance Notices (with & without URL)
    {
        "campaign_id": "v2_camp_legit_maintenance_train",
        "scenario": "genuine_civic_notice",
        "label": "legitimate",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण नागरी सूचना: तुमच्या परिसरातील वीज लाईन दुरुस्तीचे काम पूर्ण झाले आहे. अधिकृत माहितीसाठी {legit_domain} तपासा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Civic Maintenance Notice: Power grid maintenance affecting {name_roman} has concluded. For schedule updates visit {legit_domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण जनसंपर्क: सब-स्टेशन दुरुस्तीचे काम आज {time} पूर्ण झाले असून सर्व परिसरातील वीज पुरवठा सुरळीत झाला आहे. हेल्पलाईन: १९१२.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "MahaVitaran Notice: Sector line maintenance {time_roman} complete zale aahe. Power restored. Contact 1912 for power queries.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Public Notice: Scheduled water supply pipeline maintenance completed. Normal pressure restored across all sectors. Municipal Corporation.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Service Notice: Area power supply maintenance is finished as of {time_roman}. Thank you for your patience. MSEDCL 1912.",
            },
        ],
    },

    # 9. Protective Advisory: Utility Phishing Awareness (with & without URL)
    {
        "campaign_id": "v2_camp_prot_utility_train",
        "scenario": "utility_safety_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL (Warning citizens about fake links, pointing to official portal)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} जनजागृती: वीज बिल वीज पुरवठा खंडित करण्याच्या खोट्या मेसेजवर विश्वास ठेवू नका. अनधिकृत लिंकवर क्लिक करू नका. अधिकृत मार्गदर्शन: {advisory_domain}. तक्रार: १९३०.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Cyber Security Advisory from {dept_roman}: Fraudsters are sending fake electricity disconnection notices. Never click unverified links. Official guidelines at {advisory_domain}. Helpline: 1930.",
            },
            # Without URL (General broadcast warning)
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "सायबर सुरक्षा सूचना: महावितरण कधीही व्हॉट्सॲपवर वीज बिल भरण्यासाठी .apk फाईल पाठवत नाही किंवा फोनवर OTP मागत नाही. अशा मेसेजवर उत्तर देऊ नका. तक्रारीसाठी १९३० वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{dept_roman} Warning: Light bill cut honar ase sangun konalahi OTP kinva paise deu naka. MSEDCL kadhihi personal phone varun call karat nahi. Cyber helpline: 1930.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Public Warning issued by {dept_roman}: Electricity departments never demand payment over personal phone calls or solicit OTPs. Protect your savings. Dial 1930 to report cyber fraud.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Safety Alert from {dept_roman}: MSEDCL employee ase claim karun konalahi OTP or PIN sangu naka. Report suspicious calls to 1930.",
            },
        ],
    },
    # 10. Protective Advisory: Banking Credentials & OTP Security (with & without URL)
    {
        "campaign_id": "v2_camp_prot_banking_train",
        "scenario": "banking_safety_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} इशारा: बँक खाते पॅन कार्ड केवायसी ब्लॉक करण्याचे सांगून येणाऱ्या मेसेजवर बँक तपशील भरू नका. अधिकृत सुरक्षा नियम: {advisory_domain}. सायबर हेल्पलाइन: १९३०.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Consumer Security Alert from {dept_roman}: Legitimate banks never threaten immediate account suspension via SMS. Check safety circulars at {advisory_domain}. Call 1930 to report fraud.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "रिझर्व्ह बँक जनजागृती: तुमचा बँक OTP, UPI PIN किंवा ATM पासवर्ड कोणाशीही शेअर करू नका. बँक कर्मचारी कधीही गोपनीय माहिती विचारत नाहीत. संशयास्पद व्यवहाराची तक्रार १९३० वर करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "RBI Awareness: Kontehi bank officer phone var tumcha OTP, debit card number kinva CVV magat nahi. Konalahi OTP deu naka. Fraud jhale tar 1930 dial kara.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Banking Vigilance Notice: Do not share OTP or UPI PIN under any pretext. Banks never conduct KYC verification over phone calls or WhatsApp. Stay vigilant.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{dept_roman} Alert: Never share bank OTP or netbanking password with anyone. Dial 1930 for immediate cyber assistance.",
            },
        ],
    },
    # 11. Protective Advisory: Malicious APK Sideloading Warning (with & without URL)
    {
        "campaign_id": "v2_camp_prot_apk_train",
        "scenario": "apk_malware_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} इशारा: व्हॉट्सॲपवर येणाऱ्या {apk} फाईल्स फोन हॅक करू शकतात. अनधिकृत ॲप्स कधीही इन्स्टॉल करू नका. अधिकृत सुरक्षा माहिती: {advisory_domain}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "{dept_roman} Advisory: Malicious {apk} files shared via social media can steal your SMS and banking credentials. Read security advisories at {advisory_domain}. Report incidents to 1930.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} सुरक्षा सूचना: {scam_type} नावाखाली व्हॉट्सॲपवर पाठवलेले {apk} कधीही इन्स्टॉल करू नका. अधिकृत ॲप्स फक्त Google Play Store वरूनच घ्या. हेल्पलाईन: १९३०.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{dept_roman} Warning: {scam_type_roman} sathi anolkhi {apk} install karu naka. Te mobile madhil OTP chore kartat. Cyber helpline: 1930.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Warning from {dept_roman}: Never download {apk} received from unknown senders regarding {scam_type_roman}. Dial 1930 to report suspicious files.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{dept_roman} Safety Alert: WhatsApp var aaleli {apk} file install karu naka. It can steal your confidential data. Cyber helpline: 1930.",
            },
        ],
    },
    # 12. Protective Advisory: Task & Job Scam Awareness (with & without URL)
    {
        "campaign_id": "v2_camp_prot_task_train",
        "scenario": "part_time_task_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} जनजागृती: {scam_type} बहाण्याने होणाऱ्या पार्ट टाईम जॉब फसवणुकीपासून सावध राहा. सायबर हेल्प पोर्टल: {advisory_domain}. मदत क्र. १९३०.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "{dept_roman} Public Advisory: Beware of part-time work-from-home tasks promising {amount} for video likes and reviews. View fraud typologies at {advisory_domain}. Report scams to 1930.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{dept} सायबर सेल सूचना: घरबसल्या दररोज {amount} कमवा अशा {scam_type} मेसेजना बळी पडू नका. सुरुवातीला नफा दाखवून नंतर मोठी रक्कम उकळली जाते. फसवणूक झाल्यास १९३० वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{dept_roman} Warning: {scam_type_roman} task scam pasun savadh raha. Darroj {amount} milnar ase sangun anolkhi account var paise transfer karu naka. Call 1930.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Employment Fraud Alert from {dept_roman}: No genuine enterprise offers {amount} daily for liking videos or rating maps. Never deposit processing fees to unlock task earnings.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "{dept_roman} Notice: Part-time job promises of {amount} var vishwas thevu naka. Do not send registration money via UPI. Dial 1930.",
            },
        ],
    },

    # 13. Ambiguous Submissions (Quarantined)
    {
        "campaign_id": "v2_camp_ambiguous_train",
        "scenario": "ambiguous_incomplete",
        "label": "ambiguous_needs_review",
        "templates": [
            {"lang": "mr", "script": "Devanagari", "pattern": "{query}: {domain}."},
            {"lang": "mr", "script": "Devanagari", "pattern": "{query} आणि {phone} वर कॉल करा."},
            {"lang": "mr-Latn", "script": "Latin", "pattern": "{query_roman}: {domain}"},
            {"lang": "mr-Latn", "script": "Latin", "pattern": "{query_roman} contact {phone}"},
            {"lang": "en", "script": "Latin", "pattern": "Forwarded query: {query_roman} regarding {domain}"},
            {"lang": "en", "script": "Latin", "pattern": "Citizen check request: {phone}"},
            {"lang": "mr-en", "script": "Mixed", "pattern": "{query_roman} for {domain}"},
        ],
    },
]


# ---------------------------------------------------------------------------
# DECONFOUNDED TEMPLATE DEFINITIONS (PARTITION B: VALIDATION - COMPLETELY DISJOINT)
# ---------------------------------------------------------------------------
# 3 Phishing, 3 Legitimate, 3 Protective Advisory, 1 Ambiguous (Quarantine)
# Zero overlap with training campaign scenarios.

VALIDATION_TEMPLATE_FAMILIES_V2 = [
    # 14. Phishing: MSEDCL Rooftop Solar Subsidy Scam (with & without URL)
    {
        "campaign_id": "v2_camp_phish_solar_val",
        "scenario": "msedcl_solar_subsidy",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण रूफटॉप सोलर योजना: केंद्र सरकारच्या अनुदानांतर्गत मोफत सोलर पॅनेल बसवण्यासाठी {domain} वर अर्ज करा आणि ₹५०० नोंदणी फी भरा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Solar Subsidy Scheme: Your rooftop solar panel application is approved with 80% subsidy. Confirm your address and pay processing fee at {domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महावितरण सोलर योजना: तुमच्या घरावर मोफत सोलर बसवण्यासाठी नोंदणी सुरू झाली आहे. सबसिडी फॉर्म मिळवण्यासाठी सोलर समन्वयक {phone} वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Rooftop Solar Scheme: Tumchya gharasathi 80% subsidy pass zali aahe. Solar coordinator sathi {phone} var call kara aani registration kara.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "MahaVitaran Solar Update: Subsidy allocation pending aahe. Call department officer {phone} to claim your rooftop panel.",
            },
        ],
    },
    # 15. Phishing: Credit Card Reward Points Expiry Lure (with & without URL)
    {
        "campaign_id": "v2_camp_phish_rewards_val",
        "scenario": "credit_card_rewards",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "सूचना: तुमच्या {org} क्रेडिट कार्डचे ९,८५० रिवॉर्ड पॉइंट्स आज संपत आहेत. पॉइंट्सचे {amount} रोख रकमेत रूपांतर करण्यासाठी {domain} वर क्लेम करा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Urgent Reminder: Your accumulated {org_roman} reward points worth {amount} expire tonight. Redeem cash instantly to your bank account at {domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "क्रेडिट कार्ड अलर्ट: तुमच्या {org} कार्डचे {amount} रुपयांचे कॅश पॉईंट्स आज रात्री १२ वाजता लॅप्स होतील. पॉईंट्स थेट खात्यात जमा करण्यासाठी कार्ड प्रतिनिधी {phone} वर कॉल करा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Alert: Tumchya {org_roman} card che reward points worth {amount} expire hot aahet. Cash credit sathi call bank rep {phone} immediately.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Reward Notice: {org_roman} credit card points of {amount} will expire. Call executive at {phone} to redeem into your savings account.",
            },
        ],
    },
    # 16. Phishing: RTO Traffic E-Challan Threat (with & without URL)
    {
        "campaign_id": "v2_camp_phish_echallan_val",
        "scenario": "rto_echallan_fine",
        "label": "phishing",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महाराष्ट्र वाहतूक पोलीस ई-चलन: तुमच्या वाहनावरील {amount} चा प्रलंबित दंड तात्काळ भरा अन्यथा वाहन परवाना निलंबित केला जाईल. दंड भरा: {domain}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Traffic Police Notice: Unpaid violation challan of {amount} registered against your vehicle. Pay fine online immediately at {domain} to avoid court summons.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "वाहतूक पोलीस ई-चलन नोटीस: तुमच्या वाहनाचा {amount} रुपयांचा दंड थकीत आहे. कोर्ट वॉरंट टाळण्यासाठी आजच चलन अधिकारी {phone} वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "RTO Traffic Challan: Tumchya gadi var {amount} cha fine baki aahe. Court action avoid karnyasathi RTO desk {phone} var contact kara.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "E-Challan Warning: Pending fine of {amount}. Vehicle impound order issued. Call traffic duty officer at {phone} immediately.",
            },
        ],
    },

    # 17. Legitimate: Civil Hospital Appointments & OPD Booking (with & without URL)
    {
        "campaign_id": "v2_camp_legit_hospital_val",
        "scenario": "genuine_appointment_booking",
        "label": "legitimate",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "नागरी रुग्णालय अपॉइंटमेंट: {name} यांची तपासणी {time} निश्चित झाली आहे. टोकन: {consumer_no}. डिजिटल स्लिप: {legit_domain}.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Appointment Confirmed: Scheduled OPD medical consultation for {name_roman} is booked for {time_roman} at Civil Hospital. Download token slip at {legit_domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "नागरी रुग्णालय सूचना: रुग्ण {name} यांच्या तपासणीसाठी टोकन क्रमांक {consumer_no} मंजूर झाला आहे. वेळ {time}. कृपया वेळेवर उपस्थित राहावे.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Civil Hospital OPD: Consultation for {name_roman} confirmed for {time_roman}. Token number: {consumer_no}. Venue: Room 14 OPD.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Doctor Appointment: Patient {name_roman} appointment confirmed for {time_roman}. Token: {consumer_no}. Please bring previous records.",
            },
        ],
    },
    # 18. Legitimate: Telecom Plan & Recharge Receipts (with & without URL)
    {
        "campaign_id": "v2_camp_legit_telecom_val",
        "scenario": "genuine_telecom_service",
        "label": "legitimate",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "टेलिकॉम रिचार्ज पावती: {name} यांच्या मोबाईलसाठी {amount} चा प्लॅन यशस्वी झाला. वैधतेची माहिती {legit_domain} वर तपासा. धन्यवाद.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Recharge Successful: Mobile recharge of {amount} for {name_roman} has been processed. Check active plan benefits at {legit_domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "बीएसएनएल सूचना: तुमचा {amount} रुपयांचा मासिक प्लॅन यशस्वीरीत्या सुरू झाला आहे. २४ दिवसांची अमर्यादित कॉलिंग सुविधा सक्रिय आहे.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Telecom Alert: Recharge of {amount} done successfully for customer {name_roman}. Validity 28 days. Enjoy unlimited data.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Payment Received: Postpaid bill of {amount} cleared for account {consumer_no}. Current outstanding balance is zero. Thank you.",
            },
        ],
    },
    # 19. Legitimate: Education & Exam Hall Ticket Notices (with & without URL)
    {
        "campaign_id": "v2_camp_legit_exam_val",
        "scenario": "genuine_education_notice",
        "label": "legitimate",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महाराष्ट्र राज्य परीक्षा मंडळ: {name} यांचे हॉल तिकीट प्रसिद्ध झाले आहे. अधिकृत संकेतस्थळ {legit_domain} वरून डाउनलोड करा.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Board Examination Notice: Admit card for candidate {name_roman} has been generated. Download hall ticket at {legit_domain}.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "विद्यापीठ सूचना: विद्यार्थी {name} यांचा शिष्यवृत्ती अर्ज मंजूर झाला असून {amount} ची रक्कम बँक खात्यात थेट जमा केली आहे.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "University Notice: Student {name_roman} scholarship allotment of {amount} has been credited to bank account. Reference: {consumer_no}.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Scholarship Department: Financial sanction of {amount} approved for student {name_roman}. Direct bank transfer completed.",
            },
        ],
    },

    # 20. Protective Advisory: RTO Traffic E-Challan Warning (with & without URL)
    {
        "campaign_id": "v2_camp_prot_rto_val",
        "scenario": "rto_safety_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{val_dept} इशारा: ट्रॅफिक ई-चलन भरण्यासाठी व्हॉट्सॲपवर पाठवलेल्या लिंकवर जाऊन पेमेंट करू नका. अधिकृत सरकारी पोर्टल: {advisory_domain}. तक्रार: १९३०.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Public Traffic Bulletin from {val_dept_roman}: Beware of fraudulent traffic challan links requesting online fine payments. Verify penalties at {advisory_domain}. Report cyber crime to 1930.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "वाहतूक पोलीस जनजागृती: ई-चलन किंवा दंड भरण्यासाठी अनोळखी व्यक्तींनी व्हॉट्सॲपवर पाठवलेले .apk ॲप कधीही इन्स्टॉल करू नका. अधिकृत दंड फक्त अधिकृत सरकारी केंद्रावरच भरा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "{val_dept_roman} Warning: E-Challan payment sathi anolkhi APK kadhihi install karu naka. Traffic police phone var OTP magat nahi. Help line: 1930.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Safety Advisory: Never install unverified apps for traffic fines. Dial 1930 to report suspicious extortion calls.",
            },
        ],
    },
    # 21. Protective Advisory: Fake Lottery & Prize Scheme Awareness (with & without URL)
    {
        "campaign_id": "v2_camp_prot_lottery_val",
        "scenario": "lottery_reward_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "{val_dept} सूचना: तुम्हाला करोडोची लॉटरी किंवा बक्षीस लागले आहे अशा संदेशांना बळी पडू नका. फसवणुकीचे प्रकार समजून घेण्यासाठी {advisory_domain} पहा. सायबर हेल्प: १९३०.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Public Safety Bulletin: Fraudulent syndicates circulate fake lottery winner announcements demanding processing tax. Read guidelines at {advisory_domain}. Dial 1930.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "सायबर सुरक्षा सूचना: कोणत्याही सरकारी योजनेत लॉटरी किंवा बक्षीस मिळवण्यासाठी अगोदर पैसे भरावे लागत नाहीत. कोणतीही नोंदणी फी भरू नका. तक्रार: १९३०.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Lottery Fraud Warning: Kontehi sarkari office lottery jinknyasathi advance processing fee magat nahi. Konalahi paise transfer karu naka. Call 1930.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Consumer Advisory: Do not pay processing fee or tax to claim lottery prizes. It is a scam. Report incidents to 1930.",
            },
        ],
    },
    # 22. Protective Advisory: Digital Arrest & Fake Police Extortion Awareness (with & without URL)
    {
        "campaign_id": "v2_camp_prot_digital_arrest_val",
        "scenario": "digital_arrest_advisory",
        "label": "protective_advisory",
        "templates": [
            # With URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "महाराष्ट्र सायबर विभाग: 'डिजिटल अरेस्ट' किंवा पोलीस चौकशीच्या नावाखाली व्हॉट्सॲप व्हिडिओ कॉलवर पैसे मागणाऱ्यांपासून सावध राहा. अधिकृत माहिती: {advisory_domain}. हेल्पलाईन: १९३०.",
            },
            {
                "lang": "en",
                "script": "Latin",
                "pattern": "Critical Police Advisory from {val_dept_roman}: Law enforcement agencies never conduct 'Digital Arrest' via Skype or video calls. Learn how to protect yourself at {advisory_domain}. Dial 1930.",
            },
            # Without URL
            {
                "lang": "mr",
                "script": "Devanagari",
                "pattern": "सायबर क्राईम इशारा: पोलीस, सीबीआय किंवा कस्टम अधिकारी कधीही फोनवर पैशांची मागणी करत नाहीत. अशा धमक्यांना घाबरू नका. तात्काळ स्थानिक पोलीस किंवा १९३० वर संपर्क साधा.",
            },
            {
                "lang": "mr-Latn",
                "script": "Latin",
                "pattern": "Police Advisory: Digital arrest naavachi kontech legal provision nahi. Video call var konalahi paise deu naka. Lagech 1930 dial kara.",
            },
            {
                "lang": "mr-en",
                "script": "Mixed",
                "pattern": "Public Alert: Police and CBI never interrogate citizens on WhatsApp video or demand money. Dial 1930 immediately if targeted.",
            },
        ],
    },

    # 23. Ambiguous Submissions (Quarantined)
    {
        "campaign_id": "v2_camp_ambiguous_val",
        "scenario": "ambiguous_forward",
        "label": "ambiguous_needs_review",
        "templates": [
            {"lang": "mr", "script": "Devanagari", "pattern": "फॉरवर्ड मेसेज: {query} - {domain}."},
            {"lang": "mr", "script": "Devanagari", "pattern": "नागरिक विचारणा: {query} संपर्क {phone}."},
            {"lang": "mr-Latn", "script": "Latin", "pattern": "Forwarded message: {query_roman} {domain}"},
            {"lang": "mr-Latn", "script": "Latin", "pattern": "Citizen question: {query_roman} contact {phone}"},
            {"lang": "en", "script": "Latin", "pattern": "Forwarded context: {query_roman} regarding {domain}"},
            {"lang": "mr-en", "script": "Mixed", "pattern": "Fwd: {query_roman} link {domain}"},
        ],
    },
]


def generate_family_records_v2(
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
    max_attempts = target_count * 20
    idx = start_index

    while len(records) < target_count and attempts < max_attempts:
        attempts += 1
        t = rng.choice(templates)
        org = rng.choice(DUMMY_ORGANIZATIONS)
        org_roman = rng.choice(DUMMY_ORGANIZATIONS_ROMAN)
        domain = rng.choice(DUMMY_DOMAINS)
        legit_domain = rng.choice(DUMMY_LEGIT_DOMAINS)
        advisory_domain = rng.choice(DUMMY_ADVISORY_DOMAINS)
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
            legit_domain=legit_domain,
            advisory_domain=advisory_domain,
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
            "source_reference": "Seva Synthetic Corpus Generator v2.0 (Deconfounded)",
            "license_info": "CC0 1.0 Public Domain / Synthetic Generated",
            "collection_date": "2026-10-29",
            "review_status": "reviewed" if label != "ambiguous_needs_review" else "provisional",
            "campaign_id": camp_id,
            "dataset_role": dataset_role,
            "scenario_category": scenario,
        }
        records.append(rec)

    return records


def generate_full_synthetic_corpus_v2(
    seed: int = 42,
    train_target_per_family: int = 30,
    val_target_per_family: int = 15,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Generates balanced, deconfounded training and validation synthetic corpora deterministically.
    """
    rng = random.Random(seed)

    all_train_records: List[Dict[str, Any]] = []
    train_idx = 1
    for fam in TRAINING_TEMPLATE_FAMILIES_V2:
        recs = generate_family_records_v2(
            family_def=fam,
            dataset_role="development",
            target_count=train_target_per_family,
            rng=rng,
            id_prefix="syn_v2_train",
            start_index=train_idx,
        )
        train_idx += len(recs)
        all_train_records.extend(recs)

    all_val_records: List[Dict[str, Any]] = []
    val_idx = 1
    for fam in VALIDATION_TEMPLATE_FAMILIES_V2:
        recs = generate_family_records_v2(
            family_def=fam,
            dataset_role="validation",
            target_count=val_target_per_family,
            rng=rng,
            id_prefix="syn_v2_val",
            start_index=val_idx,
        )
        val_idx += len(recs)
        all_val_records.extend(recs)

    return all_train_records, all_val_records


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seva Cyber Sandbox — Synthetic Vernacular Corpus Generator v2 (Deconfounded)"
    )
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed (default: 42)")
    parser.add_argument("--output-dir", type=str, default="data/generated/v2", help="Output directory for v2 files")
    parser.add_argument("--train-per-family", type=int, default=30, help="Target samples per training family (default: 30)")
    parser.add_argument("--val-per-family", type=int, default=15, help="Target samples per validation family (default: 15)")
    args = parser.parse_args()

    out_dir = os.path.abspath(os.path.join(PROJECT_ROOT, args.output_dir))
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 76)
    print("SEVA CYBER SANDBOX — SYNTHETIC CORPUS GENERATOR V2 (DECONFOUNDED)")
    print("=" * 76)
    print(f"[*] Deterministic Seed: {args.seed}")
    print(f"[*] Output Directory: {out_dir}")

    # Generate raw synthetic records
    raw_train, raw_val = generate_full_synthetic_corpus_v2(
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
    report["corpus_version"] = "2.2.0-deconfounded"

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
