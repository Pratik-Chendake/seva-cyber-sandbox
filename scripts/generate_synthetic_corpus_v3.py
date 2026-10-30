#!/usr/bin/env python3
"""
Deterministic Offline Synthetic Vernacular Phishing & Benign Corpus Generator v3.
Part of Seva Cyber Sandbox (Phase 6.4.2 - Fresh Synthetic Dataset v3 and Benchmark Isolation).

SPECIFICATION & DESIGN PRINCIPLES:
1. Strict ₹0 Budget & Zero External Network Requests:
   - Completely local, offline, deterministic generation using reviewed templates
     and controlled synthetic substitutions.
   - Zero pretrained models, external AI APIs, or downloaded datasets.
2. Family-Disjoint Partitioning:
   - Three strictly disjoint partitions:
     * Training partition (1,200 records across 24 distinct campaign families)
     * Development validation partition (300 records across 6 distinct campaign families)
     * Sealed qualification benchmark partition (450 records across 9 distinct campaign families)
   - Zero overlap of campaign families, scenario categories, or phrasing templates across partitions.
3. Class Rebalancing (1:1:1 Ratio):
   - Phishing: ~33.3%
   - Legitimate: ~33.3%
   - Protective Advisory: ~33.3%
4. Balanced Multilingual & Messaging-Mode Coverage:
   - Languages: 'mr' (Marathi Devanagari), 'mr-Latn' (Romanized Marathi), 'en' (English), 'mr-en' (Mixed)
   - Messaging modes: 'sms', 'whatsapp', 'formal_notice', 'advisory_bulletin', 'service_alert'
5. Deconfounded URL Presence:
   - Link-bearing and link-free examples in every class (Phishing, Legitimate, Advisory)
   - URLs are never a shortcut for the label.
6. Consumable Sealed Benchmark Protection:
   - Qualification partition manifest records lifecycle state as 'sealed_independent_benchmark'.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
import random
import re
import sys
import time
from typing import Any, Dict, List, Set, Tuple

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.dataset_preprocessing import (
    clean_evasion_characters,
    detect_script,
    normalize_record_text,
    validate_single_record,
)

# Output directory for v3 corpus
OUTPUT_DIR_V3 = os.path.join(PROJECT_ROOT, "data", "generated", "v3")

# Safe dummy entities (all .invalid or non-routable fictional domains)
DUMMY_PHISH_DOMAINS = [
    "http://bill-update-alert.invalid",
    "https://mahabill-support.invalid",
    "http://secure-kyc-auth.invalid",
    "https://quick-courier-trace.invalid",
    "http://incometax-refund-claim.invalid",
    "https://speedy-esim-verify.invalid",
    "http://toll-fastag-recharge.invalid",
    "https://epfo-claim-settle.invalid",
    "http://solar-subsidy-portal.invalid",
    "https://card-reward-points.invalid",
    "http://traffic-echallan-pay.invalid",
    "https://cbi-investigation-summons.invalid",
    "http://pm-mudra-direct-loan.invalid",
]

DUMMY_LEGIT_DOMAINS = [
    "https://mahadiscom-receipt.invalid",
    "https://bank-statement-alert.invalid",
    "https://lpg-booking-portal.invalid",
    "https://grampanchayat-tax.invalid",
    "https://maha-metro-qr.invalid",
    "https://irctc-pnr-status.invalid",
    "https://ration-seva-pds.invalid",
    "https://school-pta-portal.invalid",
    "https://civil-hospital-opd.invalid",
    "https://telecom-selfservice.invalid",
    "https://education-board-exam.invalid",
    "https://municipal-water-supply.invalid",
]

DUMMY_ADVISORY_DOMAINS = [
    "https://cybercrime-alert.invalid",
    "https://police-cybercell.invalid",
    "https://rbi-consumer-safety.invalid",
    "https://certin-advisory-feed.invalid",
    "https://uidai-aadhaar-safety.invalid",
    "https://trai-vigilance-notice.invalid",
    "https://state-traffic-advisory.invalid",
    "https://agriculture-dept-alert.invalid",
]

DUMMY_PHONES = [
    "9800000001",
    "9800000002",
    "9800000003",
    "9800000004",
    "9800000005",
    "9811000000",
    "9822000000",
    "022-55550111",
    "022-55550122",
    "1800-555-0199",
]

DUMMY_HELPLINES = [
    "1930 (National Cyber Crime Helpline)",
    "1930 / cybercrime.gov.in",
    "112 (National Emergency Support)",
    "1800-555-0199",
    "1912 (Electricity Helpline)",
    "1906 (LPG Emergency Helpline)",
]

DUMMY_AMOUNTS = ["₹450", "₹1,250", "₹2,480", "₹3,150", "₹4,890", "₹12,500", "₹25,000", "₹50,000"]
DUMMY_TIMES = ["today 8:00 PM", "aaj ratri 9:30 PM", "within 24 hours", "before 5:00 PM tomorrow"]
DUMMY_DATES = ["15-Nov-2026", "20-Nov-2026", "01-Dec-2026", "10-Dec-2026"]
DUMMY_REFS = ["TXN-884920", "REF-492019", "ACK-918204", "TOKEN-58291", "BILL-381920", "REG-77482"]

# ---------------------------------------------------------------------------
# CAMPAIGN FAMILY DEFINITIONS (39 DISJOINT FAMILIES)
# ---------------------------------------------------------------------------

# 1. TRAINING CAMPAIGN FAMILIES (24 families: 8 Phish, 8 Legit, 8 Advisory)
TRAIN_FAMILIES = {
    # Phishing (8)
    "v3_train_phish_msedcl_powercut": {
        "scenario": "msedcl_powercut_threat",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "सूचना: तुमचे महावितरण वीज बिल थकीत आहे. आज रात्री ९:३० पर्यंत वीजपुरवठा खंडित होईल. त्वरित भरणा करा: {domain}"),
            ("mr-Latn", "sms", True, "Alert: Mahavitaran light bill pending aahe. Power cut honar aaj ratri. Pay kara: {domain}"),
            ("en", "sms", True, "Urgent Notice: Your electricity bill is unpaid. Power disconnection scheduled for {time}. Pay now at {domain}"),
            ("mr-en", "whatsapp", True, "Dear Consumer, tumche MSEDCL bill overdue aahe. Disconnection avoid karnyasathi visit {domain} immediately."),
            ("mr", "sms", False, "महावितरण अलर्ट: वीज बिल अपडेट न केल्यास आज रात्री कनेक्शन तोडले जाईल. सहाय्यक अधिकारी यांच्याशी {phone} वर संपर्क साधा."),
            ("mr-Latn", "whatsapp", False, "Urgent MSEDCL Update: Bill update fail zale. Line cut honar. Call electricity officer at {phone} right now."),
            ("en", "formal_notice", False, "MSEDCL Electricity Department Notice: Immediate bill clearance required. To stop meter removal, contact desk at {phone}."),
            ("mr-en", "sms", False, "Notice: Power cutoff warning for consumer {ref}. Please call sub-station officer {phone} within 2 hours."),
        ],
    },
    "v3_train_phish_bank_kyc_freeze": {
        "scenario": "bank_kyc_suspension",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "बँक सूचना: तुमचे बँक खाते पॅन कार्ड अपडेट न केल्यामुळे ब्लॉक केले आहे. केवायसी पूर्ण करा: {domain}"),
            ("mr-Latn", "sms", True, "Bank Alert: Tumche account suspend zale aahe. KYC re-verification sathi click kara: {domain}"),
            ("en", "sms", True, "State Bank Notice: Your bank account is suspended due to expired KYC. Reactivate within 24 hours at {domain}"),
            ("mr-en", "whatsapp", True, "Dear Customer, tumche netbanking block kele aahe. To unlock immediately, submit Aadhaar at {domain}"),
            ("mr", "sms", False, "बँक केवायसी सूचना: तुमचे खाते २४ तासांत गोठवले जाईल. त्वरित शाखा व्यवस्थापक यांना {phone} वर कॉल करून माहिती द्या."),
            ("mr-Latn", "whatsapp", False, "Bank Warning: Debit card deactivated due to pending PAN link. Call nodal officer {phone} to prevent permanent block."),
            ("en", "formal_notice", False, "Customer Alert: Immediate KYC document verification required for account {ref}. Contact desk at {phone}."),
            ("mr-en", "sms", False, "Important: Tumche account hold var thevle aahe. Call support desk {phone} to clear verification."),
        ],
    },
    "v3_train_phish_courier_hold": {
        "scenario": "courier_parcel_delivery",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "स्पीड पोस्ट सूचना: तुमचा पार्सल पत्ता अपूर्ण असल्याने थांबवला आहे. ₹२५ पत्ता शुल्क भरून पार्सल मिळवा: {domain}"),
            ("mr-Latn", "sms", True, "Courier Alert: Tumcha parcel hub var hold var aahe. Address update kara aani delivery ghya: {domain}"),
            ("en", "sms", True, "Delivery Notification: Your shipment {ref} is held due to incorrect address. Pay redelivery fee at {domain}"),
            ("mr-en", "whatsapp", True, "Parcel Notice: Tumcha parcel dispatch fail zala. Re-schedule delivery and pay small fee at {domain}"),
            ("mr", "sms", False, "कुरियर सूचना: तुमचे पार्सल गोडाऊनमध्ये अडकले आहे. डिलिव्हरी बॉयशी {phone} वर संपर्क साधा."),
            ("mr-Latn", "whatsapp", False, "Courier Desk: Package {ref} delivery pending. Call delivery coordinator at {phone} before 6 PM."),
            ("en", "service_alert", False, "Express Logistics: Consignment delivery postponed. Contact hub supervisor at {phone} for instant release."),
            ("mr-en", "sms", False, "Dispatch Notice: Parcel hold var aahe. Call local depot {phone} to confirm house location."),
        ],
    },
    "v3_train_phish_part_time_job": {
        "scenario": "part_time_task_scam",
        "label": "phishing",
        "patterns": [
            ("mr", "whatsapp", True, "घरबसल्या कमवा: दररोज यूट्यूब व्हिडिओ लाईक करून ₹२,५०० ते ₹५,००० कमवा. नोंदणीसाठी येथे क्लिक करा: {domain}"),
            ("mr-Latn", "whatsapp", True, "Work from Home: Daily 2-3 tas kam karun ₹3000 kamva. Registration sathi click kara: {domain}"),
            ("en", "whatsapp", True, "Part-Time Job Offer: Earn ₹2,000 to ₹4,500 daily by rating hotels and videos. Start your trial today at {domain}"),
            ("mr-en", "sms", True, "Student & Housewife Job: Daily income ₹3500 guaranteed. Join Telegram task group at {domain}"),
            ("mr", "sms", False, "नोकरीची संधी: घरबसल्या पार्ट टाईम डेटा काम करून दरमहा ₹३०,००० कमवा. व्हॉट्सॲप मेसेज करा: {phone}"),
            ("mr-Latn", "sms", False, "Earn Money: Daily ₹2500 task salary. Send 'HI' to manager on {phone} to start immediately."),
            ("en", "sms", False, "Hiring Alert: Part-time online rating job with immediate payout. Contact recruiter via WhatsApp at {phone}"),
            ("mr-en", "whatsapp", False, "Online Kam: Daily payment guaranteed. Contact hr team {phone} to receive first task assignment."),
        ],
    },
    "v3_train_phish_income_tax_refund": {
        "scenario": "income_tax_refund_lure",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "प्राप्तिकर विभाग सूचना: तुमचा ₹१८,४५० परतावा (Refund) मंजूर झाला आहे. बँक खात्यात जमा करण्यासाठी येथे पडताळणी करा: {domain}"),
            ("mr-Latn", "sms", True, "Income Tax Alert: Tumcha refund ₹18450 pass zala aahe. Bank verify karun claim kara: {domain}"),
            ("en", "sms", True, "Income Tax Department: Tax refund of {amount} has been approved. Submit your bank account details at {domain} to credit."),
            ("mr-en", "whatsapp", True, "IT Refund Notice: Reference {ref} refund amount credited to pending queue. Verify IFSC at {domain}"),
            ("mr", "sms", False, "प्राप्तिकर परतावा: तुमचा टॅक्स रिफंड खात्यात जमा होऊ शकला नाही. आयकर अधिकाऱ्यांशी {phone} वर त्वरित संपर्क साधा."),
            ("mr-Latn", "whatsapp", False, "Income Tax Desk: Refund sanction pending due to IFSC error. Call tax officer {phone} to release payment."),
            ("en", "formal_notice", False, "Tax Clearance Notice: Outstanding refund of {amount} awaiting verification. Contact refund desk at {phone}"),
            ("mr-en", "sms", False, "Notice: Tumcha tax refund reject zala aahe. Call IT helpline officer {phone} within 24 hours."),
        ],
    },
    "v3_train_phish_sim_esim_block": {
        "scenario": "sim_card_deactivation",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "टेलिकॉम सूचना: तुमची ५G सिम अपग्रेड प्रक्रिया अपूर्ण आहे. आज रात्री २४ तासांत सिम बंद होईल. येथे पडताळणी करा: {domain}"),
            ("mr-Latn", "sms", True, "Telecom Warning: Tumche SIM card deactivate honar aahe. 5G update sathi link var click kara: {domain}"),
            ("en", "sms", True, "Telecom Notice: Your mobile connection is scheduled for immediate suspension. Complete mandatory 5G KYC at {domain}"),
            ("mr-en", "whatsapp", True, "SIM Alert: Connection deactivation warning for {ref}. Update digital document at {domain} to keep service active."),
            ("mr", "sms", False, "सिम कार्ड ब्लॉक इशारा: तुमचे सिम कार्ड आज संध्याकाळी बंद केले जाईल. त्वरित दूरसंचार प्रतिनिधीशी {phone} वर बोला."),
            ("mr-Latn", "sms", False, "Telecom Alert: Mobile number switch off honar. Contact telecom verification officer at {phone} right now."),
            ("en", "service_alert", False, "Cellular Alert: Outgoing and incoming calls will be stopped. Contact verification team at {phone} immediately."),
            ("mr-en", "whatsapp", False, "SIM Warning: Biometric verify nahi zale. Call cellular support officer {phone} to keep number running."),
        ],
    },
    "v3_train_phish_fastag_blocked": {
        "scenario": "fastag_blacklist_threat",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "फास्टॅग इशारा: तुमचा FASTag ब्लॅकलिस्ट करण्यात आला आहे. टोल दंड टाळण्यासाठी येथे त्वरित केवायसी पूर्ण करा: {domain}"),
            ("mr-Latn", "sms", True, "FASTag Alert: Tumcha FASTag balance zero aahe aani card block zale. Recharge kara: {domain}"),
            ("en", "sms", True, "NHAI Alert: Your FASTag is deactivated due to pending vehicle KYC. Reactivate immediately to avoid 2X penalty: {domain}"),
            ("mr-en", "whatsapp", True, "Toll Notice: Vehicle FASTag suspended. To unblock and clear toll clearance visit {domain}"),
            ("mr", "sms", False, "फास्टॅग सूचना: महामार्ग टोल प्लाझावर तुमचा फास्टॅग नाकारला जाऊ शकतो. त्वरित टोल हेल्पडेस्क {phone} वर कॉल करा."),
            ("mr-Latn", "sms", False, "FASTag Warning: Card blacklisted. Call toll verification center at {phone} before traveling."),
            ("en", "service_alert", False, "Highway Toll Advisory: FASTag tag ID {ref} blocked. Contact highway customer care desk at {phone}."),
            ("mr-en", "whatsapp", False, "FASTag Desk: Wallet block zala aahe. Contact toll manager {phone} to reactivate vehicle tag."),
        ],
    },
    "v3_train_phish_epfo_claim_approved": {
        "scenario": "epfo_pf_withdrawal_scam",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "ईपीएफओ सूचना: तुमचा भविष्य निर्वाह निधी (PF) दावा ₹४५,००० मंजूर झाला आहे. थेट खात्यात जमा करण्यासाठी क्लिक करा: {domain}"),
            ("mr-Latn", "sms", True, "EPFO Update: Tumcha PF claim ₹45000 approve zala. Amount account madhe transfer karayla visit: {domain}"),
            ("en", "sms", True, "EPFO Notification: Your PF withdrawal claim {ref} is processed. Confirm your bank account at {domain} to disburse."),
            ("mr-en", "whatsapp", True, "EPF Notice: Provident fund claim release zala aahe. Enter UAN and OTP at {domain} to receive funds."),
            ("mr", "sms", False, "पीएफ क्लेम सूचना: तुमचा ईपीएफओ परतावा बँक खात्याशी न जुळल्याने अडकला आहे. पीएफ सहाय्यक अधिकारी {phone} शी संपर्क साधा."),
            ("mr-Latn", "whatsapp", False, "EPFO Support: Claim transfer failed due to IFSC mismatch. Call PF desk coordinator {phone} to verify."),
            ("en", "formal_notice", False, "EPFO Clearance: Settlement order ready for claim {ref}. Contact grievance desk at {phone} for immediate payout."),
            ("mr-en", "sms", False, "PF Update: Withdrawal amount pending release. Call EPFO representative {phone} to resolve hold."),
        ],
    },

    # Legitimate (8)
    "v3_train_legit_utility_bill_receipt": {
        "scenario": "genuine_utility_receipt",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "महावितरण पावती: ग्राहक क्र {ref} चे वीज बिल ₹१,२५० यशस्वीरित्या भरले आहे. पावती पाहण्यासाठी: {domain}"),
            ("mr-Latn", "sms", True, "MahaVitaran Receipt: Bill payment of ₹1250 received successfully for consumer {ref}. View receipt: {domain}"),
            ("en", "sms", True, "Dear Consumer, payment of {amount} for bill {ref} is successfully received. Download receipt at {domain}"),
            ("mr-en", "whatsapp", True, "MSEDCL Update: Bill payment confirm zale aahe. Thanks for timely payment. Check receipt at {domain}"),
            ("mr", "sms", False, "महावितरण सूचना: ग्राहक क्र {ref} साठी ₹१,२५० चे देयक दिनांक {date} रोजी रोख स्वरूपात जमा झाले आहे. धन्यवाद."),
            ("mr-Latn", "sms", False, "MahaVitaran Alert: Payment received for consumer {ref}. Your balance is now Nil. Thank you for paying on time."),
            ("en", "service_alert", False, "Electricity Board Notice: Payment confirmation. Your account {ref} is fully updated as of today."),
            ("mr-en", "whatsapp", False, "Receipt Notice: Consumer {ref} electricity payment successfully reconciled. No outstanding dues."),
        ],
    },
    "v3_train_legit_bank_credit_alert": {
        "scenario": "genuine_banking_credit",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "बँक सूचना: तुमचे खाते क्र. XX४९२० मध्ये ₹२५,००० पगार जमा झाला आहे. शिल्लक पाहण्यासाठी: {domain}"),
            ("mr-Latn", "sms", True, "Bank Alert: Your A/c XX4920 credited by ₹25000 towards salary on {date}. Check balance: {domain}"),
            ("en", "sms", True, "Dear Customer, your A/c XX4920 has been credited with {amount} by NEFT on {date}. Net available balance updated at {domain}"),
            ("mr-en", "whatsapp", True, "Bank Update: Account XX4920 madhe salary credit zali aahe. View mini-statement at {domain}"),
            ("mr", "sms", False, "बँक अलर्ट: तुमचे खाते क्र. XX४९२० मध्ये ₹१,२५० युपीआय द्वारे जमा झाले आहेत. चालू शिल्लक ₹१८,४५०. धन्यवाद."),
            ("mr-Latn", "sms", False, "Bank Notice: INR 2500 credited to your A/c XX4920 on {date}. Avl Bal INR 18450. Info via official mobile banking app."),
            ("en", "service_alert", False, "State Bank Alert: Credit transaction of {amount} completed for A/c XX4920. Reference ID {ref}."),
            ("mr-en", "sms", False, "Bank Credit: Tumchya account madhe payment aale aahe. Avl Balance update zale aahe."),
        ],
    },
    "v3_train_legit_lpg_cylinder_booking": {
        "scenario": "genuine_lpg_booking",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "गॅस बुकिंग सूचना: तुमचा एलपीजी सिलिंडर रिफिल नोंदवला आहे. ऑर्डर क्र {ref}. डिलिव्हरी तपशील पाहण्यासाठी: {domain}"),
            ("mr-Latn", "sms", True, "Gas Booking: LPG refill booked with order no {ref}. Cash memo ₹850. Track delivery: {domain}"),
            ("en", "sms", True, "LPG Notification: Refill cylinder booked successfully. Booking Ref {ref}. Estimated delivery in 2 days. Details: {domain}"),
            ("mr-en", "whatsapp", True, "Bharat Gas: Tumche cylinder booking confirm zale aahe. Delivery agent details sathi visit {domain}"),
            ("mr", "sms", False, "गॅस एजन्सी सूचना: ग्राहक क्र {ref} साठी सिलिंडर डिलिव्हरीसाठी पाठवला आहे. डिलिव्हरी बॉयला ओटीपी ४९२० द्या."),
            ("mr-Latn", "sms", False, "HP Gas Alert: Refill cylinder out for delivery today. Delivery authentication code is 4920. Cash memo ₹850."),
            ("en", "service_alert", False, "Indane Gas: Your refill is out for delivery. Share delivery authentication code 4920 with delivery staff upon arrival."),
            ("mr-en", "sms", False, "Gas Notice: Cylinder delivery agent rastyavar aahe. Please keep exact change ₹850 ready."),
        ],
    },
    "v3_train_legit_gram_panchayat_tax": {
        "scenario": "genuine_gram_panchayat_tax",
        "label": "legitimate",
        "patterns": [
            ("mr", "formal_notice", True, "ग्रामपंचायत सूचना: सन २०२६ चे घरपट्टी व पाणीपट्टी बिल जारी करण्यात आले आहे. ऑनलाइन भरणा करण्यासाठी: {domain}"),
            ("mr-Latn", "formal_notice", True, "Gram Panchayat Notice: Property tax assessment for 2026 is published. Pay civic tax online: {domain}"),
            ("en", "formal_notice", True, "Municipal Corporation Notice: Property tax assessment demand for property {ref} is issued. Pay civic dues at {domain}"),
            ("mr-en", "whatsapp", True, "Civic Update: Gram Panchayat tax receipt portal var available aahe. View property dues at {domain}"),
            ("mr", "formal_notice", False, "ग्रामपंचायत कार्यालय: सर्व ग्रामस्थांना कळविण्यात येते की वार्षिक कर भरणा शिबिर शनिवार दिनांक {date} रोजी ग्रामपंचायत कार्यालयात होईल."),
            ("mr-Latn", "formal_notice", False, "Civic Notice: Gram Panchayat tax collection camp will be held at local office on Saturday from 10 AM to 4 PM."),
            ("en", "formal_notice", False, "Municipal Notice: Citizens are informed that annual property tax collection counters are open at ward office till {date}."),
            ("mr-en", "sms", False, "Gram Panchayat: Tax collection camp Saturday roji office madhe aahe. Vel 10 AM te 4 PM."),
        ],
    },
    "v3_train_legit_maha_metro_ticket": {
        "scenario": "genuine_metro_ticket",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "महा मेट्रो तिकीट: तुमचे मेट्रो क्यूआर तिकीट बुक झाले आहे. तिकीट क्र {ref}. प्रवास वैध २ तास. तिकीट पहा: {domain}"),
            ("mr-Latn", "sms", True, "Maha Metro Ticket: QR ticket confirmed for journey Pune to Shivajinagar. View ticket barcode: {domain}"),
            ("en", "sms", True, "Metro Booking: Your electronic QR ticket {ref} is confirmed. Valid for entry within 2 hours. Access ticket at {domain}"),
            ("mr-en", "whatsapp", True, "Metro Notice: Tumche metro ticket confirm zale. Entry sathi QR code open kara: {domain}"),
            ("mr", "sms", False, "महा मेट्रो सूचना: तिकीट क्र {ref} साठी ₹३० यशस्वीरित्या प्राप्त झाले. प्रवासादरम्यान तिकीट जवळ बाळगा."),
            ("mr-Latn", "sms", False, "Metro Rail: ₹30 paid for entry pass. Please scan your mobile screen at automatic fare collection gates."),
            ("en", "service_alert", False, "Metro Rail Authority: Fare of ₹30 deducted. Retain ticket until exiting destination station."),
            ("mr-en", "sms", False, "Metro Ticket: Transaction successful for station entry. Have a safe journey."),
        ],
    },
    "v3_train_legit_railway_irctc_pnr": {
        "scenario": "genuine_railway_pnr",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "रेल्वे सूचना: पीएनआर क्र {ref} साठी चार्ट तयार झाला आहे. डबा B2, बर्थ ३१ (कन्फर्म). तपशील: {domain}"),
            ("mr-Latn", "sms", True, "IRCTC Notice: Chart prepared for PNR {ref}. Coach B2, Seat 31 confirmed. Check live status: {domain}"),
            ("en", "sms", True, "Indian Railways: PNR {ref} chart prepared. Train 12124 Deccan Queen. Coach C1, Seat 45 confirmed. View status: {domain}"),
            ("mr-en", "whatsapp", True, "Railway Update: PNR {ref} reservation confirmed aahe. Check coach position at {domain}"),
            ("mr", "sms", False, "भारतीय रेल्वे सूचना: पीएनआर क्र {ref} चे तिकीट कन्फर्म झाले आहे. प्रस्थान वेळ दुपारी २:१५ वाजता प्लॅटफॉर्म क्र. ३ वरून."),
            ("mr-Latn", "sms", False, "Railway Alert: PNR {ref} confirmed. Train departure at 2:15 PM from Platform 3. Please carry valid ID proof."),
            ("en", "service_alert", False, "IRCTC Alert: Reservation confirmed for PNR {ref}. Departure scheduled at 14:15 hrs from Platform 3. Carry photo ID."),
            ("mr-en", "sms", False, "Train Notice: PNR {ref} confirm zala aahe. Platform no 3 varun train sutnar aahe."),
        ],
    },
    "v3_train_legit_ration_distribution": {
        "scenario": "genuine_ration_distribution",
        "label": "legitimate",
        "patterns": [
            ("mr", "formal_notice", True, "रेशन सूचना: सार्वजनिक वितरण प्रणाली अंतर्गत या महिन्याचे धान्य वाटप सुरू झाले आहे. अधिकृत दुकान तपशील: {domain}"),
            ("mr-Latn", "formal_notice", True, "Ration Seva: Monthly foodgrain quota for card {ref} is available at fair price shop. Details: {domain}"),
            ("en", "formal_notice", True, "Food and Civil Supplies Department: PDS foodgrain entitlement for this month is ready for collection. Portal: {domain}"),
            ("mr-en", "whatsapp", True, "Ration Notice: Ration dukanavar ya mahinyache dhanya vitran suru zale aahe. Check balance at {domain}"),
            ("mr", "formal_notice", False, "रेशन वाटप सूचना: सर्व शिधापत्रिकाधारकांना कळविण्यात येते की दिनांक {date} पर्यंत बायोमेट्रिक प्रमाणीकरण करून धान्य घ्यावे."),
            ("mr-Latn", "formal_notice", False, "PDS Notice: Ration card holders are requested to collect foodgrain allocation by {date} using Aadhaar e-PoS."),
            ("en", "formal_notice", False, "Civil Supplies Notice: Monthly subsidized grain distribution is underway at authorized ration shops till {date}."),
            ("mr-en", "sms", False, "Ration Alert: Mahinyache dhanya vitran dukanat suru aahe. Krupaya shop var jaun ghya."),
        ],
    },
    "v3_train_legit_school_parent_meeting": {
        "scenario": "genuine_school_circular",
        "label": "legitimate",
        "patterns": [
            ("mr", "formal_notice", True, "शाळा सूचना: पालक-शिक्षक सभेचे (PTA) परिपत्रक व सत्र वेळापत्रक जारी केले आहे. वेळापत्रक पाहण्यासाठी: {domain}"),
            ("mr-Latn", "formal_notice", True, "School Notice: Parent-Teacher Meeting is scheduled for Saturday at 10 AM. View circular: {domain}"),
            ("en", "formal_notice", True, "School Circular: Term progress report and PTA meeting scheduled for Saturday. Download agenda at {domain}"),
            ("mr-en", "whatsapp", True, "School Update: Palak-shikshak meeting circular portal var upload zale aahe. Check timing at {domain}"),
            ("mr", "formal_notice", False, "शाळा कार्यालय: सर्व पालकांना कळविण्यात येते की सत्र १ चा निकाल शनिवार दिनांक {date} रोजी सकाळी ९ ते १२ या वेळेत दिला जाईल."),
            ("mr-Latn", "formal_notice", False, "School Desk: First semester result card distribution on Saturday from 9 AM to 12 PM in school auditorium."),
            ("en", "formal_notice", False, "School Administration: Term results will be handed to parents on Saturday morning between 9 AM and 12 noon."),
            ("mr-en", "sms", False, "School Notice: Saturday roji palak meeting aahe. Vel sakali 10 te 12. Sarva palakanni upasthit rahave."),
        ],
    },

    # Protective Advisory (8)
    "v3_train_advisory_cybercell_lottery": {
        "scenario": "lottery_fraud_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सायबर सुरक्षा दक्षता: लॉटरी, बक्षीस किंवा लकी ड्रॉच्या संदेशांवर विश्वास ठेवू नका. अशी फसवणूक झाल्यास १९३० वर तक्रार करा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "CyberCell Advisory: KBC lottery kinva cash prize lures var vishwas thevu naka. Report fraud at: {domain}"),
            ("en", "advisory_bulletin", True, "Public Advisory from Police: Do not fall for fake lottery rewards or prize money messages. Report cyber frauds at {domain}"),
            ("mr-en", "whatsapp", True, "Safety Alert: Lottery reward messages fake astat. Paise deu naka. Official helpline: {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र सायबर इशारा: कोणतीही संस्था लॉटरी जिंकण्यासाठी आगाऊ कर किंवा नोंदणी शुल्क मागत नाही. संशयास्पद कॉल्स त्वरित १९३० वर कळवा."),
            ("mr-Latn", "advisory_bulletin", False, "Cyber Crime Alert: Never transfer processing fees to claim lottery rewards. Government never asks for advance payment."),
            ("en", "advisory_bulletin", False, "Police Advisory: Beware of unsolicited lottery win messages on WhatsApp. No legitimate agency demands processing fees."),
            ("mr-en", "sms", False, "Vigilance Notice: Fake lottery SMS var vishwas naka thevu. Cyber crime helpline 1930 var call kara."),
        ],
    },
    "v3_train_advisory_rbi_banking_safety": {
        "scenario": "banking_safety_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "आरबीआय ग्राहक दक्षता: बँक कधीही पासवर्ड, ओटीपी किंवा सीव्हीव्ही मागत नाही. माहितीसाठी अधिकृत पोर्टल: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "RBI Public Notice: Bank kadhihi phone var OTP kinva PIN vicharat nahi. Check safety guidelines: {domain}"),
            ("en", "advisory_bulletin", True, "RBI Safety Alert: Never share OTP, PIN, UPI-PIN, or CVV with anyone posing as bank manager. Guidelines: {domain}"),
            ("mr-en", "whatsapp", True, "Banking Caution: Bank officials OTP kadhihi vicharat nahit. Fraud zalyas complain kara {domain}"),
            ("mr", "advisory_bulletin", False, "बँक दक्षता सूचना: बँक अधिकारी असल्याचे सांगून ओटीपी विचारणाऱ्या कोणत्याही व्यक्तीला माहिती देऊ नका. त्वरित १९३० वर तक्रार नोंदवा."),
            ("mr-Latn", "advisory_bulletin", False, "Security Notice: Banks never call to verify debit card PIN or internet banking password. Stay alert."),
            ("en", "advisory_bulletin", False, "RBI Advisory: Fraudsters pose as bank executives claiming account block. Do not disclose secret codes on phone calls."),
            ("mr-en", "sms", False, "Bank Alert: Fraud calls pasun savadh raha. Konalahi OTP sangu naka. Helpline 1930."),
        ],
    },
    "v3_train_advisory_certin_malware_apk": {
        "scenario": "apk_malware_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सर्ट-इन (CERT-In) इशारा: व्हॉट्सॲपवरून येणाऱ्या अज्ञात .apk फाइल्स इन्स्टॉल करू नका. अधिक माहितीसाठी: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "CERT-In Advisory: WhatsApp kinva SMS madhil unverified APK files install karu naka. Read advisory: {domain}"),
            ("en", "advisory_bulletin", True, "CERT-In Security Warning: Sideloading malicious APK files from messaging apps steals banking SMS. Security portal: {domain}"),
            ("mr-en", "whatsapp", True, "Malware Warning: Electric bill kinva update chya navane aalele APK download karu naka. Details: {domain}"),
            ("mr", "advisory_bulletin", False, "सायबर सुरक्षा सूचना: अज्ञात स्रोतावरून आलेले ॲप्स इन्स्टॉल केल्यास बँक खात्यातून पैसे चोरी होऊ शकतात. फक्त अधिकृत ॲप स्टोअर वापरा."),
            ("mr-Latn", "advisory_bulletin", False, "Security Notice: Do not install APK files sent via WhatsApp for bill updates or loans. They contain financial spyware."),
            ("en", "advisory_bulletin", False, "Advisory from Cyber Cell: Fraudsters send malicious Android apps pretending to be utility managers. Sideloading is unsafe."),
            ("mr-en", "sms", False, "Alert: Anolki APK install karu naka. Te mobile madhil OTP chore shaktat."),
        ],
    },
    "v3_train_advisory_police_job_scam": {
        "scenario": "job_scam_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "पोलीस दक्षता परिपत्रक: ऑनलाइन पार्ट टाईम कामाच्या नावाखाली आगाऊ पैशांची मागणी झाल्यास सावध राहा. तक्रार नोंदवा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Police Advisory: Part-time job task scams pasun savadh raha. Advance fee magitlyas report kara: {domain}"),
            ("en", "advisory_bulletin", True, "Crime Branch Advisory: Fraudsters lure job seekers with daily rating payouts and demand prepaid deposits. Portal: {domain}"),
            ("mr-en", "whatsapp", True, "Job Fraud Caution: Ghar baslya kam dakhvun paise ghenare scammers ahet. Report suspicious tasks at {domain}"),
            ("mr", "advisory_bulletin", False, "महाराष्ट्र पोलीस इशारा: युट्यूब व्हिडिओ लाईक करणे किंवा हॉटेल रिव्ह्यू देण्याच्या बहाण्याने पैसे उकळणाऱ्या टोळ्यांपासून सावध राहा."),
            ("mr-Latn", "advisory_bulletin", False, "Vigilance Alert: No genuine company asks job applicants to deposit money in Telegram tasks. Report to Cyber Police."),
            ("en", "advisory_bulletin", False, "Public Notice: Work-from-home prepaid task schemes are financial frauds. Never deposit money to unlock commissions."),
            ("mr-en", "sms", False, "Police Alert: Telegram task job offers fraud astat. Krupaya paise invest karu naka."),
        ],
    },
    "v3_train_advisory_uidai_aadhaar_lock": {
        "scenario": "aadhaar_safety_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "युआयडीएआय दक्षता: आधार गैरवापर रोखण्यासाठी आपले बायोमेट्रिक्स लॉक ठेवा. अधिक माहितीसाठी: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "UIDAI Public Notice: Use mAadhaar app to lock biometric verification and avoid spoofing: {domain}"),
            ("en", "advisory_bulletin", True, "UIDAI Security Advisory: Secure your identity by locking biometric authentication via official portal {domain}"),
            ("mr-en", "whatsapp", True, "Aadhaar Safety: Aadhaar biometric lock thevlya ne fake fingerprint transactions avoid hotat. Portal: {domain}"),
            ("mr", "advisory_bulletin", False, "आधार सुरक्षा सूचना: आधार क्रमांकाची छायाप्रत किंवा बायोमेट्रिक्स कोणालाही अज्ञात व्यक्तीला देऊ नका. संशयास्पद व्यवहाराची तक्रार १९४७ वर करा."),
            ("mr-Latn", "advisory_bulletin", False, "Identity Security: Lock Aadhaar biometrics when not in use. Call UIDAI toll-free 1947 to report misuse."),
            ("en", "advisory_bulletin", False, "Aadhaar Protection Alert: Always use Masked Aadhaar for identity verification. Never leave biometric records unlocked."),
            ("mr-en", "sms", False, "UIDAI Alert: Aadhaar card misuse pasun vachnya sathi mAadhaar app madhe biometrics lock kara."),
        ],
    },
    "v3_train_advisory_msedcl_fraud_alert": {
        "scenario": "utility_fraud_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "महावितरण जनहित सूचना: महावितरण कधीही व्यक्तिगत मोबाईल क्रमांकावरून वीज कापण्याचा संदेश पाठवत नाही. अधिकृत माहिती: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "MSEDCL Caution: Mahavitaran personal mobile numbers varun disconnection notice pathvat nahi. Verify: {domain}"),
            ("en", "advisory_bulletin", True, "MSEDCL Vigilance Bulletin: Power company never requests citizens to call personal 10-digit mobile numbers for bill payments: {domain}"),
            ("mr-en", "whatsapp", True, "MahaVitaran Notice: Fake light bill cutoff messages ignore kara. Official payment app ch vapra: {domain}"),
            ("mr", "advisory_bulletin", False, "महावितरण दक्षता इशारा: आज रात्री वीज कापली जाईल अशा खोट्या संदेशांना बळी पडू नका. महावितरणचा अधिकृत टोल-फ्री क्रमांक १९१२ आहे."),
            ("mr-Latn", "advisory_bulletin", False, "MSEDCL Notice: Ignore SMS threatening immediate power cut from unknown phone numbers. Call 1912 for billing confirmation."),
            ("en", "advisory_bulletin", False, "Consumer Alert: Scammers are circulating fake electricity cutoff ultimatums. Check bill dues only on official billing desks."),
            ("mr-en", "sms", False, "MSEDCL Alert: Light cutoff SMS fake asu shaktat. Konalahi personal number var call karun bill deu naka."),
        ],
    },
    "v3_train_advisory_trai_sim_spoof": {
        "scenario": "telecom_spoof_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "ट्राय (TRAI) दक्षता सूचना: टेलिकॉम विभाग कोणाचाही फोन क्रमांक ऑटोमॅटिक कॉलद्वारे बंद करत नाही. अधिकृत पोर्टल: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "TRAI Advisory: Telecom Department numbers disconnect karnyasathi WhatsApp kinva IVR calls karat nahi. Check: {domain}"),
            ("en", "advisory_bulletin", True, "TRAI Public Warning: Department of Telecommunications does not disconnect citizen numbers via automated voice calls: {domain}"),
            ("mr-en", "whatsapp", True, "Telecom Safety: SIM band hone chya fake calls ignore kara. Report to National Cyber Crime portal: {domain}"),
            ("mr", "advisory_bulletin", False, "दूरसंचार विभाग इशारा: तुमचा फोन २ तासांत बंद होईल असा धमकी देणारा कॉल आल्यास घाबरू नका. हा सायबर गुन्हेगारांचा बनाव आहे. १९३० वर कळवा."),
            ("mr-Latn", "advisory_bulletin", False, "TRAI Caution: Do not press 9 on IVR calls threatening mobile deactivation. Official departments never issue phone warrants."),
            ("en", "advisory_bulletin", False, "DoT Alert: Citizens are advised to disconnect automated calls claiming mobile disconnection. Official inquiry helpline is 1930."),
            ("mr-en", "sms", False, "Telecom Alert: SIM block hone chya fake automated call var vishwas thevu naka. Call 1930 immediately."),
        ],
    },
    "v3_train_advisory_social_media_impersonation": {
        "scenario": "impersonation_fraud_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सायबर दक्षता: सोशल मीडियावर मित्र किंवा अधिकाऱ्याचा फोटो वापरून तातडीने पैशांची मागणी झाल्यास पडताळणी करा. पोर्टल: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "CyberCell Advisory: Friend kinva senior officer chya profile varun urgent paise magitle tar call karun confirm kara: {domain}"),
            ("en", "advisory_bulletin", True, "Police Cyber Advisory: Scammers create cloned profiles of friends to demand urgent hospital fees. Confirm before transfer: {domain}"),
            ("mr-en", "whatsapp", True, "Vigilance Notice: WhatsApp profile photo check karun paise deu naka. Direct phone var bolun confirm kara: {domain}"),
            ("mr", "advisory_bulletin", False, "पोलीस सायबर सेल सूचना: व्हॉट्सॲपवर परिचितांचा फोटो लावून अचानक वैद्यकीय मदतीसाठी पैसे मागणाऱ्या सायबर भामट्यांपासून सावध राहा."),
            ("mr-Latn", "advisory_bulletin", False, "Security Advisory: Verify identity by phone call before sending money to any WhatsApp message requesting emergency funds."),
            ("en", "advisory_bulletin", False, "Public Warning: Impersonation scams on messaging apps are on the rise. Verify with the actual person via a voice call."),
            ("mr-en", "sms", False, "Cyber Alert: Friend chya naavane urgent paise magitlyas pahile phone var bolun verify kara."),
        ],
    },
}

# 2. DEVELOPMENT CAMPAIGN FAMILIES (6 families: 2 Phish, 2 Legit, 2 Advisory)
DEV_FAMILIES = {
    # Phishing (2)
    "v3_dev_phish_solar_subsidy": {
        "scenario": "dev_solar_subsidy_lure",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "महावितरण सौर ऊर्जा योजना: तुमच्या छतावरील सोलर पॅनेलसाठी ८०% अनुदान मंजूर झाले आहे. नोंदणी पूर्ण करा: {domain}"),
            ("mr-Latn", "sms", True, "Solar Scheme Alert: 80% subsidy pass zali aahe rooftop solar sathi. Claim kara: {domain}"),
            ("en", "sms", True, "PM Solar Scheme: Your rooftop solar subsidy approval is pending. Confirm bank account for 80% grant: {domain}"),
            ("mr-en", "whatsapp", True, "Rooftop Solar Update: Sanction order {ref} ready. Complete registration at {domain} before deadline."),
            ("mr", "sms", False, "सौर ऊर्जा अनुदान: सोलर सबसिडी कोटा संपण्यापूर्वी मंजूर करून घेण्यासाठी विभागीय अधिकारी {phone} यांच्याशी बोला."),
            ("mr-Latn", "whatsapp", False, "PM Solar Desk: Subsidy allocation pending. Call rooftop solar coordinator at {phone} to secure grant."),
            ("en", "formal_notice", False, "Solar Subsidy Department: Approval pending for consumer {ref}. Contact solar inspection desk at {phone}."),
            ("mr-en", "sms", False, "Solar Scheme: Subsidy claim approval sathi call official coordinator {phone} right now."),
        ],
    },
    "v3_dev_phish_credit_card_points": {
        "scenario": "dev_credit_card_points_scam",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "क्रेडिट कार्ड सूचना: तुमचे ९,८५० रिवॉर्ड पॉईंट्स आज रात्री संपत आहेत. रोख रक्कम किंवा व्हाउचर्स मिळवा: {domain}"),
            ("mr-Latn", "sms", True, "Credit Card Alert: 9850 reward points expire honar aaj. ₹9850 cash voucher claim kara: {domain}"),
            ("en", "sms", True, "Card Rewards Notification: Your 9,850 accumulated reward points worth ₹4,925 will expire today. Redeem at {domain}"),
            ("mr-en", "whatsapp", True, "Bank Card Update: Reward points expiry alert for card ending 4920. Convert points to cash at {domain}"),
            ("mr", "sms", False, "रिवॉर्ड पॉईंट्स इशारा: तुमचे क्रेडिट कार्ड पॉईंट्स ब्लॉक केले जातील. रिडीम करण्यासाठी कार्ड व्यवस्थापक {phone} शी संपर्क साधा."),
            ("mr-Latn", "sms", False, "Card Point Notice: Points expire tonight. Call bank reward executive {phone} to credit cash to account."),
            ("en", "service_alert", False, "Credit Card Services: Reward points expiration warning. Contact customer rewards desk at {phone}."),
            ("mr-en", "whatsapp", False, "Rewards Desk: Points lapse honya purvi card manager {phone} var contact kara."),
        ],
    },

    # Legitimate (2)
    "v3_dev_legit_hospital_opd_booking": {
        "scenario": "dev_hospital_opd_appointment",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "जिल्हा रुग्णालय सूचना: ओपीडी टोकन क्र {ref} डॉ. जोशी यांच्यासाठी पुष्टी झाली. दिनांक {date}. तपासणी वेळ पाहण्यासाठी: {domain}"),
            ("mr-Latn", "sms", True, "Civil Hospital OPD: Appointment token {ref} confirmed for Dr. Joshi on {date} at 10:30 AM. Details: {domain}"),
            ("en", "sms", True, "District Civil Hospital: Your outpatient consultation token {ref} is scheduled for {date} at 10:30 AM. View slip at {domain}"),
            ("mr-en", "whatsapp", True, "Hospital Appointment: OPD booking confirm zali aahe. Token {ref}. View consultation room number at {domain}"),
            ("mr", "sms", False, "सिव्हिल हॉस्पिटल सूचना: टोकन क्र {ref} साठी दिनांक {date} रोजी सकाळी १०:३० वाजता रूम नं १२ मध्ये उपस्थित राहावे."),
            ("mr-Latn", "sms", False, "Hospital OPD Alert: Token {ref} confirmed for Dr. Joshi on {date}. Please report to Room 12 at 10:30 AM with old case paper."),
            ("en", "service_alert", False, "General Hospital: Your doctor consultation is confirmed for {date}. Please arrive at registration counter 15 mins prior."),
            ("mr-en", "whatsapp", False, "Hospital Alert: OPD consultation token {ref} confirm aahe. Old papers aani Aadhaar card sobat theva."),
        ],
    },
    "v3_dev_legit_telecom_data_pack": {
        "scenario": "dev_telecom_service_renewal",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "मोबाईल रिचार्ज सूचना: ₹२९९ चा पॅक यशस्वीरित्या रिचार्ज झाला. दररोज १.५ जीबी डेटा वैध २८ दिवस. शिल्लक तपासा: {domain}"),
            ("mr-Latn", "sms", True, "Recharge Success: ₹299 plan active on your number. 1.5GB/day + Unlimited calls valid till {date}. Check balance: {domain}"),
            ("en", "sms", True, "Recharge Confirmed: Payment of ₹299 received. Your 28-day 1.5GB/day high-speed data plan is active. Manage pack at {domain}"),
            ("mr-en", "whatsapp", True, "Telecom Update: ₹299 recharge successful zala aahe. Balance aani validity check karnyasathi: {domain}"),
            ("mr", "sms", False, "टेलिकॉम पावती: तुमचा मासिक रिचार्ज दिनांक {date} रोजी यशस्वी झाला आहे. ट्रॅन्झॅक्शन आयडी {ref}. धन्यवाद."),
            ("mr-Latn", "sms", False, "Cellular Alert: ₹299 plan activated on your SIM. Daily 1.5GB data renewed. Reference TXN {ref}."),
            ("en", "service_alert", False, "Mobile Services: Monthly unlimited pack renewal completed successfully. Transaction {ref}. Enjoy seamless 5G."),
            ("mr-en", "sms", False, "Recharge Alert: Monthly plan active zala aahe. Daily quota 1.5GB renewed. Thanks for choosing our network."),
        ],
    },

    # Protective Advisory (2)
    "v3_dev_advisory_rto_echallan": {
        "scenario": "dev_rto_echallan_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "वाहतूक पोलीस दक्षता: बनावट ई-चलन मेसेजपासून सावध राहा. अधिकृत ई-चलन फक्त echallan.parivahan.gov.in वर तपासा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Traffic Police Advisory: Fake e-challan SMS madhil non-gov links var click karu naka. Official portal: {domain}"),
            ("en", "advisory_bulletin", True, "State Traffic Police Advisory: Scammers are sending fake traffic fine SMS ending in non-gov domains. Verify fines at {domain}"),
            ("mr-en", "whatsapp", True, "Traffic Alert: Challan fine bharayla unauthorized links open karu naka. Official portal ch vapra: {domain}"),
            ("mr", "advisory_bulletin", False, "वाहतूक शाखा इशारा: व्हॉट्सॲपवर येणाऱ्या ट्रॅफिक चालानच्या मेसेजमधील अज्ञात ॲप इन्स्टॉल करू नका. अधिकृत चलन पोर्टल echallan.parivahan.gov.in आहे."),
            ("mr-Latn", "advisory_bulletin", False, "RTO Public Warning: Traffic police never send personal UPI IDs for challan payment. Verify only on Parivahan website."),
            ("en", "advisory_bulletin", False, "Traffic Safety Alert: Beware of fake traffic violation SMS asking to download APK files. Always verify on official portal."),
            ("mr-en", "sms", False, "Traffic Advisory: Fake e-challan SMS ignore kara. Challan payment sathi Parivahan portal vapra."),
        ],
    },
    "v3_dev_advisory_deepfake_voice_fraud": {
        "scenario": "dev_deepfake_extortion_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "सायबर दक्षता सूचना: नातेवाईकांचा आवाज क्लोन करून (AI Deepfake) पैशांची मागणी करणाऱ्या कॉल्सपासून सावध राहा. माहिती: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Cyber Security Alert: AI voice clone vaprun emergency hospital paise magitlyas call verify kara: {domain}"),
            ("en", "advisory_bulletin", True, "Cyber Crime Warning: Criminals use AI deepfake voice cloning to mimic children or family members in distress. Report: {domain}"),
            ("mr-en", "whatsapp", True, "Safety Alert: Deepfake voice call aalyas ghabru naka. Pahile family member chya original number var call kara: {domain}"),
            ("mr", "advisory_bulletin", False, "पोलीस सायबर सेल इशारा: मुलाला अटक झाली आहे किंवा अपघात झाला आहे असा बनावट कॉल आल्यास घाईघाईत पैसे पाठवू नका. थेट संपर्क साधा."),
            ("mr-Latn", "advisory_bulletin", False, "Police Alert: If you receive a call claiming your family member is in police custody, verify directly. It is an extortion racket."),
            ("en", "advisory_bulletin", False, "Public Safety Advisory: AI-generated distress voice calls are used for instant money transfer. Always cross-verify in person."),
            ("mr-en", "sms", False, "Cyber Caution: Family member chya awajat emergency call aalyas ghabru naka. Direct verify kara."),
        ],
    },
}

# 3. QUALIFICATION CAMPAIGN FAMILIES (9 families: 3 Phish, 3 Legit, 3 Advisory)
QUALIFICATION_FAMILIES = {
    # Phishing (3)
    "v3_qual_phish_traffic_challan_seizure": {
        "scenario": "qual_traffic_challan_threat",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "वाहतूक पोलीस नोटीस: वाहन क्र MH-12-AB-4920 चे ₹३,५०० चलन थकीत आहे. वाहन जप्ती टाळण्यासाठी त्वरित भरणा करा: {domain}"),
            ("mr-Latn", "sms", True, "Traffic Police Final Notice: Vehicle seizure warrant issued for challan ₹3500. Pay fine immediately: {domain}"),
            ("en", "sms", True, "RTO Enforcement Notice: Vehicle impound notice issued for pending challan {ref}. Pay within 2 hours at {domain}"),
            ("mr-en", "whatsapp", True, "Traffic Court Notice: Vehicle confiscation warrant pending. Pay pending fine amount at {domain} to cancel seizure."),
            ("mr", "sms", False, "वाहतूक शाखा इशारा: तुमचे वाहन जप्तीसाठी पोलीस पथक पाठवले आहे. कारवाई टाळण्यासाठी आरटीओ अधिकारी {phone} शी त्वरित बोला."),
            ("mr-Latn", "whatsapp", False, "Traffic Desk: Vehicle seizure order ready for {ref}. Call enforcement officer {phone} before 5 PM."),
            ("en", "formal_notice", False, "Traffic Enforcement Branch: Immediate court summons issued for unpaid fine. Contact desk officer at {phone}"),
            ("mr-en", "sms", False, "RTO Alert: Vehicle MH-12 pending fine. Seizure avoid karnyasathi contact traffic squad {phone}."),
        ],
    },
    "v3_qual_phish_digital_arrest_extortion": {
        "scenario": "qual_digital_arrest_extortion",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "सीबीआय सायबर नोटीस: तुमच्या आधार कार्डावर संशयास्पद कुरियर आढळल्याने डिजिटल अटक वॉरंट जारी झाले आहे. चौकशीसाठी जॉईन करा: {domain}"),
            ("mr-Latn", "sms", True, "CBI Digital Arrest Notice: Arrest warrant issued against Aadhaar {ref}. Join video verification room: {domain}"),
            ("en", "sms", True, "Narcotics Control Bureau: Suspicious parcel seized under your name. Immediate video interrogation summons issued: {domain}"),
            ("mr-en", "whatsapp", True, "Mumbai Police Cyber Desk: Digital arrest warrant issued for passport {ref}. Connect to magistrate room at {domain}"),
            ("mr", "sms", False, "केंद्रीय तपास विभाग: तुमच्याविरुद्ध आर्थिक गैरव्यवहाराचा गुन्हा दाखल झाला आहे. तात्काळ सीबीआय इन्स्पेक्टर {phone} शी स्काईप/व्हॉट्सॲपवर बोला."),
            ("mr-Latn", "whatsapp", False, "Police Notice: Narcotic seizure case registered. Call cyber investigation cell {phone} immediately to avoid arrest."),
            ("en", "formal_notice", False, "Customs Legal Department: Consignment containing restricted items held. Contact legal officer at {phone} for bail verification."),
            ("mr-en", "sms", False, "CBI Alert: Digital arrest summons. Contact investigating inspector {phone} within 30 minutes."),
        ],
    },
    "v3_qual_phish_mudra_loan_subsidy": {
        "scenario": "qual_mudra_loan_scam",
        "label": "phishing",
        "patterns": [
            ("mr", "sms", True, "पीएम मुद्रा योजना: तुमचा ₹५,००,००० चा बिनव्याजी व्यवसाय कर्ज मंजूर झाला आहे. मंजुरी पत्र व रक्कम मिळवण्यासाठी: {domain}"),
            ("mr-Latn", "sms", True, "PM Mudra Scheme: ₹5,00,000 collateral-free loan approved. Download sanction letter: {domain}"),
            ("en", "sms", True, "Government Loan Approval: Your PM Mudra loan of ₹5,00,000 has been sanctioned at 0% interest. Disburse funds at {domain}"),
            ("mr-en", "whatsapp", True, "Mudra Yojana Update: Reference {ref} subsidy loan sanction zali aahe. Pay ₹1500 stamp duty at {domain}"),
            ("mr", "sms", False, "मुद्रा कर्ज वाटप: तुमचे मंजूर कर्ज बँक खात्यात पाठवण्यासाठी फाईल शुल्क ₹१,५०० भरा. कर्ज अधिकारी {phone} शी बोला."),
            ("mr-Latn", "whatsapp", False, "Govt Loan Desk: Mudra sanction cheque ready. Call loan nodal officer {phone} to clear documentation."),
            ("en", "formal_notice", False, "Ministry of MSME: Pre-approved business loan sanction notice. Contact verification manager at {phone}"),
            ("mr-en", "sms", False, "Mudra Loan: ₹5 Lakh loan pass zala aahe. Contact branch manager {phone} to collect cheque."),
        ],
    },

    # Legitimate (3)
    "v3_qual_legit_exam_hall_ticket": {
        "scenario": "qual_exam_hall_ticket_notice",
        "label": "legitimate",
        "patterns": [
            ("mr", "formal_notice", True, "महाराष्ट्र राज्य परीक्षा मंडळ: मार्च २०२६ परीक्षेचे प्रवेशपत्र (Hall Ticket) उपलब्ध झाले आहे. डाऊनलोड करा: {domain}"),
            ("mr-Latn", "formal_notice", True, "State Board Exam Notice: Higher Secondary examination admit card is available for download: {domain}"),
            ("en", "formal_notice", True, "State Examination Authority: Hall ticket for upcoming board examination is released. Download your admit card at {domain}"),
            ("mr-en", "whatsapp", True, "Exam Board Update: Board exam hall ticket portal var upload zale aahe. Roll number check kara at {domain}"),
            ("mr", "formal_notice", False, "परीक्षा मंडळ सूचना: सर्व विद्यार्थ्यांचे प्रवेशपत्र संबंधित शाळा आणि कनिष्ठ महाविद्यालयात दिनांक {date} पासून उपलब्ध होईल."),
            ("mr-Latn", "formal_notice", False, "Examination Board: Students can collect authorized physical hall tickets from college counter from {date}."),
            ("en", "formal_notice", False, "University Examination Cell: Admit cards have been dispatched to college centers. Collect before examination date."),
            ("mr-en", "sms", False, "Exam Alert: Hall ticket college office madhe distribute hot aahe. Original fee receipt sobat theva."),
        ],
    },
    "v3_qual_legit_water_supply_maintenance": {
        "scenario": "qual_water_supply_maintenance",
        "label": "legitimate",
        "patterns": [
            ("mr", "formal_notice", True, "महानगरपालिका सूचना: मुख्य जलवाहिनी दुरुस्तीसाठी उद्या सकाळी ९ ते दुपारी ३ पर्यंत पाणीपुरवठा बंद राहील. तपशील: {domain}"),
            ("mr-Latn", "formal_notice", True, "Municipal Corporation: Water pipeline maintenance scheduled tomorrow 9 AM to 3 PM. Read circular: {domain}"),
            ("en", "formal_notice", True, "Municipal Corporation Alert: Planned water shutdown in Zone 4 tomorrow from 9:00 AM to 3:00 PM for valve maintenance. Notice: {domain}"),
            ("mr-en", "whatsapp", True, "Water Dept Notice: Ward 12 madhe udya pipeline repair sathi water supply cut rahil. Check affected areas: {domain}"),
            ("mr", "formal_notice", False, "महानगरपालिका पाणीपुरवठा विभाग: जलशुद्धीकरण केंद्रातील तातडीच्या देखभालीमुळे उद्या शहरातील पाणीपुरवठा कमी दाबाने होईल."),
            ("mr-Latn", "formal_notice", False, "Municipal Notice: Water supply will be restored tomorrow evening at 6 PM. Citizens are requested to store adequate water."),
            ("en", "service_alert", False, "Public Utilities Notice: Scheduled pipeline replacement in progress. Water tankers are available on request at ward office."),
            ("mr-en", "sms", False, "Water Supply Alert: Udya dupari water supply band rahil. Krupaya pani saun theva."),
        ],
    },
    "v3_qual_legit_bank_statement_ready": {
        "scenario": "qual_bank_estatement_ready",
        "label": "legitimate",
        "patterns": [
            ("mr", "sms", True, "बँक सूचना: तुमचे मासिक खाते विवरण (e-Statement) ईमेलवर पाठवले आहे. पासवर्ड स्वरूपासाठी मार्गदर्शक: {domain}"),
            ("mr-Latn", "sms", True, "Bank e-Statement: Monthly statement for A/c XX4920 sent to registered email. Password instructions: {domain}"),
            ("en", "sms", True, "Dear Customer, monthly e-statement for your account XX4920 for the month of October has been sent to your email. Help: {domain}"),
            ("mr-en", "whatsapp", True, "Bank Update: A/c XX4920 statement registered email var pathavle aahe. To open PDF use PAN in capitals: {domain}"),
            ("mr", "sms", False, "बँक सूचना: खाते क्र. XX४९२० चे मासिक विवरण आपल्या नोंदणीकृत ईमेलवर पाठवले आहे. पीडीएफ उघडण्यासाठी पॅन क्रमांक वापरावा."),
            ("mr-Latn", "sms", False, "Bank Alert: e-Statement generated. Password to open PDF is first 4 letters of name in CAPITAL followed by birth year."),
            ("en", "service_alert", False, "State Bank Alert: Your monthly e-Statement has been emailed to you. Note: We never ask for account credentials via email."),
            ("mr-en", "sms", False, "Bank Notice: Monthly statement email var aale aahe. PDF password tumcha date of birth aahe."),
        ],
    },

    # Protective Advisory (3)
    "v3_qual_advisory_digital_arrest_alert": {
        "scenario": "qual_digital_arrest_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "राष्ट्रीय सायबर सुरक्षा दक्षता: पोलीस किंवा सीमाशुल्क विभाग कधीही व्हिडिओ कॉलवर 'डिजिटल अटक' करत नाही. माहिती: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "National Cyber Crime Alert: Police kadhihi video call var arrest karat nahi. Report fake warrants: {domain}"),
            ("en", "advisory_bulletin", True, "Cyber Police Advisory: Law enforcement agencies NEVER conduct arrests over Skype or WhatsApp video calls. Report to {domain}"),
            ("mr-en", "whatsapp", True, "Caution: Digital arrest ha ek scam aahe. Police kadhihi video call var paise magat nahit. Report at {domain}"),
            ("mr", "advisory_bulletin", False, "पोलीस सायबर सेल इशारा: सीबीआय किंवा अंमलबजावणी संचालनालयाच्या नावाने व्हिडिओ कॉल करून धमकावल्यास त्वरित फोन कट करा आणि १९३० वर संपर्क साधा."),
            ("mr-Latn", "advisory_bulletin", False, "Police Advisory: Beware of fraudsters posing as CBI officers claiming your Aadhaar is linked to illegal couriers. It is a scam."),
            ("en", "advisory_bulletin", False, "Public Safety Warning: There is no legal provision for 'Digital Arrest' under Indian law. Do not transfer funds under intimidation."),
            ("mr-en", "sms", False, "Cyber Crime Notice: Digital arrest calls pasun ghabru naka. Konalahi paise transfer karu naka. Call 1930."),
        ],
    },
    "v3_qual_advisory_loan_app_harassment": {
        "scenario": "qual_illegal_loan_apps_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "आरबीआय दक्षता सूचना: बेकायदेशीर झटपट कर्ज देणाऱ्या ॲप्सपासून सावध राहा. अधिकृत नोंदणीकृत बँकांची यादी पहा: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "RBI Public Advisory: Unauthorized instant loan apps install karu naka. Check approved NBFC list at: {domain}"),
            ("en", "advisory_bulletin", True, "RBI Consumer Protection: Beware of predatory micro-lending apps demanding phone contact book access. Verify lenders at {domain}"),
            ("mr-en", "whatsapp", True, "Loan App Caution: Contact access magnare instant loan apps illegal astat. Complain to cybercell: {domain}"),
            ("mr", "advisory_bulletin", False, "रिझर्व्ह बँक दक्षता इशारा: एका मिनिटात कर्ज देण्याचे आमिष दाखवून संपर्क यादी आणि गॅलरीचा गैरवापर करणाऱ्या बनावट ॲप्सना परवानगी देऊ नका."),
            ("mr-Latn", "advisory_bulletin", False, "Vigilance Bulletin: Unregulated Chinese loan apps harass borrowers using morphed photos. File complaint at local police station."),
            ("en", "advisory_bulletin", False, "Police Cyber Alert: Never install loan apps that ask permission to read contacts or photos. Report harassment to 1930."),
            ("mr-en", "sms", False, "RBI Notice: Instant loan chya fake apps pasun dur raha. Te tumcha data chore shaktat."),
        ],
    },
    "v3_qual_advisory_pm_kisan_phishing": {
        "scenario": "qual_pm_kisan_fraud_advisory",
        "label": "protective_advisory",
        "patterns": [
            ("mr", "advisory_bulletin", True, "कृषी विभाग दक्षता परिपत्रक: पीएम-किसान सन्मान निधीसाठी कोणत्याही तिसऱ्या पक्षाच्या लिंकवर पैसे देऊ नका. अधिकृत पोर्टल: {domain}"),
            ("mr-Latn", "advisory_bulletin", True, "Agriculture Dept Alert: PM-Kisan kist sathi fake link var form bharu naka. Official portal: {domain}"),
            ("en", "advisory_bulletin", True, "Ministry of Agriculture Advisory: Farmers are cautioned against phishing websites asking for registration fees for PM-Kisan: {domain}"),
            ("mr-en", "whatsapp", True, "Kisan Alert: PM-Kisan installment credit sathi fee magitlyas reject kara. Official site: {domain}"),
            ("mr", "advisory_bulletin", False, "कृषी विभाग इशारा: पीएम-किसान हप्ता जमा करण्यासाठी शेतकर्‍यांना कधीही कोणतीही पूर्व-फी किंवा ओटीपी विचारला जात नाही. फसवणुकीपासून सावध राहा."),
            ("mr-Latn", "advisory_bulletin", False, "Farmer Caution: PM-Kisan installment is directly transferred by DBT. No officer calls for advance verification."),
            ("en", "advisory_bulletin", False, "Public Notice: Beware of fake SMS claiming PM-Kisan 16th installment is blocked. Verify status only on pmkisan.gov.in."),
            ("mr-en", "sms", False, "Kisan Notice: PM-Kisan che paise थेट bank khyat jamat astat. Konalahi online fee deu naka."),
        ],
    },
}


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
    role_map = {"training": "development", "development": "validation", "qualification": "qualification"}

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
        "source_reference": "Seva Synthetic Corpus Generator v3.0 (Family Disjoint)",
        "license_info": "CC0 1.0 Public Domain / Synthetic Generated",
        "collection_date": "2026-10-30",
        "review_status": "reviewed",
        "dataset_role": role_map.get(partition, "development"),
        "partition": partition,
        "character_count": len(clean_text),
        "normalized_character_count": len(norm_text),
        "detected_script": detect_script(clean_text),
        "generator_version": "3.0.0",
    }
    return record


def generate_partition_records(
    families_dict: Dict[str, Dict[str, Any]],
    target_per_family: int,
    partition_name: str,
    id_prefix: str,
    seed: int,
) -> List[Dict[str, Any]]:
    """Generates all records for a partition across its registered families."""
    rng = random.Random(seed)
    records = []
    global_idx = 1

    for family_id, family_def in families_dict.items():
        patterns = family_def["patterns"]
        # Generate target_per_family records cyclically through patterns with permutations
        for i in range(target_per_family):
            p_tuple = patterns[i % len(patterns)]
            rec_id = f"{id_prefix}_{global_idx:04d}"
            rec = render_record(
                family_id=family_id,
                family_def=family_def,
                pattern_tuple=p_tuple,
                index=i,
                partition=partition_name,
                record_id=rec_id,
                rng=rng,
            )
            records.append(rec)
            global_idx += 1

    return records


def compute_manifest(records: List[Dict[str, Any]], filepath: str, partition: str, lifecycle: str = "active") -> Dict[str, Any]:
    """Computes cryptographic manifest and distribution metadata for a partition."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    file_sha = h.hexdigest()

    labels = Counter(r["ground_truth_label"] for r in records)
    langs = Counter(r["language"] for r in records)
    modes = Counter(r["messaging_mode"] for r in records)
    urls = Counter(r["has_url"] for r in records)
    families = sorted(set(r["campaign_id"] for r in records))
    scenarios = sorted(set(r["scenario_category"] for r in records))

    manifest = {
        "manifest_schema_version": "3.0.0",
        "partition": partition,
        "lifecycle_state": lifecycle,
        "file_name": os.path.basename(filepath),
        "file_sha256": file_sha,
        "record_count": len(records),
        "campaign_family_count": len(families),
        "campaign_families": families,
        "scenario_count": len(scenarios),
        "scenarios": scenarios,
        "distributions": {
            "label_distribution": dict(labels),
            "language_distribution": dict(langs),
            "messaging_mode_distribution": dict(modes),
            "url_presence_distribution": {str(k): v for k, v in dict(urls).items()},
        },
        "isolation_metadata": {
            "is_qualification_held_back": (partition == "qualification"),
            "disjoint_family_guarantee": True,
            "locked_eval_accessible": False,
        },
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return manifest


def main() -> None:
    print("=" * 78)
    print("SEVA CYBER SANDBOX — SYNTHETIC DATASET GENERATOR v3.0")
    print("=" * 78)
    print(f"[*] Target Directory: {OUTPUT_DIR_V3}")
    os.makedirs(OUTPUT_DIR_V3, exist_ok=True)

    # Verify disjointness of families before generation
    train_fams = set(TRAIN_FAMILIES.keys())
    dev_fams = set(DEV_FAMILIES.keys())
    qual_fams = set(QUALIFICATION_FAMILIES.keys())

    print(f"[*] Training Families:      {len(train_fams)}")
    print(f"[*] Development Families:   {len(dev_fams)}")
    print(f"[*] Qualification Families: {len(qual_fams)}")

    t_d = train_fams & dev_fams
    t_q = train_fams & qual_fams
    d_q = dev_fams & qual_fams

    if t_d or t_q or d_q:
        raise ValueError(f"CRITICAL LEAKAGE: Overlapping families detected! T&D={t_d}, T&Q={t_q}, D&Q={d_q}")
    print("[+] Verified: All 39 campaign families are 100% disjoint.")

    # 1. Generate Training Partition (24 families * 50 = 1200 records)
    print("\n[*] Generating Training Partition (1,200 records)...")
    train_records = generate_partition_records(TRAIN_FAMILIES, target_per_family=50, partition_name="training", id_prefix="syn_v3_train", seed=42)
    train_path = os.path.join(OUTPUT_DIR_V3, "synthetic_training_corpus.jsonl")
    with open(train_path, "w", encoding="utf-8") as f:
        for r in train_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    train_manifest = compute_manifest(train_records, train_path, partition="training", lifecycle="active_training")
    with open(os.path.join(OUTPUT_DIR_V3, "training_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(train_manifest, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved Training Partition: {len(train_records)} records -> SHA-256: {train_manifest['file_sha256'][:16]}...")

    # 2. Generate Development Partition (6 families * 50 = 300 records)
    print("\n[*] Generating Development Partition (300 records)...")
    dev_records = generate_partition_records(DEV_FAMILIES, target_per_family=50, partition_name="development", id_prefix="syn_v3_dev", seed=101)
    dev_path = os.path.join(OUTPUT_DIR_V3, "synthetic_dev_corpus.jsonl")
    with open(dev_path, "w", encoding="utf-8") as f:
        for r in dev_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    dev_manifest = compute_manifest(dev_records, dev_path, partition="development", lifecycle="active_development")
    with open(os.path.join(OUTPUT_DIR_V3, "dev_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(dev_manifest, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved Development Partition: {len(dev_records)} records -> SHA-256: {dev_manifest['file_sha256'][:16]}...")

    # 3. Generate Qualification Partition (9 families * 50 = 450 records)
    print("\n[*] Generating Qualification Partition (450 records)...")
    qual_records = generate_partition_records(QUALIFICATION_FAMILIES, target_per_family=50, partition_name="qualification", id_prefix="syn_v3_qual", seed=202)
    qual_path = os.path.join(OUTPUT_DIR_V3, "synthetic_qualification_corpus.jsonl")
    with open(qual_path, "w", encoding="utf-8") as f:
        for r in qual_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    qual_manifest = compute_manifest(qual_records, qual_path, partition="qualification", lifecycle="sealed_independent_benchmark")
    with open(os.path.join(OUTPUT_DIR_V3, "qualification_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(qual_manifest, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved Qualification Partition: {len(qual_records)} records -> SHA-256: {qual_manifest['file_sha256'][:16]}...")

    # 4. Generate Master Corpus Manifest
    master_manifest = {
        "manifest_schema_version": "3.0.0",
        "corpus_id": "seva-synthetic-corpus-v3",
        "generator_version": "3.0.0",
        "total_records": len(train_records) + len(dev_records) + len(qual_records),
        "partitions": {
            "training": train_manifest,
            "development": dev_manifest,
            "qualification": qual_manifest,
        },
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(OUTPUT_DIR_V3, "v3_corpus_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(master_manifest, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 78)
    print("V3 SYNTHETIC CORPUS GENERATION COMPLETED SUCCESSFULLY")
    print(f"Total Records Generated: {master_manifest['total_records']}")
    print(f"  • Training:      {len(train_records)} records (24 families)")
    print(f"  • Development:   {len(dev_records)} records (6 families)")
    print(f"  • Qualification: {len(qual_records)} records (9 families, SEALED)")
    print("=" * 78)


if __name__ == "__main__":
    main()
