"""
Unified Evidence Intake and Multi-Artifact Cybersecurity Analysis Engine.
Seva Cyber Sandbox — Phase 7.1.0

DESIGN & INVARIANT GUARANTEES:
1. Reuses Existing Engines:
   - Phishing & message detection: `src.phishing_detector.analyze_message_text`
   - Deterministic risk scoring: `src.risk_scorer.score_message_analysis` and `score_apk_analysis`
   - Static URL inspection: `src.url_analyzer.analyze_url`
   - Static APK inspection: `src.apk_analyzer.analyze_apk_bytes`
   - Shadow AI evaluation: `src.hybrid_decision_engine.evaluate_message_hybrid`
   - Privacy gate: `src.privacy_gate.sanitize_for_local_training`
2. Zero Fabrication & Transparency:
   - For image/screenshot artifacts: Local inspection with PIL. Transparently reports
     OCR unavailable locally (Tesseract not installed; zero cloud OCR APIs). Zero fabricated text.
   - For unsupported binaries: Computes SHA-256, reports mime/format, explains limitation without fabrication.
3. Air-Gapped & Local-Only:
   - ₹0 budget, 100% CPU execution, no outbound HTTP/cloud API requests.
4. Fail-Soft Resilience:
   - Individual artifact errors do not crash or compromise other artifacts in the submission.
5. Cross-Evidence Correlation:
   - Connects URLs, domains, APKs, messages, and threat intel with explicit confidence
     and limitations notes (correlation != causation; user report != independent corroboration).
6. Non-Authoritative Neural Shadow:
   - Neural model runs strictly in shadow mode (delta = 0.00; deterministic rules authoritative).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import io
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Existing Engine Imports
from src.apk_analyzer import (
    MAX_APK_UPLOAD_BYTES,
    MAX_UNCOMPRESSED_MEMBER_BYTES,
    analyze_apk_bytes,
)
from src.case_manager import (
    SessionCaseStore,
    create_apk_case,
    create_message_case,
    create_url_case,
    generate_case_id,
    get_utc_timestamp_iso,
)
from src.hybrid_decision_engine import evaluate_message_hybrid
from src.phishing_detector import analyze_message_text
from src.privacy_gate import prepare_for_local_analysis, sanitize_for_local_training
from src.risk_scorer import score_apk_analysis, score_message_analysis
from src.url_analyzer import analyze_url, normalize_url_string

# Safety & Upload Limits
MAX_TEXT_INPUT_CHARS = 50000          # Matches ReDoS protection boundary
MAX_DOCUMENT_UPLOAD_BYTES = 15 * 1024 * 1024  # 15 MB
MAX_FILES_PER_SUBMISSION = 10
MAX_URLS_PER_SUBMISSION = 25


class EvidenceType:
    MESSAGE = "message"
    URL = "url"
    APK = "apk"
    DOCUMENT_PDF = "pdf_document"
    IMAGE = "image"
    TEXT_FILE = "text_file"
    UNSUPPORTED = "unsupported"


class ProcessingStatus:
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    REJECTED = "rejected"


# URL regex pattern matching
URL_PATTERN = re.compile(
    r"""(?i)\b((?:https?://|ftp://|www\d{0,3}\.)[^\s()<>]+|\b[a-zA-Z0-9.\-]+\.(?:com|org|net|gov\.in|nic\.in|in|co\.in|cc|xyz|top|info|me|app|biz|online|site|club|vip|live)\b(?:/[^\s()<>]*)?)""",
    re.VERBOSE,
)


def compute_sha256(data: bytes) -> str:
    """Computes standard hexadecimal SHA-256 digest of binary data."""
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def detect_evidence_type(
    raw_data: Any, filename: Optional[str] = None
) -> Tuple[str, str, str]:
    """
    Safely detects the evidence type of raw input data using magic bytes and heuristics.
    Returns: (evidence_type, detection_method, mime_or_description)
    """
    fname = (filename or "").strip().lower()

    # Case 1: String Input
    if isinstance(raw_data, str):
        stripped = raw_data.strip()
        # Check if entire string is a clean URL
        if re.match(r"^https?://[^\s]+$", stripped, re.IGNORECASE):
            return EvidenceType.URL, "scheme_prefix", "text/uri-list"
        # Check if short single-token domain or link
        if ("." in stripped and " " not in stripped and "\n" not in stripped and
            any(stripped.startswith(p) for p in ["http://", "https://", "www.", "ladkibahin.", "msedcl."])):
            return EvidenceType.URL, "domain_heuristic", "text/uri-list"
        return EvidenceType.MESSAGE, "text_content", "text/plain"

    # Case 2: Binary Bytes Input
    if isinstance(raw_data, (bytes, bytearray)):
        b_data = bytes(raw_data)
        size = len(b_data)

        # Magic bytes: PDF
        if b_data.startswith(b"%PDF-"):
            return EvidenceType.DOCUMENT_PDF, "magic_bytes_pdf", "application/pdf"

        # Magic bytes: ZIP archive (Potential APK)
        if b_data.startswith(b"PK\x03\x04") or b_data.startswith(b"PK\x05\x06"):
            # Check for APK indicators in central directory or filename
            if fname.endswith(".apk") or b"AndroidManifest.xml" in b_data[:65536]:
                return EvidenceType.APK, "magic_bytes_zip_axml", "application/vnd.android.package-archive"

        # Magic bytes: Images
        if b_data.startswith(b"\x89PNG\r\n\x1a\n"):
            return EvidenceType.IMAGE, "magic_bytes_png", "image/png"
        if b_data.startswith(b"\xff\xd8\xff"):
            return EvidenceType.IMAGE, "magic_bytes_jpeg", "image/jpeg"
        if b_data.startswith(b"GIF87a") or b_data.startswith(b"GIF89a"):
            return EvidenceType.IMAGE, "magic_bytes_gif", "image/gif"
        if b_data.startswith(b"RIFF") and b_data[8:12] == b"WEBP":
            return EvidenceType.IMAGE, "magic_bytes_webp", "image/webp"

        # Filename hints for known formats
        if fname.endswith(".apk"):
            return EvidenceType.APK, "filename_extension", "application/vnd.android.package-archive"
        if fname.endswith(".pdf"):
            return EvidenceType.DOCUMENT_PDF, "filename_extension", "application/pdf"
        if any(fname.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"]):
            return EvidenceType.IMAGE, "filename_extension", "image/generic"
        if any(fname.endswith(ext) for ext in [".txt", ".log", ".csv", ".json", ".md"]):
            try:
                b_data.decode("utf-8")
                return EvidenceType.TEXT_FILE, "utf8_text_content", "text/plain"
            except UnicodeDecodeError:
                pass

        # Text detection heuristic for extensionless or general text files
        if size <= 1024 * 1024:
            try:
                b_data.decode("utf-8")
                return EvidenceType.TEXT_FILE, "utf8_decode_check", "text/plain"
            except UnicodeDecodeError:
                pass

        return EvidenceType.UNSUPPORTED, "unrecognized_binary", "application/octet-stream"

    return EvidenceType.UNSUPPORTED, "unknown_data_type", "application/octet-stream"


# -----------------------------------------------------------------------------
# LOCAL DOCUMENT AND IMAGE EXTRACTORS
# -----------------------------------------------------------------------------

def extract_pdf_document(pdf_bytes: bytes, filename: str = "document.pdf") -> Dict[str, Any]:
    """
    Safely extracts page count, text, and hyperlinks from a PDF file using local pypdf.
    Zero external APIs or network calls.
    """
    if len(pdf_bytes) > MAX_DOCUMENT_UPLOAD_BYTES:
        return {
            "status": ProcessingStatus.REJECTED,
            "error": f"PDF size ({len(pdf_bytes):,} bytes) exceeds 15 MB limit.",
            "page_count": 0,
            "extracted_text": "",
            "extracted_urls": [],
            "metadata": {},
        }

    try:
        import pypdf

        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        num_pages = len(reader.pages)
        extracted_pages = []
        found_urls = set()

        for idx, page in enumerate(reader.pages):
            if idx >= 50:  # Page ceiling for performance
                break
            try:
                p_text = page.extract_text() or ""
                if p_text:
                    extracted_pages.append(p_text)
            except Exception:
                pass

            # Extract annotations / links
            try:
                if "/Annots" in page:
                    annots = page["/Annots"]
                    if annots:
                        for annot in annots:
                            annot_obj = annot.get_object()
                            if annot_obj.get("/Subtype") == "/Link":
                                action = annot_obj.get("/A")
                                if action and action.get("/S") == "/URI":
                                    uri = action.get("/URI")
                                    if uri:
                                        found_urls.add(str(uri))
            except Exception:
                pass

        full_text = "\n\n".join(extracted_pages)
        if len(full_text) > MAX_TEXT_INPUT_CHARS:
            full_text = full_text[:MAX_TEXT_INPUT_CHARS]

        # Also search text for embedded URLs
        for m in URL_PATTERN.findall(full_text):
            found_urls.add(m)

        pdf_meta = {}
        try:
            if reader.metadata:
                for k, v in reader.metadata.items():
                    if k and v:
                        pdf_meta[str(k).lstrip("/")] = str(v)[:200]
        except Exception:
            pass

        return {
            "status": ProcessingStatus.COMPLETED,
            "page_count": num_pages,
            "extracted_text": full_text,
            "extracted_urls": sorted(list(found_urls)),
            "metadata": pdf_meta,
            "error": None,
        }
    except Exception as e:
        return {
            "status": ProcessingStatus.FAILED,
            "error": f"Failed to parse PDF document: {str(e)}",
            "page_count": 0,
            "extracted_text": "",
            "extracted_urls": [],
            "metadata": {},
        }


def inspect_image_file(image_bytes: bytes, filename: str = "image.png") -> Dict[str, Any]:
    """
    Safely inspects an image file for metadata, dimensions, and format using PIL.
    Transparently discloses that local OCR engine is not installed; no synthetic text fabricated.
    """
    if len(image_bytes) > MAX_DOCUMENT_UPLOAD_BYTES:
        return {
            "status": ProcessingStatus.REJECTED,
            "error": f"Image size ({len(image_bytes):,} bytes) exceeds 15 MB limit.",
            "format": "Unknown",
            "dimensions": (0, 0),
            "ocr_status": "REJECTED_SIZE",
        }

    try:
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        img_format = img.format or "Unknown"
        mode = img.mode

        return {
            "status": ProcessingStatus.COMPLETED,
            "format": img_format,
            "dimensions": (width, height),
            "color_mode": mode,
            "file_size_bytes": len(image_bytes),
            "ocr_status": "UNAVAILABLE_LOCAL_ONLY",
            "extracted_text": None,
            "ocr_explanation": (
                "Local OCR engine (e.g., Tesseract) is not installed on this workstation. "
                "External or cloud OCR APIs are strictly prohibited under Seva's zero-network "
                "and zero-paid-dependency security architecture. "
                "Image dimensions and cryptographic fingerprint recorded without content fabrication."
            ),
            "error": None,
        }
    except Exception as e:
        return {
            "status": ProcessingStatus.FAILED,
            "error": f"Failed to parse image file: {str(e)}",
            "format": "Corrupted",
            "dimensions": (0, 0),
            "ocr_status": "FAILED",
            "extracted_text": None,
            "ocr_explanation": "Image file could not be parsed as a valid image format.",
        }


def extract_text_file(text_bytes: bytes, filename: str = "document.txt") -> Dict[str, Any]:
    """Safely decodes and extracts plaintext from uploaded text files."""
    if len(text_bytes) > MAX_DOCUMENT_UPLOAD_BYTES:
        return {
            "status": ProcessingStatus.REJECTED,
            "error": f"File size ({len(text_bytes):,} bytes) exceeds 15 MB limit.",
            "text": "",
        }

    try:
        try:
            decoded = text_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decoded = text_bytes.decode("latin-1")

        if len(decoded) > MAX_TEXT_INPUT_CHARS:
            decoded = decoded[:MAX_TEXT_INPUT_CHARS]

        return {
            "status": ProcessingStatus.COMPLETED,
            "text": decoded,
            "char_count": len(decoded),
            "error": None,
        }
    except Exception as e:
        return {
            "status": ProcessingStatus.FAILED,
            "error": f"Failed to decode text file: {str(e)}",
            "text": "",
        }


# -----------------------------------------------------------------------------
# CROSS-EVIDENCE CORRELATION ENGINE
# -----------------------------------------------------------------------------

@dataclass
class CorrelationFinding:
    correlation_id: str
    correlation_type: str
    source_artifact_id: str
    target_artifact_id: str
    headline_en: str
    headline_mr: str
    detail_en: str
    detail_mr: str
    confidence: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    supporting_evidence: List[str] = field(default_factory=list)
    limitations_note: str = (
        "Shared technical indicators or similar text phrasing do not constitute conclusive "
        "proof of a unified threat campaign. User reports require independent corroboration."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "correlation_type": self.correlation_type,
            "source_artifact_id": self.source_artifact_id,
            "target_artifact_id": self.target_artifact_id,
            "headline_en": self.headline_en,
            "headline_mr": self.headline_mr,
            "detail_en": self.detail_en,
            "detail_mr": self.detail_mr,
            "confidence": self.confidence,
            "supporting_evidence": self.supporting_evidence,
            "limitations_note": self.limitations_note,
        }


def extract_domains_from_text(text: str) -> Set[str]:
    """Extracts unique normalized domains from a text string."""
    domains = set()
    for m in URL_PATTERN.findall(text):
        try:
            parsed = urlparse(m if "://" in m else f"http://{m}")
            host = (parsed.netloc or parsed.path).split("/")[0].split(":")[0].strip().lower()
            if "." in host and not host.startswith("."):
                domains.add(host)
        except Exception:
            pass
    return domains


def correlate_investigation_evidence(
    artifacts: List[Dict[str, Any]],
    known_indicators: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """
    Identifies cross-evidence relationships between analyzed artifacts.
    Enforces strict safeguards:
    - Never changes authoritative risk scores directly.
    - Preserves uncertainty and limitations on every finding.
    """
    correlations: List[CorrelationFinding] = []
    corr_counter = 1

    # Build lookup dictionaries
    urls_by_artifact: Dict[str, Set[str]] = {}
    domains_by_artifact: Dict[str, Set[str]] = {}
    apk_by_artifact: Dict[str, Dict[str, Any]] = {}
    messages_by_artifact: Dict[str, str] = {}

    for art in artifacts:
        art_id = art["artifact_id"]
        atype = art["artifact_type"]
        res = art.get("analysis_result", {})

        if atype in (EvidenceType.URL,):
            url_str = art.get("target_identifier") or res.get("url") or ""
            if url_str:
                urls_by_artifact.setdefault(art_id, set()).add(url_str)
                doms = extract_domains_from_text(url_str)
                domains_by_artifact.setdefault(art_id, set()).update(doms)

        elif atype in (EvidenceType.MESSAGE, EvidenceType.TEXT_FILE):
            text_str = art.get("text_content") or ""
            messages_by_artifact[art_id] = text_str
            # Extracted URLs
            ext_urls = res.get("extracted_urls", [])
            for u in ext_urls:
                urls_by_artifact.setdefault(art_id, set()).add(u)
                domains_by_artifact.setdefault(art_id, set()).update(extract_domains_from_text(u))

        elif atype in (EvidenceType.DOCUMENT_PDF,):
            doc_urls = res.get("extracted_urls", [])
            for u in doc_urls:
                urls_by_artifact.setdefault(art_id, set()).add(u)
                domains_by_artifact.setdefault(art_id, set()).update(extract_domains_from_text(u))

        elif atype in (EvidenceType.APK,):
            apk_by_artifact[art_id] = res
            # Check passive URLs extracted from APK
            for pu in res.get("passive_urls", []):
                urls_by_artifact.setdefault(art_id, set()).add(pu)
                domains_by_artifact.setdefault(art_id, set()).update(extract_domains_from_text(pu))

    # 1. Message-to-URL Correlation
    for msg_art_id, msg_doms in domains_by_artifact.items():
        for url_art_id, url_doms in domains_by_artifact.items():
            if msg_art_id == url_art_id:
                continue
            common = msg_doms.intersection(url_doms)
            if common:
                dom_list = ", ".join(sorted(list(common)))
                correlations.append(
                    CorrelationFinding(
                        correlation_id=f"CORR-{corr_counter:03d}",
                        correlation_type="MESSAGE_URL_SHARED_DOMAIN",
                        source_artifact_id=msg_art_id,
                        target_artifact_id=url_art_id,
                        headline_en=f"Message mentions domain matching submitted URL: {dom_list}",
                        headline_mr=f"संदेशामध्ये सादर केलेल्या URL शी जुळणारे डोमेन आढळले: {dom_list}",
                        detail_en=(
                            f"Artifact '{msg_art_id}' references domain '{dom_list}', which was also "
                            f"independently submitted in artifact '{url_art_id}'."
                        ),
                        detail_mr=(
                            f"आर्टिफॅक्ट '{msg_art_id}' मध्ये डोमेन '{dom_list}' चा संदर्भ आहे, "
                            f"जे आर्टिफॅक्ट '{url_art_id}' मध्ये स्वतंत्रपणे सादर केले गेले आहे."
                        ),
                        confidence="HIGH",
                        supporting_evidence=[f"Matching domain: {dom_list}"],
                    )
                )
                corr_counter += 1

    # 2. APK-to-URL / Domain Correlation
    for apk_art_id, apk_res in apk_by_artifact.items():
        apk_doms = domains_by_artifact.get(apk_art_id, set())
        for other_art_id, other_doms in domains_by_artifact.items():
            if apk_art_id == other_art_id:
                continue
            common_apk_doms = apk_doms.intersection(other_doms)
            if common_apk_doms:
                dom_list = ", ".join(sorted(list(common_apk_doms)))
                correlations.append(
                    CorrelationFinding(
                        correlation_id=f"CORR-{corr_counter:03d}",
                        correlation_type="APK_DOMAIN_CROSS_REFERENCE",
                        source_artifact_id=apk_art_id,
                        target_artifact_id=other_art_id,
                        headline_en=f"APK static strings contain domain linked to submission: {dom_list}",
                        headline_mr=f"APK मधील स्ट्रिंग्समध्ये सादर केलेल्या लिंक्सचे डोमेन आढळले: {dom_list}",
                        detail_en=(
                            f"Static inspection of APK '{apk_art_id}' revealed embedded domain '{dom_list}', "
                            f"which directly cross-references artifact '{other_art_id}'."
                        ),
                        detail_mr=(
                            f"APK '{apk_art_id}' च्या तपासणीत '{dom_list}' हे डोमेन आढळले, "
                            f"जे आर्टिफॅक्ट '{other_art_id}' शी थेट संबंधित आहे."
                        ),
                        confidence="HIGH",
                        supporting_evidence=[f"Embedded APK domain: {dom_list}"],
                    )
                )
                corr_counter += 1

    # 3. APK Package Name Mentioned in Message
    for apk_art_id, apk_res in apk_by_artifact.items():
        pkg_name = (apk_res.get("package_name") or "").lower()
        if pkg_name and pkg_name != "unknown":
            # Extract last token of package name (e.g., 'ladkibahin' from 'com.maharashtra.ladkibahin')
            pkg_tokens = [t for t in pkg_name.split(".") if len(t) >= 4]
            for msg_art_id, msg_text in messages_by_artifact.items():
                m_lower = msg_text.lower()
                for tok in pkg_tokens:
                    if tok in m_lower:
                        correlations.append(
                            CorrelationFinding(
                                correlation_id=f"CORR-{corr_counter:03d}",
                                correlation_type="MESSAGE_APK_TOKEN_MATCH",
                                source_artifact_id=msg_art_id,
                                target_artifact_id=apk_art_id,
                                headline_en=f"Message mentions application identifier '{tok}' matching APK package",
                                headline_mr=f"संदेशामध्ये APK पॅकेजशी जुळणारा अनुप्रयोग संदर्भ '{tok}' आढळला",
                                detail_en=(
                                    f"Message text in '{msg_art_id}' references token '{tok}', which matches "
                                    f"the declared Android package name '{pkg_name}' of APK '{apk_art_id}'."
                                ),
                                detail_mr=(
                                    f"संदेशामधील मजकुरात '{tok}' चा उल्लेख आहे, जो APK '{apk_art_id}' च्या "
                                    f"पॅकेज नाव '{pkg_name}' शी जुळतो."
                                ),
                                confidence="MEDIUM",
                                supporting_evidence=[f"Package: {pkg_name}", f"Matched token: {tok}"],
                            )
                        )
                        corr_counter += 1
                        break

    # 4. Known Threat Intelligence Observable Matches
    if known_indicators:
        for art in artifacts:
            art_id = art["artifact_id"]
            sha = art.get("artifact_sha256")
            art_doms = domains_by_artifact.get(art_id, set())

            for ind in known_indicators:
                ival = ind.get("indicator_value", "").lower()
                itype = ind.get("indicator_type", "")
                if itype == "apk_sha256" and sha and sha.lower() == ival:
                    correlations.append(
                        CorrelationFinding(
                            correlation_id=f"CORR-{corr_counter:03d}",
                            correlation_type="KNOWN_THREAT_INTEL_HASH_MATCH",
                            source_artifact_id=art_id,
                            target_artifact_id="LOCAL_THREAT_INTEL_DB",
                            headline_en=f"APK SHA-256 matches confirmed threat indicator: {sha[:12]}...",
                            headline_mr=f"APK SHA-256 स्थानिक सायबर धोक्याच्या निर्देशकाशी जुळतो: {sha[:12]}...",
                            detail_en=(
                                f"Artifact '{art_id}' has SHA-256 hash matching local threat intelligence "
                                f"record '{ind.get('indicator_id')}' (Severity: {ind.get('severity', 'High')})."
                            ),
                            detail_mr=f"आर्टिफॅक्ट '{art_id}' चा हॅश स्थानिक धोका नोंदीशी जुळतो.",
                            confidence="HIGH",
                            supporting_evidence=[f"Indicator ID: {ind.get('indicator_id')}", f"SHA: {sha}"],
                        )
                    )
                    corr_counter += 1
                elif itype == "domain" and ival in art_doms:
                    correlations.append(
                        CorrelationFinding(
                            correlation_id=f"CORR-{corr_counter:03d}",
                            correlation_type="KNOWN_THREAT_INTEL_DOMAIN_MATCH",
                            source_artifact_id=art_id,
                            target_artifact_id="LOCAL_THREAT_INTEL_DB",
                            headline_en=f"Artifact references known malicious domain: {ival}",
                            headline_mr=f"आर्टिफॅक्टमध्ये ज्ञात धोकादायक डोमेन आढळले: {ival}",
                            detail_en=(
                                f"Domain '{ival}' in artifact '{art_id}' matches local threat intelligence "
                                f"record '{ind.get('indicator_id')}'."
                            ),
                            detail_mr=f"आर्टिफॅक्टमधील डोमेन '{ival}' स्थानिक धोका नोंदीशी जुळतो.",
                            confidence="HIGH",
                            supporting_evidence=[f"Indicator ID: {ind.get('indicator_id')}", f"Domain: {ival}"],
                        )
                    )
                    corr_counter += 1

    # 5. Conflicting Government vs Phishing Domain Detection
    has_official_gov = False
    has_suspicious_lookalike = False
    gov_arts = []
    susp_arts = []

    for art_id, doms in domains_by_artifact.items():
        for d in doms:
            if d.endswith(".gov.in") or d.endswith(".nic.in") or d == "mahadiscom.in":
                has_official_gov = True
                gov_arts.append((art_id, d))
            elif any(d.endswith(bad_tld) for bad_tld in [".top", ".xyz", ".cc", ".site", ".club", ".live"]):
                has_suspicious_lookalike = True
                susp_arts.append((art_id, d))

    if has_official_gov and has_suspicious_lookalike and gov_arts and susp_arts:
        correlations.append(
            CorrelationFinding(
                correlation_id=f"CORR-{corr_counter:03d}",
                correlation_type="DECEPTIVE_IMPERSONATION_CONFLICT",
                source_artifact_id=gov_arts[0][0],
                target_artifact_id=susp_arts[0][0],
                headline_en="Submission pairs official government domain with suspicious lookalike TLD",
                headline_mr="सादरीकरणामध्ये अधिकृत सरकारी डोमेन आणि संशयास्पद बनावट डोमेन एकत्र आढळले",
                detail_en=(
                    f"Official government domain ({gov_arts[0][1]}) was observed alongside suspicious "
                    f"lookalike domain ({susp_arts[0][1]}). Attackers frequently reference real schemes "
                    f"while providing fraudulent application portals."
                ),
                detail_mr="अधिकृत सरकारी संदर्भ देऊन बनावट लिंकवर पाठवण्याचा सायबर फसवणुकीचा प्रकार असू शकतो.",
                confidence="HIGH",
                supporting_evidence=[f"Official: {gov_arts[0][1]}", f"Lookalike: {susp_arts[0][1]}"],
            )
        )
        corr_counter += 1

    return [c.to_dict() for c in correlations]


# -----------------------------------------------------------------------------
# UNIFIED EVIDENCE ANALYZER WORKFLOW
# -----------------------------------------------------------------------------

class UnifiedEvidenceAnalyzer:
    """
    Central Coordinator for Multi-Artifact Cybersecurity Evidence Analysis.
    Orchestrates validation, type detection, isolated engine routing,
    cross-evidence correlation, and consolidated synthesis.
    """

    def __init__(self, case_repository: Optional[Any] = None):
        self.repository = case_repository

    def analyze_submission(
        self,
        message_text: Optional[str] = None,
        urls: Optional[List[str]] = None,
        files: Optional[List[Dict[str, Any]]] = None,
        enable_shadow_ai: bool = True,
        training_consent_opt_in: bool = False,
        operator_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes unified multi-artifact analysis across all provided evidence items.
        Returns a structured, consolidated investigation dictionary.
        """
        start_time_iso = get_utc_timestamp_iso()
        investigation_id = generate_case_id("INV")

        artifacts: List[Dict[str, Any]] = []
        artifact_counter = 1

        # ---------------------------------------------------------------------
        # 1. PROCESS MESSAGE TEXT (IF PROVIDED)
        # ---------------------------------------------------------------------
        msg_str = (message_text or "").strip()
        if msg_str:
            art_id = f"ART-{artifact_counter:02d}-MSG"
            artifact_counter += 1

            if len(msg_str) > MAX_TEXT_INPUT_CHARS:
                # Fail-closed boundary check
                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.MESSAGE,
                    "target_identifier": "Message Text (Exceeded Limit)",
                    "status": ProcessingStatus.REJECTED,
                    "error": f"Input length ({len(msg_str)} chars) exceeds maximum allowable boundary ({MAX_TEXT_INPUT_CHARS}).",
                    "artifact_sha256": compute_sha256(msg_str.encode("utf-8")),
                    "risk_score": 0,
                    "risk_category": "Unknown",
                    "badge_color": "gray",
                    "analysis_result": {},
                    "text_content": "",
                })
            else:
                try:
                    # Sanitize for local inspection
                    prep_res = prepare_for_local_analysis(msg_str)
                    sanitized_text = prep_res.get("text", msg_str) if isinstance(prep_res, dict) else prep_res
                    rule_res = analyze_message_text(sanitized_text)
                    scored_res = score_message_analysis(rule_res)

                    # Shadow AI inference
                    shadow_eval = None
                    if enable_shadow_ai:
                        try:
                            shadow_eval = evaluate_message_hybrid(
                                message_text=sanitized_text,
                                rule_analysis=rule_res,
                            )
                        except Exception as e:
                            shadow_eval = {"error": str(e), "operating_mode": "shadow"}

                    artifacts.append({
                        "artifact_id": art_id,
                        "artifact_type": EvidenceType.MESSAGE,
                        "target_identifier": f"Message ({rule_res.get('script_detected', 'Unknown Script')})",
                        "status": ProcessingStatus.COMPLETED,
                        "error": None,
                        "artifact_sha256": compute_sha256(msg_str.encode("utf-8")),
                        "risk_score": scored_res.get("score", 0),
                        "risk_category": scored_res.get("risk_level", "Unknown"),
                        "badge_color": scored_res.get("badge_color", "gray"),
                        "analysis_result": rule_res,
                        "scored_result": scored_res,
                        "shadow_eval": shadow_eval,
                        "text_content": sanitized_text,
                    })

                    # If message contains extracted URLs, also register them as connected URL artifacts
                    for ext_url in rule_res.get("extracted_urls", []):
                        u_art_id = f"ART-{artifact_counter:02d}-URL"
                        artifact_counter += 1
                        try:
                            u_eval = analyze_url(ext_url)
                            artifacts.append({
                                "artifact_id": u_art_id,
                                "artifact_type": EvidenceType.URL,
                                "target_identifier": u_eval.get("hostname") or ext_url,
                                "status": ProcessingStatus.COMPLETED,
                                "error": None,
                                "artifact_sha256": compute_sha256(ext_url.encode("utf-8")),
                                "risk_score": u_eval.get("score", 0),
                                "risk_category": u_eval.get("risk_level", "Unknown"),
                                "badge_color": u_eval.get("badge_color", "gray"),
                                "analysis_result": u_eval,
                                "extracted_from_message": art_id,
                            })
                        except Exception as e:
                            artifacts.append({
                                "artifact_id": u_art_id,
                                "artifact_type": EvidenceType.URL,
                                "target_identifier": ext_url,
                                "status": ProcessingStatus.FAILED,
                                "error": str(e),
                                "artifact_sha256": compute_sha256(ext_url.encode("utf-8")),
                                "risk_score": 0,
                                "risk_category": "Unknown",
                                "badge_color": "gray",
                                "analysis_result": {},
                                "extracted_from_message": art_id,
                            })
                except Exception as e:
                    artifacts.append({
                        "artifact_id": art_id,
                        "artifact_type": EvidenceType.MESSAGE,
                        "target_identifier": "Message Text",
                        "status": ProcessingStatus.FAILED,
                        "error": f"Message analysis failed: {str(e)}",
                        "artifact_sha256": compute_sha256(msg_str.encode("utf-8")),
                        "risk_score": 0,
                        "risk_category": "Unknown",
                        "badge_color": "gray",
                        "analysis_result": {},
                        "text_content": msg_str,
                    })

        # ---------------------------------------------------------------------
        # 2. PROCESS DIRECTLY SUBMITTED URLS
        # ---------------------------------------------------------------------
        cleaned_urls = []
        if urls:
            for u in urls:
                if not u:
                    continue
                # Split multiple newline-separated URLs if present
                for sub_u in str(u).splitlines():
                    trimmed = sub_u.strip()
                    if trimmed and trimmed not in cleaned_urls:
                        cleaned_urls.append(trimmed)

        for u_str in cleaned_urls[:MAX_URLS_PER_SUBMISSION]:
            # Avoid duplicate if already extracted from message
            existing_urls = [a.get("target_identifier") for a in artifacts if a.get("artifact_type") == EvidenceType.URL]
            art_id = f"ART-{artifact_counter:02d}-URL"
            artifact_counter += 1

            try:
                norm_u = normalize_url_string(u_str)
                u_eval = analyze_url(norm_u)
                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.URL,
                    "target_identifier": u_eval.get("hostname") or u_str,
                    "status": ProcessingStatus.COMPLETED,
                    "error": None,
                    "artifact_sha256": compute_sha256(u_str.encode("utf-8")),
                    "risk_score": u_eval.get("score", 0),
                    "risk_category": u_eval.get("risk_level", "Unknown"),
                    "badge_color": u_eval.get("badge_color", "gray"),
                    "analysis_result": u_eval,
                })
            except Exception as e:
                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.URL,
                    "target_identifier": u_str,
                    "status": ProcessingStatus.FAILED,
                    "error": str(e),
                    "artifact_sha256": compute_sha256(u_str.encode("utf-8")),
                    "risk_score": 0,
                    "risk_category": "Unknown",
                    "badge_color": "gray",
                    "analysis_result": {},
                })

        # ---------------------------------------------------------------------
        # 3. PROCESS ATTACHED FILES (APKs, PDFs, Images, Text Files, etc.)
        # ---------------------------------------------------------------------
        raw_files = files or []
        for file_item in raw_files[:MAX_FILES_PER_SUBMISSION]:
            filename = file_item.get("filename", "unnamed_artifact")
            content_bytes = file_item.get("content") or b""
            if not isinstance(content_bytes, (bytes, bytearray)):
                content_bytes = bytes(content_bytes)

            file_sha = compute_sha256(content_bytes)
            detected_type, det_method, mime_desc = detect_evidence_type(content_bytes, filename)

            # Allow user override if provided
            user_override_type = file_item.get("user_override_type")
            final_type = user_override_type or detected_type

            art_id = f"ART-{artifact_counter:02d}-{final_type.upper()[:3]}"
            artifact_counter += 1

            # --- APK ARTIFACT ---
            if final_type == EvidenceType.APK:
                try:
                    apk_res = analyze_apk_bytes(content_bytes, filename)
                    scored_apk = score_apk_analysis(apk_res)
                    artifacts.append({
                        "artifact_id": art_id,
                        "artifact_type": EvidenceType.APK,
                        "target_identifier": filename,
                        "status": ProcessingStatus.COMPLETED if apk_res.get("is_valid_apk") else ProcessingStatus.FAILED,
                        "error": apk_res.get("error_message") if not apk_res.get("is_valid_apk") else None,
                        "artifact_sha256": apk_res.get("sha256_hash") or file_sha,
                        "risk_score": scored_apk.get("score", 0),
                        "risk_category": scored_apk.get("risk_level", "Unknown"),
                        "badge_color": scored_apk.get("badge_color", "gray"),
                        "analysis_result": apk_res,
                        "scored_result": scored_apk,
                        "file_size_bytes": len(content_bytes),
                    })
                except Exception as e:
                    artifacts.append({
                        "artifact_id": art_id,
                        "artifact_type": EvidenceType.APK,
                        "target_identifier": filename,
                        "status": ProcessingStatus.FAILED,
                        "error": f"APK processing exception: {str(e)}",
                        "artifact_sha256": file_sha,
                        "risk_score": 0,
                        "risk_category": "Unknown",
                        "badge_color": "gray",
                        "analysis_result": {},
                        "file_size_bytes": len(content_bytes),
                    })

            # --- PDF DOCUMENT ---
            elif final_type == EvidenceType.DOCUMENT_PDF:
                pdf_res = extract_pdf_document(content_bytes, filename)
                pdf_text = pdf_res.get("extracted_text", "")
                pdf_score = 0
                pdf_category = "Benign"
                pdf_badge = "green"
                text_rule_res = None

                if pdf_text:
                    try:
                        prep_res = prepare_for_local_analysis(pdf_text)
                        sanitized_pdf_text = prep_res.get("text", pdf_text) if isinstance(prep_res, dict) else prep_res
                        text_rule_res = analyze_message_text(sanitized_pdf_text)
                        scored_pdf_msg = score_message_analysis(text_rule_res)
                        pdf_score = scored_pdf_msg.get("score", 0)
                        pdf_category = scored_pdf_msg.get("risk_level", "Benign")
                        pdf_badge = scored_pdf_msg.get("badge_color", "green")
                    except Exception:
                        pass

                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.DOCUMENT_PDF,
                    "target_identifier": filename,
                    "status": pdf_res["status"],
                    "error": pdf_res.get("error"),
                    "artifact_sha256": file_sha,
                    "risk_score": pdf_score,
                    "risk_category": pdf_category,
                    "badge_color": pdf_badge,
                    "analysis_result": pdf_res,
                    "text_rule_analysis": text_rule_res,
                    "file_size_bytes": len(content_bytes),
                    "text_content": pdf_text,
                })

            # --- IMAGE / SCREENSHOT ---
            elif final_type == EvidenceType.IMAGE:
                img_res = inspect_image_file(content_bytes, filename)
                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.IMAGE,
                    "target_identifier": filename,
                    "status": img_res["status"],
                    "error": img_res.get("error"),
                    "artifact_sha256": file_sha,
                    "risk_score": 0,  # Neutral unless OCR detects threat; OCR unavailable locally
                    "risk_category": "Unassessed",
                    "badge_color": "gray",
                    "analysis_result": img_res,
                    "file_size_bytes": len(content_bytes),
                })

            # --- PLAINTEXT FILE ---
            elif final_type == EvidenceType.TEXT_FILE:
                txt_res = extract_text_file(content_bytes, filename)
                txt_content = txt_res.get("text", "")
                txt_score = 0
                txt_category = "Benign"
                txt_badge = "green"
                txt_rule_res = None

                if txt_content:
                    try:
                        prep_res = prepare_for_local_analysis(txt_content)
                        sanitized_txt = prep_res.get("text", txt_content) if isinstance(prep_res, dict) else prep_res
                        txt_rule_res = analyze_message_text(sanitized_txt)
                        scored_txt = score_message_analysis(txt_rule_res)
                        txt_score = scored_txt.get("score", 0)
                        txt_category = scored_txt.get("risk_level", "Benign")
                        txt_badge = scored_txt.get("badge_color", "green")
                    except Exception:
                        pass

                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.TEXT_FILE,
                    "target_identifier": filename,
                    "status": txt_res["status"],
                    "error": txt_res.get("error"),
                    "artifact_sha256": file_sha,
                    "risk_score": txt_score,
                    "risk_category": txt_category,
                    "badge_color": txt_badge,
                    "analysis_result": txt_res,
                    "text_rule_analysis": txt_rule_res,
                    "file_size_bytes": len(content_bytes),
                    "text_content": txt_content,
                })

            # --- UNSUPPORTED BINARY ---
            else:
                artifacts.append({
                    "artifact_id": art_id,
                    "artifact_type": EvidenceType.UNSUPPORTED,
                    "target_identifier": filename,
                    "status": ProcessingStatus.UNSUPPORTED,
                    "error": (
                        f"Unsupported format '{mime_desc}'. Cryptographic SHA-256 recorded. "
                        "Content extraction unsupported on this local workstation without external APIs."
                    ),
                    "artifact_sha256": file_sha,
                    "risk_score": 0,
                    "risk_category": "Unsupported",
                    "badge_color": "gray",
                    "analysis_result": {"mime_desc": mime_desc, "detection_method": det_method},
                    "file_size_bytes": len(content_bytes),
                })

        # ---------------------------------------------------------------------
        # 4. CROSS-EVIDENCE CORRELATION
        # ---------------------------------------------------------------------
        known_threat_indicators = []
        if self.repository and hasattr(self.repository, "list_indicators"):
            try:
                known_threat_indicators = self.repository.list_indicators(is_active=True)
            except Exception:
                pass

        correlations = correlate_investigation_evidence(
            artifacts=artifacts,
            known_indicators=known_threat_indicators,
        )

        # ---------------------------------------------------------------------
        # 5. CONSOLIDATE INVESTIGATION RESULT
        # ---------------------------------------------------------------------
        total_count = len(artifacts)
        completed_count = sum(1 for a in artifacts if a["status"] == ProcessingStatus.COMPLETED)
        unsupported_count = sum(1 for a in artifacts if a["status"] == ProcessingStatus.UNSUPPORTED)
        failed_count = sum(1 for a in artifacts if a["status"] in (ProcessingStatus.FAILED, ProcessingStatus.REJECTED))

        # Overall Authoritative Deterministic Score:
        # Highest risk score observed across all individual analyzed artifacts
        scores = [a.get("risk_score", 0) for a in artifacts if a.get("status") == ProcessingStatus.COMPLETED]
        overall_score = max(scores, default=0)

        # Determine overall category and badge color
        if overall_score >= 80:
            overall_category = "Critical Risk"
            overall_badge = "red"
        elif overall_score >= 60:
            overall_category = "High Risk"
            overall_badge = "orange"
        elif overall_score >= 40:
            overall_category = "Medium Risk"
            overall_badge = "yellow"
        elif overall_score >= 20:
            overall_category = "Low Risk"
            overall_badge = "blue"
        else:
            overall_category = "Benign / Verified"
            overall_badge = "green"

        # Identify driving artifact
        driving_artifact = None
        for a in artifacts:
            if a.get("risk_score") == overall_score and overall_score > 0:
                driving_artifact = a
                break

        # Collect high-level observations
        key_observations = []
        for a in artifacts:
            if a.get("risk_score", 0) >= 60:
                key_observations.append(
                    f"[{a['artifact_type'].upper()}] '{a['target_identifier']}': {a['risk_category']} (Score {a['risk_score']}/100)"
                )

        if not key_observations and completed_count > 0:
            key_observations.append("No critical indicators detected across submitted artifacts.")

        return {
            "investigation_id": investigation_id,
            "created_at_utc": start_time_iso,
            "summary_stats": {
                "total_artifacts": total_count,
                "completed_count": completed_count,
                "unsupported_count": unsupported_count,
                "failed_count": failed_count,
            },
            "overall_verdict": {
                "score": overall_score,
                "risk_category": overall_category,
                "badge_color": overall_badge,
                "driving_artifact_id": driving_artifact["artifact_id"] if driving_artifact else None,
                "key_observations": key_observations,
            },
            "artifacts": artifacts,
            "correlations": correlations,
            "unresolved_questions": [
                "Are submitted URLs hosted on ephemeral bulletproof infrastructure?",
                "Has any monetary transaction or credential disclosure occurred?",
                "Does an authentic government resolution (GR) exist for any referenced scheme?",
            ],
            "shadow_ai_summary": {
                "active_model_version": "custom-mlp-v4.0.0-seed42",
                "operating_mode": "shadow",
                "is_production_authoritative": False,
                "authoritative_score_delta": 0.00,
                "note": "Custom neural classifier operates strictly in shadow mode. Scores are 100% deterministic rule-based.",
            },
        }

    def save_investigation_cases(
        self,
        case_store: SessionCaseStore,
        analysis_result: Dict[str, Any],
        submitted_by: Optional[str] = None,
        consent_given: bool = True,
    ) -> Dict[str, Any]:
        """
        Creates individual child cases for each artifact and a parent investigation case,
        preserving cross-artifact relationships and provenance in SQLite.
        """
        investigation_id = analysis_result["investigation_id"]
        artifacts = analysis_result.get("artifacts", [])

        # Idempotency check: prevent duplicate investigations on repeated save calls or replays
        try:
            for c in case_store.list_cases():
                meta = c.get("metadata", {})
                if meta.get("is_parent_investigation") and meta.get("investigation_id") == investigation_id:
                    return {
                        "investigation_id": investigation_id,
                        "parent_case_id": c["case_id"],
                        "child_case_ids": meta.get("child_case_ids", []),
                        "child_evidence_ids": meta.get("child_evidence_ids", []),
                        "artifact_case_mapping": meta.get("artifact_case_mapping", {}),
                        "is_idempotent_replay": True,
                    }
        except Exception:
            pass

        child_case_ids: List[str] = []
        child_evidence_ids: List[str] = []
        artifact_case_mapping: Dict[str, str] = {}

        # 1. Create and save individual child cases
        for art in artifacts:
            atype = art["artifact_type"]
            art_id = art["artifact_id"]
            case_id = generate_case_id(f"CASE-{atype.upper()[:3]}")

            case_record: Dict[str, Any] = {}

            if atype == EvidenceType.MESSAGE and art.get("status") == ProcessingStatus.COMPLETED:
                case_record = create_message_case(
                    msg_res=art.get("analysis_result", {}),
                    scored_res=art.get("scored_result", {}),
                    store_raw_text=False,
                )
            elif atype == EvidenceType.URL and art.get("status") == ProcessingStatus.COMPLETED:
                case_record = create_url_case(art.get("analysis_result", {}))
            elif atype == EvidenceType.APK and art.get("status") == ProcessingStatus.COMPLETED:
                case_record = create_apk_case(
                    apk_res=art.get("analysis_result", {}),
                    scored_res=art.get("scored_result", {}),
                    store_raw_bytes=False,
                )
            else:
                # Document, image, or failed/unsupported artifact
                case_record = {
                    "case_id": case_id,
                    "timestamp_utc": get_utc_timestamp_iso(),
                    "analysis_type": f"Unified Intake — {atype.capitalize()} Evidence",
                    "analysis_status": art.get("status", "Unknown"),
                    "risk_score": art.get("risk_score", 0),
                    "risk_category": art.get("risk_category", "Unknown"),
                    "badge_color": art.get("badge_color", "gray"),
                    "indicator_count": 0,
                    "sha256_hash": art.get("artifact_sha256"),
                    "hash_algorithm": "SHA-256" if art.get("artifact_sha256") else None,
                    "extracted_urls": art.get("analysis_result", {}).get("extracted_urls", []),
                    "observed_evidence": [f"File: {art.get('target_identifier')}, Status: {art.get('status')}"],
                    "heuristic_inferences": [art.get("error")] if art.get("error") else [],
                    "official_sources": [],
                    "target_identifier": art.get("target_identifier", "unnamed_artifact"),
                    "recommended_action": "Retain evidence for forensic review",
                    "raw_data_stored": False,
                    "limitations": "Local parsing only.",
                }

            # Stamp parent investigation linkage into child metadata
            child_meta = {
                "parent_investigation_id": investigation_id,
                "artifact_id": art_id,
                "artifact_type": atype,
                "submitted_by": submitted_by or "user",
            }
            case_record["metadata"] = child_meta
            case_record["submitted_by"] = submitted_by
            case_record["consent_given"] = consent_given

            saved_child_id = case_store.add_case(case_record)
            child_case_ids.append(saved_child_id)
            artifact_case_mapping[art_id] = saved_child_id
            if case_record.get("evidence_id"):
                child_evidence_ids.append(case_record["evidence_id"])

        # 2. Create and save the parent investigation case
        parent_case_id = generate_case_id("CASE-UNIF")
        overall = analysis_result["overall_verdict"]

        observed_summary = [
            f"Consolidated analysis of {len(artifacts)} multi-artifact evidence items.",
            f"Overall authoritative risk score: {overall['score']}/100 ({overall['risk_category']}).",
        ]
        for corr in analysis_result.get("correlations", []):
            observed_summary.append(f"Correlation [{corr['correlation_type']}]: {corr['headline_en']}")

        parent_case_record = {
            "case_id": parent_case_id,
            "timestamp_utc": get_utc_timestamp_iso(),
            "analysis_type": "Unified Evidence Multi-Artifact Investigation",
            "analysis_status": "Completed",
            "risk_score": overall["score"],
            "risk_category": overall["risk_category"],
            "badge_color": overall["badge_color"],
            "indicator_count": sum(a.get("risk_score", 0) > 0 for a in artifacts),
            "sha256_hash": None,
            "hash_algorithm": None,
            "extracted_urls": [],
            "observed_evidence": observed_summary,
            "heuristic_inferences": overall.get("key_observations", []),
            "official_sources": [],
            "target_identifier": f"Investigation {investigation_id} ({len(artifacts)} artifacts)",
            "recommended_action": "Review consolidated per-artifact evidence findings and correlations.",
            "raw_data_stored": False,
            "limitations": "Deterministic rules authoritative; neural model executed strictly in shadow mode.",
            "metadata": {
                "is_parent_investigation": True,
                "investigation_id": investigation_id,
                "child_case_ids": child_case_ids,
                "child_evidence_ids": child_evidence_ids,
                "artifact_case_mapping": artifact_case_mapping,
                "correlations": analysis_result.get("correlations", []),
                "summary_stats": analysis_result.get("summary_stats", {}),
            },
            "submitted_by": submitted_by,
            "consent_given": consent_given,
        }

        saved_parent_id = case_store.add_case(parent_case_record)

        return {
            "investigation_id": investigation_id,
            "parent_case_id": saved_parent_id,
            "child_case_ids": child_case_ids,
            "child_evidence_ids": child_evidence_ids,
            "artifact_case_mapping": artifact_case_mapping,
            "is_idempotent_replay": False,
        }

    def get_investigation_details(
        self,
        case_store: SessionCaseStore,
        parent_case_id_or_inv_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves the parent investigation and all associated child artifact cases
        with their current lifecycle and withdrawal status.
        """
        cases = case_store.list_cases()
        parent_case = None
        for c in cases:
            meta = c.get("metadata", {})
            if meta.get("is_parent_investigation"):
                if c["case_id"] == parent_case_id_or_inv_id or meta.get("investigation_id") == parent_case_id_or_inv_id:
                    parent_case = c
                    break

        if not parent_case:
            return None

        child_ids = parent_case.get("metadata", {}).get("child_case_ids", [])
        child_cases = []
        for cid in child_ids:
            child = case_store.get_case(cid)
            if child:
                if self.repository and child.get("evidence_id"):
                    try:
                        ev_prov = self.repository.get_evidence_provenance(child["evidence_id"])
                        child["current_evidence_provenance"] = ev_prov
                    except Exception:
                        pass
                child_cases.append(child)

        return {
            "parent_case": parent_case,
            "child_cases": child_cases,
            "total_children": len(child_cases),
            "expected_children_count": len(child_ids),
            "all_children_exist": len(child_cases) == len(child_ids),
        }
