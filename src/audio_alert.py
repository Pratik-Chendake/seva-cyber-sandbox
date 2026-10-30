"""
Offline Audio Alert & Safe Windows Speech Synthesis Module.

HOW THIS WORKS:
1. Browser WAV Alert (100% Offline, Cross-Platform):
   Uses Python's built-in wave, math, and struct modules to generate a valid 16-bit PCM
   .wav audio stream in RAM. Streamlit renders this in an HTML5 <audio> player that works
   on Windows, macOS, and Linux cloud servers without internet access.
2. Optional Windows Offline TTS (pyttsx3 / SAPI5):
   Runs in an isolated child process (subprocess.run) with an 8-second timeout so Windows COM
   threading issues inside Streamlit never crash the application.
   Also inspects installed Windows SAPI5 voices to report honestly whether a Marathi/Hindi
   voice pack is installed on the laptop.
"""

import io
import math
import re
import struct
import subprocess
import sys
import wave
from typing import Dict, List, Tuple


def generate_alert_wav_bytes(badge_color: str) -> bytes:
    """
    Synthesizes an in-memory 16-bit mono PCM WAV audio tone (22,050 Hz).
    - 'red': Three-pulse caution chime (660 Hz / 520 Hz)
    - 'orange': Two-pulse notice tone (520 Hz)
    - 'green' / other: Single soft confirmation chime (440 Hz)
    """
    color = str(badge_color or "green").strip().lower()
    sample_rate = 22050
    duration_sec = 1.2 if color in ("red", "orange") else 0.6
    num_samples = int(sample_rate * duration_sec)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)

        frames = bytearray()
        for i in range(num_samples):
            t = i / sample_rate
            if color == "red":
                freq = 660.0 if int(t * 4) % 2 == 0 else 520.0
                amplitude = 0.35
            elif color == "orange":
                freq = 520.0 if int(t * 3) % 2 == 0 else 0.0
                amplitude = 0.30
            else:
                freq = 440.0
                amplitude = 0.20 * max(0.0, (duration_sec - t) / duration_sec)

            sample_val = int(32767.0 * amplitude * math.sin(2.0 * math.pi * freq * t))
            frames.extend(struct.pack("<h", sample_val))

        wav_file.writeframes(bytes(frames))

    return buf.getvalue()


def get_spoken_script(badge_color: str, analysis_type: str) -> Tuple[str, str]:
    """
    Returns (spoken_english_script, written_marathi_script) proportionate to the risk level.
    """
    if badge_color == "red":
        spoken_en = (
            f"Caution. {analysis_type} detected high-risk warning signs. "
            "Do not install this file, click links, or share any O T P or U P I PIN. "
            "Please review the Marathi and English safety explanation on screen."
        )
        written_mr = (
            "ध्वनी सूचना (मराठी अर्थ): सावधान! या तपासणीमध्ये धोक्याचे संकेत आढळले आहेत. "
            "कोणतीही अनोळखी .apk फाईल इन्स्टॉल करू नका आणि तुमचा OTP किंवा UPI PIN कोणालाही सांगू नका."
        )
    elif badge_color == "orange":
        spoken_en = (
            f"Notice. {analysis_type} found moderate warning indicators. "
            "Please verify this request independently through an official office or website before acting."
        )
        written_mr = (
            "ध्वनी सूचना (मराठी अर्थ): या मेसेज किंवा फाईलमध्ये काही संशयास्पद बाबी आहेत. "
            "अधिकृत कार्यालयातून खात्री केल्याशिवाय पुढील कृती करू नका."
        )
    else:
        spoken_en = (
            f"Analysis complete. No strong risk indicators were detected by {analysis_type}, "
            "but always remain cautious with unexpected files or payment requests."
        )
        written_mr = (
            "ध्वनी सूचना (मराठी अर्थ): तपासणी पूर्ण झाली. यात ठळक धोक्याचे संकेत आढळले नाहीत, तरीही नेहमी सावधगिरी बाळगा."
        )
    return spoken_en, written_mr


def inspect_installed_tts_voices() -> Dict[str, object]:
    """
    Checks installed offline TTS voices in a safe subprocess and reports whether a Marathi/Hindi
    voice is installed on the host machine.
    """
    probe_code = (
        "import json, pyttsx3; e = pyttsx3.init(); "
        "v = [{'name': x.name, 'id': x.id} for x in e.getProperty('voices')]; "
        "print(json.dumps(v))"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", probe_code],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return {
                "tts_available": False,
                "has_marathi_or_hindi_voice": False,
                "voices": [],
            }
        import json

        voices: List[Dict[str, str]] = json.loads(proc.stdout.strip().splitlines()[-1])
        has_indic = any(
            any(k in (v.get("name", "") + v.get("id", "")).lower() for k in ("marathi", "hindi", "mr-in", "hi-in", "hemant", "kalpana", "aarohi"))
            for v in voices
        )
        return {
            "tts_available": True,
            "has_marathi_or_hindi_voice": has_indic,
            "voices": [v.get("name", "Unknown Voice") for v in voices],
        }
    except Exception:
        return {
            "tts_available": False,
            "has_marathi_or_hindi_voice": False,
            "voices": [],
        }


def speak_offline_windows_tts(text_to_speak: str) -> Tuple[bool, str]:
    """
    Speaks text_to_speak aloud using Windows offline SAPI5 (pyttsx3) in a separate subprocess.
    Never crashes the calling Streamlit thread even if audio hardware or drivers are unavailable.
    """
    safe_text = re.sub(r"[^a-zA-Z0-9\s.,!?-]", " ", str(text_to_speak or "Alert."))[:300].strip() or "Alert."
    tts_script = (
        "import sys, pyttsx3; "
        "engine = pyttsx3.init(); "
        "engine.setProperty('rate', 165); "
        "engine.say(sys.argv[1]); "
        "engine.runAndWait(); "
        "engine.stop()"
    )
    try:
        proc = subprocess.run(
            [sys.executable, "-c", tts_script, safe_text],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if proc.returncode == 0:
            return (
                True,
                "Spoken audio alert played via local Windows offline voice synthesizer (SAPI5).",
            )
        err_snippet = (proc.stderr or "").strip().splitlines()[-1:] or ["Unknown driver error"]
        return (
            False,
            f"Local offline TTS driver unavailable ({err_snippet[0]}). Please use the embedded browser WAV player above.",
        )
    except Exception as exc:
        return (
            False,
            f"Offline voice synthesizer timed out or is unsupported on this host ({exc}). Please use the embedded WAV player above.",
        )