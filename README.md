# Seva Cyber Sandbox: Malicious APK & Vernacular Phishing Detector for WhatsApp

**Hackathon:** Seva First Innovation Challenge 2026 (Maharashtra Zone)  
**Sub-Theme:** Responsible AI, Deepfake Detection, Cyber Resilience and Digital Trust

## Quick Start (Windows PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python create_sample_apks.py
python -m pytest -v
python -m streamlit run app.py