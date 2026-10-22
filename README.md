# ScamShield 🛡️

ScamShield is a local-first scam-message checker built with Streamlit. It combines rule-based signals with an Ollama language model to help explain whether a message looks safe, suspicious, or like a scam.

## Features

- Check pasted message text and uploaded screenshots.
- Combine quick rule-based indicators with an AI-assisted analysis.
- Display a risk score, warning signs, and suggested next steps.
- Explain results in English, Hindi, or Marathi.
- Keep message analysis on your device when using the local Ollama setup.

> **Important:** ScamShield is an aid, not a guarantee. A “safe” result does not prove a message is legitimate. Never share passwords, OTPs, payment details, or other sensitive information based only on this tool's result.

## Requirements

- Python 3.10 or newer
- [Ollama](https://ollama.com/) installed and running
- The model configured in `analyzer.py` pulled into Ollama
- Dependencies from `requirements.txt`

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/JeevAnand313/ScamShield.git
cd ScamShield
```

### 2. Create and activate a virtual environment

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Start Ollama and download the model

Install Ollama from the official website, then check `analyzer.py` for the exact model name used by this project. Pull that model before launching the app:

```bash
ollama pull MODEL_NAME
```

Replace `MODEL_NAME` with the model name configured in `analyzer.py`. Make sure the Ollama service is running.

### 5. Run ScamShield

```bash
python -m streamlit run app.py
```

Streamlit will print a local URL to open in your browser.

## Project layout

- `app.py` — Streamlit interface and result display
- `analyzer.py` — AI/model analysis
- `rules.py` — rule-based warning signals
- `extras.py` — history and sharing helpers
- `i18n.py` — translated interface text
- `test_samples.py` — sample/test inputs

## Troubleshooting

- **Ollama connection/model errors:** Start Ollama and confirm the model name in `analyzer.py` matches a model available locally.
- **Missing Python packages:** Activate the virtual environment and rerun `python -m pip install -r requirements.txt`.
- **Python command not found:** On macOS/Linux, try `python3` instead of `python`.

## Privacy

The app is designed for local analysis with Ollama. Avoid entering real personal or financial information into test messages. Review any future integrations before assuming that all data remains local.
