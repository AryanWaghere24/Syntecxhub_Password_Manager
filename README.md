<div align="center">

```
           ██████╗ ██╗  ██╗██╗  ██╗███████╗██╗   ██╗
          ██╔═████╗╚██╗██╔╝██║ ██╔╝██╔════╝╚██╗ ██╔╝
          ██║██╔██║ ╚███╔╝ █████╔╝ █████╗   ╚████╔╝
          ████╔╝██║ ██╔██╗ ██╔═██╗ ██╔══╝    ╚██╔╝
          ╚██████╔╝██╔╝ ██╗██║  ██╗███████╗   ██║
           ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝
```

### 🔐 AES-256-GCM Encrypted Local Password Manager

*Cryptography-first. Zero cloud. Entirely yours.*

![Python](https://img.shields.io/badge/Python-3.10+-cyan?style=for-the-badge&logo=python&logoColor=white)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-green?style=for-the-badge&logo=shield&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-purple?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

</div>

---

<div align="center">

> **0xKey** is a cryptography-first, offline password manager engineered for those who don't trust the cloud with their secrets. Built on AES-256-GCM encryption and PBKDF2 key derivation, it transforms your master password into an unbreakable vault — stored locally, owned entirely by you. Every credential is encrypted at rest, every action is audit-logged, and every retrieved password auto-wipes from your clipboard in 10 seconds. No servers. No subscriptions. No attack surface. Just pure cryptographic security, living on your machine, under your control. **Because the safest cloud is the one that doesn't exist.**

</div>

---

## ⚡ Why 0xKey?

| Other Password Managers | 0xKey |
|---|---|
| ☁️ Stores your data on their servers | 🖥️ Everything stays on YOUR machine |
| 💳 Paid subscriptions | 🆓 Completely free, forever |
| 🔒 You trust their encryption | 🔍 Open source — verify it yourself |
| 📡 Requires internet | ✈️ Works fully offline |
| 🎯 Big target for hackers | 🫥 Zero attack surface |

---

## 🛡️ Security Architecture

```
Your Master Password
        │
        ▼
┌─────────────────────────────────────┐
│  PBKDF2-HMAC-SHA256                 │
│  600,000 iterations · 32-byte salt  │
│  Slows brute-force by years         │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  AES-256-GCM                        │
│  Authenticated Encryption           │
│  Detects tampering instantly        │
└─────────────────────────────────────┘
        │
        ▼
   vault.enc  ←  Your encrypted vault on disk
```

- 🔑 **New salt on every save** — same content, completely different ciphertext each time
- ⚛️ **Atomic writes** — vault written to `.tmp` then renamed, zero corruption risk
- 🧹 **Clipboard auto-wipe** — password erased from clipboard after 10 seconds
- 📋 **Audit trail** — every action logged with timestamp, event, and success status

---

## ✨ Features

```
  ╔══════════════════════════════════╗
  ║  0xKey  —  MAIN MENU             ║
  ╠══════════════════════════════════╣
  ║  1  Add entry                    ║
  ║  2  List all entries             ║
  ║  3  Search                       ║
  ║  4  Retrieve password            ║
  ║  5  Delete entry                 ║
  ║  6  Generate password            ║
  ║  7  Check strength               ║
  ║  8  Export vault                 ║
  ║  9  Audit log                    ║
  ║  0  Change master password       ║
  ║  q  Quit                         ║
  ╚══════════════════════════════════╝
```

- 🔐 **Master password authentication** with 3-attempt lockout
- 🛡️ **AES-256-GCM vault** — authenticated, tamper-proof encryption
- ➕ **Full CRUD** — add, list, search, retrieve, delete credentials
- 🎲 **Cryptographic password generator** — powered by OS-level randomness
- 💪 **Strength checker** — NIST-based scoring with actionable tips
- 📋 **Clipboard copy** — auto-wipes after 10 seconds
- 📜 **Audit log** — append-only JSONL trail of every vault operation
- 📤 **Export** — JSON and plain-text formats
- 🔄 **Change master password** — re-encrypts entire vault instantly
- 🎨 **Coloured CLI** — clean, professional terminal interface

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/AryanWaghere24/Syntecxhub_Password_Manager.git

# Navigate into the folder
cd Syntecxhub_Password_Manager

# Install dependencies
pip install -r requirements.txt

# Initialise your vault
python 0xKey.py --init

# Launch 0xKey
python 0xKey.py
```

---

## 🖥️ CLI Flags

```bash
python 0xKey.py --init        # Create a new vault
python 0xKey.py --generate    # Generate a password
python 0xKey.py --check       # Check password strength
python 0xKey.py --audit       # View audit log
python 0xKey.py --version     # Show version
```

---

## 🗂️ Project Structure

```
0xKey/
│
├── 0xKey.py            ← Main application (single file)
├── requirements.txt    ← Dependencies
├── README.md           ← You are here
├── LICENSE             ← MIT License
│
├── data/
│   ├── vault.enc       ← AES-256-GCM encrypted vault
│   └── master.hash     ← Hashed master password
│
├── logs/
│   └── audit.log       ← Append-only audit trail
│
└── exports/            ← Exported vault files
```

---

## 📋 Audit Log Sample

```json
{"timestamp":"2025-08-14T10:22:01Z","event":"UNLOCK_VAULT","detail":"successful","success":true}
{"timestamp":"2025-08-14T10:22:15Z","event":"ADD_ENTRY","detail":"service=GitHub","success":true}
{"timestamp":"2025-08-14T10:22:30Z","event":"GET_PASSWORD","detail":"service=GitHub","success":true}
{"timestamp":"2025-08-14T10:23:01Z","event":"UNLOCK_VAULT","detail":"failed attempt 1","success":false}
```

---

## 📦 Dependencies

| Package | Purpose | Version |
|---|---|---|
| `cryptography` | AES-GCM + PBKDF2 | ≥ 41.0.0 |
| `pyperclip` | Clipboard support | ≥ 1.8.2 |
| `colorama` | Coloured terminal output | ≥ 0.4.6 |

---

## ⚠️ Disclaimer

Exports are **plaintext** — treat exported files like raw passwords and store them securely.
For high-stakes production environments, consider audited tools like
[Bitwarden](https://bitwarden.com) or [KeePassXC](https://keepassxc.org).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**Built with 🔐 by [Aryan Waghere](https://github.com/AryanWaghere24)**

*If you found this useful, drop a ⭐ on the repo — it means a lot!*

</div>
