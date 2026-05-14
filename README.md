# 🔐 0xKey — Password Manager

A fully local CLI password manager built in Python.
Credentials are stored encrypted using **AES-256-GCM**.
No cloud. No tracking. No nonsense.

---

## ✨ Features

| Feature | Detail |
|---|---|
| **Master password** | PBKDF2-HMAC-SHA256 key derivation (600 000 rounds) |
| **AES-256-GCM encryption** | Authenticated encryption — detects tampering |
| **Add / List / Search / Get / Delete** | Full credential CRUD |
| **Password generator** | Cryptographically secure |
| **Password strength checker** | Scoring with actionable tips |
| **Clipboard copy** | Auto-wipes after 10 seconds |
| **Audit log** | Append-only JSONL log of every operation |
| **Export** | JSON and plain-text formats |
| **Change master password** | Re-encrypts vault with new key |
| **Coloured CLI** | Clean terminal UI |

---

## 📦 Setup

### Requirements
- Python 3.10+
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

### Initialise your vault

```bash
python 0xKey.py --init
```

---

## 🚀 Usage

### Start

```bash
python 0xKey.py
```

```
  ╔══════════════════════════════════╗
  ║  0xKey  —  MAIN MENU            ║
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

### CLI flags

```bash
python 0xKey.py --init        # Create new vault
python 0xKey.py --generate    # Generate a password
python 0xKey.py --check       # Check password strength
python 0xKey.py --audit       # View audit log
python 0xKey.py --version     # Show version
```

---

## 🗂 Project Structure

```
0xKey/
│
├── 0xKey.py            # Main application
├── requirements.txt    # Dependencies
├── README.md           # This file
├── LICENSE             # MIT License
│
├── data/
│   ├── vault.enc       # Encrypted vault (auto-created)
│   └── master.hash     # Master password hash (auto-created)
│
├── logs/
│   └── audit.log       # Audit trail (auto-created)
│
└── exports/            # Export output folder
```

---

## 🔒 Security Design

```
Master Password
      │
      ▼
PBKDF2-HMAC-SHA256 (600 000 iterations, 32-byte random salt)
      │
      ▼
256-bit AES Key
      │
      ▼
AES-256-GCM (12-byte nonce, authenticated encryption)
      │
      ▼
Disk: [32-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
```

- **New salt on every save** — identical content produces different ciphertext every time
- **Atomic writes** — vault written to `.tmp` then renamed, no corruption on crash
- **Exports are plaintext** — treat them like raw passwords, store carefully

---

## 📋 Audit Log Format

```json
{"timestamp":"2025-08-14T10:22:01Z","event":"UNLOCK_VAULT","detail":"successful","success":true,"pid":12345}
{"timestamp":"2025-08-14T10:22:15Z","event":"ADD_ENTRY","detail":"service=GitHub","success":true,"pid":12345}
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `cryptography` | AES-GCM + PBKDF2 |
| `pyperclip` | Clipboard support |
| `colorama` | Coloured terminal output |

---

## ⚠ Disclaimer

This tool is for educational and personal use.
For production use with sensitive credentials, consider audited tools like
[Bitwarden](https://bitwarden.com) or [KeePassXC](https://keepassxc.org).
