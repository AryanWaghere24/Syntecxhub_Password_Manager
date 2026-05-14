#!/usr/bin/env python3
"""
0xKey — AES-256-GCM Local Password Manager
"""

import os
import sys
import json
import time
import string
import random
import hashlib
import getpass
import argparse
import threading
import datetime

# ── Third-party ───────────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("❌  Missing dependency: pip install cryptography")

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    sys.exit("❌  Missing dependency: pip install colorama")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(BASE_DIR, "data")
LOG_DIR    = os.path.join(BASE_DIR, "logs")
EXPORT_DIR = os.path.join(BASE_DIR, "exports")

VAULT_FILE  = os.path.join(DATA_DIR, "vault.enc")
MASTER_FILE = os.path.join(DATA_DIR, "master.hash")
AUDIT_FILE  = os.path.join(LOG_DIR,  "audit.log")

for d in (DATA_DIR, LOG_DIR, EXPORT_DIR):
    os.makedirs(d, exist_ok=True)

# ── Constants ─────────────────────────────────────────────────────────────────
PBKDF2_ITERATIONS = 600_000
SALT_SIZE         = 32
NONCE_SIZE        = 12
CLIPBOARD_CLEAR   = 10
APP_VERSION       = "1.0.0"


# ═════════════════════════════════════════════════════════════════════════════
#  COLOUR HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
 ██████╗ ██╗  ██╗██╗  ██╗███████╗██╗   ██╗
██╔═████╗╚██╗██╔╝██║ ██╔╝██╔════╝╚██╗ ██╔╝
██║██╔██║ ╚███╔╝ █████╔╝ █████╗   ╚████╔╝
████╔╝██║ ██╔██╗ ██╔═██╗ ██╔══╝    ╚██╔╝
╚██████╔╝██╔╝ ██╗██║  ██╗███████╗   ██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.GREEN + Style.BRIGHT + f"  0xKey Password Manager  v{APP_VERSION}")
    print(Fore.WHITE + "  AES-256-GCM  •  Local Vault  •  Zero Cloud\n" + Style.RESET_ALL)


def ok(msg: str):   print(Fore.GREEN  + "  ✔  " + Style.RESET_ALL + msg)
def err(msg: str):  print(Fore.RED    + "  ✖  " + Style.RESET_ALL + msg)
def info(msg: str): print(Fore.CYAN   + "  ℹ  " + Style.RESET_ALL + msg)
def warn(msg: str): print(Fore.YELLOW + "  ⚠  " + Style.RESET_ALL + msg)
def hdr(msg: str):  print(Fore.MAGENTA + Style.BRIGHT + f"\n  ╔▸ {msg}" + Style.RESET_ALL)


def table(entries: list[dict]):
    """Pretty-print vault entries as a coloured table."""
    if not entries:
        warn("No entries found.")
        return
    col_w = {"#": 4, "Service": 22, "Username": 22, "URL": 30, "Created": 20}
    header = (
        Fore.MAGENTA + Style.BRIGHT
        + f"  {'#':<{col_w['#']}} {'Service':<{col_w['Service']}} "
          f"{'Username':<{col_w['Username']}} {'URL':<{col_w['URL']}} "
          f"{'Created':<{col_w['Created']}}"
        + Style.RESET_ALL
    )
    separator = Fore.CYAN + "  " + "━" * (sum(col_w.values()) + 4) + Style.RESET_ALL
    print(separator)
    print(header)
    print(separator)
    for i, e in enumerate(entries, 1):
        row = (
            f"  {str(i):<{col_w['#']}} "
            f"{e.get('service','')[:21]:<{col_w['Service']}} "
            f"{e.get('username','')[:21]:<{col_w['Username']}} "
            f"{e.get('url','')[:29]:<{col_w['URL']}} "
            f"{e.get('created','')[:19]:<{col_w['Created']}}"
        )
        print(Fore.WHITE + row + Style.RESET_ALL)
    print(separator)


# ═════════════════════════════════════════════════════════════════════════════
#  CRYPTO ENGINE
# ═════════════════════════════════════════════════════════════════════════════

class CryptoEngine:
    """
    Key derivation : PBKDF2-HMAC-SHA256  (600 000 rounds, 32-byte salt)
    Encryption     : AES-256-GCM         (authenticated, 12-byte nonce)
    Storage layout : [32-byte salt][12-byte nonce][ciphertext+tag]
    """

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    @staticmethod
    def encrypt(plaintext: bytes, password: str) -> bytes:
        salt  = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key   = CryptoEngine.derive_key(password, salt)
        ct    = AESGCM(key).encrypt(nonce, plaintext, None)
        return salt + nonce + ct

    @staticmethod
    def decrypt(blob: bytes, password: str) -> bytes:
        salt, nonce, ct = (
            blob[:SALT_SIZE],
            blob[SALT_SIZE: SALT_SIZE + NONCE_SIZE],
            blob[SALT_SIZE + NONCE_SIZE:],
        )
        key = CryptoEngine.derive_key(password, salt)
        try:
            return AESGCM(key).decrypt(nonce, ct, None)
        except Exception:
            raise ValueError("Decryption failed — wrong master password or corrupted vault.")

    @staticmethod
    def hash_master(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════
#  AUDIT LOGGER
# ═════════════════════════════════════════════════════════════════════════════

class AuditLog:
    """Append-only structured audit log (JSONL format)."""

    @staticmethod
    def write(event: str, detail: str = "", success: bool = True):
        record = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "event":     event,
            "detail":    detail,
            "success":   success,
            "pid":       os.getpid(),
        }
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    @staticmethod
    def tail(n: int = 20) -> list[dict]:
        if not os.path.exists(AUDIT_FILE):
            return []
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        records = []
        for line in lines[-n:]:
            try:
                records.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                pass
        return records


# ═════════════════════════════════════════════════════════════════════════════
#  PASSWORD UTILITIES
# ═════════════════════════════════════════════════════════════════════════════

class PasswordUtils:
    """Password strength analysis and secure generation."""

    STRENGTH_LABELS  = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
    STRENGTH_COLOURS = [Fore.RED, Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.GREEN + Style.BRIGHT]

    @staticmethod
    def strength(password: str) -> tuple[int, str, list[str]]:
        score = 0
        tips  = []

        if len(password) >= 8:
            score += 1
        else:
            tips.append("Use at least 8 characters (12+ recommended).")

        if len(password) >= 12:
            score += 1
        elif len(password) >= 8:
            tips.append("Increase length to 12+ for a stronger password.")

        has_lower  = any(c.islower()  for c in password)
        has_upper  = any(c.isupper()  for c in password)
        has_digit  = any(c.isdigit()  for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        variety = sum([has_lower, has_upper, has_digit, has_symbol])
        if variety >= 3:
            score += 1
        else:
            if not has_upper:  tips.append("Add uppercase letters.")
            if not has_digit:  tips.append("Add digits.")
            if not has_symbol: tips.append("Add special characters (!@#$…).")

        if variety == 4:
            score += 1

        score = min(score, 4)
        return score, PasswordUtils.STRENGTH_LABELS[score], tips

    @staticmethod
    def display_strength(password: str):
        score, label, tips = PasswordUtils.strength(password)
        bar_filled = "█" * (score + 1)
        bar_empty  = "░" * (4 - score)
        colour     = PasswordUtils.STRENGTH_COLOURS[score]
        print(f"\n  Strength: {colour}{label}{Style.RESET_ALL}  "
              f"{colour}{bar_filled}{Fore.WHITE}{bar_empty}{Style.RESET_ALL}")
        for tip in tips:
            warn(tip)

    @staticmethod
    def generate(
        length:  int  = 16,
        upper:   bool = True,
        lower:   bool = True,
        digits:  bool = True,
        symbols: bool = True,
    ) -> str:
        charset    = ""
        guaranteed = []

        if upper:
            charset += string.ascii_uppercase
            guaranteed.append(random.SystemRandom().choice(string.ascii_uppercase))
        if lower:
            charset += string.ascii_lowercase
            guaranteed.append(random.SystemRandom().choice(string.ascii_lowercase))
        if digits:
            charset += string.digits
            guaranteed.append(random.SystemRandom().choice(string.digits))
        if symbols:
            syms = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            charset += syms
            guaranteed.append(random.SystemRandom().choice(syms))

        if not charset:
            raise ValueError("At least one character class must be selected.")

        rng = random.SystemRandom()
        remaining = [rng.choice(charset) for _ in range(length - len(guaranteed))]
        pool = guaranteed + remaining
        rng.shuffle(pool)
        return "".join(pool)


# ═════════════════════════════════════════════════════════════════════════════
#  VAULT
# ═════════════════════════════════════════════════════════════════════════════

class Vault:
    """AES-256-GCM encrypted credential store."""

    def __init__(self, master_password: str):
        self._master = master_password
        self._entries: list[dict] = []
        self._load()

    def _load(self):
        if not os.path.exists(VAULT_FILE):
            self._entries = []
            return
        with open(VAULT_FILE, "rb") as f:
            blob = f.read()
        plaintext     = CryptoEngine.decrypt(blob, self._master)
        self._entries = json.loads(plaintext.decode("utf-8"))

    def _save(self):
        plaintext = json.dumps(self._entries, indent=2).encode("utf-8")
        blob      = CryptoEngine.encrypt(plaintext, self._master)
        tmp_path  = VAULT_FILE + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(blob)
        os.replace(tmp_path, VAULT_FILE)

    def add(self, service: str, username: str, password: str,
            url: str = "", notes: str = "") -> dict:
        entry = {
            "id":       hashlib.sha256(os.urandom(16)).hexdigest()[:12],
            "service":  service.strip(),
            "username": username.strip(),
            "password": password,
            "url":      url.strip(),
            "notes":    notes.strip(),
            "created":  datetime.datetime.utcnow().isoformat(),
            "modified": datetime.datetime.utcnow().isoformat(),
        }
        self._entries.append(entry)
        self._save()
        AuditLog.write("ADD_ENTRY", f"service={service}")
        return entry

    def get_all(self) -> list[dict]:
        return list(self._entries)

    def search(self, query: str) -> list[dict]:
        q = query.lower()
        return [
            e for e in self._entries
            if q in e.get("service",  "").lower()
            or q in e.get("username", "").lower()
            or q in e.get("url",      "").lower()
            or q in e.get("notes",    "").lower()
        ]

    def delete(self, entry_id: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e["id"] != entry_id]
        if len(self._entries) < before:
            self._save()
            AuditLog.write("DELETE_ENTRY", f"id={entry_id}")
            return True
        return False

    def update(self, entry_id: str, **kwargs) -> bool:
        for e in self._entries:
            if e["id"] == entry_id:
                e.update({k: v for k, v in kwargs.items() if v is not None})
                e["modified"] = datetime.datetime.utcnow().isoformat()
                self._save()
                AuditLog.write("UPDATE_ENTRY", f"id={entry_id}")
                return True
        return False

    def count(self) -> int:
        return len(self._entries)

    def export_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2)
        AuditLog.write("EXPORT_JSON", f"path={path}")

    def export_text(self, path: str):
        lines = [
            "=" * 60,
            "  0xKey — Vault Export",
            f"  Generated : {datetime.datetime.utcnow().isoformat()}Z",
            f"  Entries   : {len(self._entries)}",
            "=" * 60, "",
        ]
        for i, e in enumerate(self._entries, 1):
            lines += [
                f"[{i}] {e['service']}",
                f"    Username : {e['username']}",
                f"    Password : {e['password']}",
                f"    URL      : {e.get('url',  '—')}",
                f"    Notes    : {e.get('notes','—')}",
                f"    Created  : {e['created']}",
                "",
            ]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        AuditLog.write("EXPORT_TEXT", f"path={path}")


# ═════════════════════════════════════════════════════════════════════════════
#  MASTER PASSWORD MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════════

def master_exists() -> bool:
    return os.path.exists(MASTER_FILE)

def set_master(password: str):
    with open(MASTER_FILE, "w") as f:
        f.write(CryptoEngine.hash_master(password))

def verify_master(password: str) -> bool:
    with open(MASTER_FILE) as f:
        stored = f.read().strip()
    return stored == CryptoEngine.hash_master(password)

def prompt_master(confirm: bool = False) -> str:
    pw = getpass.getpass("  🔑  Master password: ")
    if confirm:
        pw2 = getpass.getpass("  🔑  Confirm master password: ")
        if pw != pw2:
            err("Passwords do not match.")
            sys.exit(1)
    return pw


# ═════════════════════════════════════════════════════════════════════════════
#  CLIPBOARD
# ═════════════════════════════════════════════════════════════════════════════

def clipboard_copy(text: str):
    if not CLIPBOARD_AVAILABLE:
        warn("pyperclip not installed — clipboard copy unavailable.")
        return
    pyperclip.copy(text)
    ok(f"Copied to clipboard. Auto-clears in {CLIPBOARD_CLEAR}s.")

    def _clear():
        time.sleep(CLIPBOARD_CLEAR)
        try:
            if pyperclip.paste() == text:
                pyperclip.copy("")
                print(Fore.YELLOW + "\n  ⏱  Clipboard cleared." + Style.RESET_ALL)
        except Exception:
            pass

    threading.Thread(target=_clear, daemon=True).start()


# ═════════════════════════════════════════════════════════════════════════════
#  CLI COMMANDS
# ═════════════════════════════════════════════════════════════════════════════

def cmd_init():
    if master_exists():
        warn("Vault already exists. Unlock it to continue.")
        return
    hdr("Create Master Password")
    info("This password encrypts your vault. It cannot be recovered if lost.")
    pw = prompt_master(confirm=True)
    PasswordUtils.display_strength(pw)
    score, label, _ = PasswordUtils.strength(pw)
    if score < 2:
        warn("Master password is weak.")
        if input("  Continue anyway? [y/N]: ").strip().lower() != "y":
            sys.exit(0)
    set_master(pw)
    v = Vault(pw)
    v._save()
    AuditLog.write("VAULT_INIT", "new vault created")
    ok("Vault created and encrypted.")
    info(f"Location: {VAULT_FILE}")


def cmd_add(vault: Vault):
    hdr("Add Entry")
    service  = input("  Service / App   : ").strip()
    if not service:
        err("Service name is required."); return
    username = input("  Username / Email: ").strip()
    if input("  Generate password? [y/N]: ").strip().lower() == "y":
        length   = input("  Length [16]: ").strip()
        length   = int(length) if length.isdigit() else 16
        password = PasswordUtils.generate(length=length)
        info(f"Generated: {Fore.GREEN}{password}{Style.RESET_ALL}")
        PasswordUtils.display_strength(password)
    else:
        password = getpass.getpass("  Password        : ")
        PasswordUtils.display_strength(password)
    url   = input("  URL (optional)  : ").strip()
    notes = input("  Notes (optional): ").strip()
    entry = vault.add(service, username, password, url, notes)
    ok(f"Entry saved  [id: {Fore.CYAN}{entry['id']}{Style.RESET_ALL}]")
    if CLIPBOARD_AVAILABLE:
        if input("  Copy password to clipboard? [y/N]: ").strip().lower() == "y":
            clipboard_copy(password)


def cmd_list(vault: Vault):
    hdr(f"All Entries  [{vault.count()} total]")
    table(vault.get_all())
    AuditLog.write("LIST_ENTRIES")


def cmd_search(vault: Vault):
    hdr("Search")
    query   = input("  Query: ").strip()
    results = vault.search(query)
    info(f"{len(results)} result(s) for '{query}'")
    table(results)
    AuditLog.write("SEARCH", f"query={query}, hits={len(results)}")


def cmd_get(vault: Vault):
    hdr("Retrieve Password")
    query   = input("  Service or username: ").strip()
    results = vault.search(query)
    if not results:
        warn("No matching entries."); return
    table(results)
    if len(results) == 1:
        entry = results[0]
    else:
        idx = input("  Enter # to view: ").strip()
        if not idx.isdigit() or not (1 <= int(idx) <= len(results)):
            err("Invalid selection."); return
        entry = results[int(idx) - 1]

    print(f"\n  Service  : {Fore.CYAN}{entry['service']}{Style.RESET_ALL}")
    print(f"  Username : {Fore.CYAN}{entry['username']}{Style.RESET_ALL}")
    print(f"  Password : {Fore.GREEN + Style.BRIGHT}{entry['password']}{Style.RESET_ALL}")
    if entry.get("url"):   print(f"  URL      : {entry['url']}")
    if entry.get("notes"): print(f"  Notes    : {entry['notes']}")

    AuditLog.write("GET_PASSWORD", f"service={entry['service']}")

    if CLIPBOARD_AVAILABLE:
        if input("\n  Copy to clipboard? [y/N]: ").strip().lower() == "y":
            clipboard_copy(entry["password"])


def cmd_delete(vault: Vault):
    hdr("Delete Entry")
    query   = input("  Search entry to delete: ").strip()
    results = vault.search(query)
    if not results:
        warn("No matching entries."); return
    table(results)
    idx = input("  Enter # to delete: ").strip()
    if not idx.isdigit() or not (1 <= int(idx) <= len(results)):
        err("Invalid selection."); return
    entry   = results[int(idx) - 1]
    confirm = input(
        f"  {Fore.RED}Permanently delete '{entry['service']}'? [yes/N]:{Style.RESET_ALL} "
    ).strip().lower()
    if confirm == "yes":
        vault.delete(entry["id"])
        ok("Entry deleted.")
    else:
        info("Cancelled.")


def cmd_generate():
    hdr("Password Generator")
    length  = input("  Length [16]: ").strip()
    length  = int(length) if length.isdigit() else 16
    symbols = input("  Include symbols? [Y/n]: ").strip().lower() != "n"
    digits  = input("  Include digits?  [Y/n]: ").strip().lower() != "n"
    upper   = input("  Include upper?   [Y/n]: ").strip().lower() != "n"
    lower   = input("  Include lower?   [Y/n]: ").strip().lower() != "n"
    try:
        pw = PasswordUtils.generate(length=length, upper=upper,
                                    lower=lower, digits=digits, symbols=symbols)
    except ValueError as e:
        err(str(e)); return
    print(f"\n  {Fore.GREEN + Style.BRIGHT}{pw}{Style.RESET_ALL}")
    PasswordUtils.display_strength(pw)
    AuditLog.write("GENERATE_PASSWORD")
    if CLIPBOARD_AVAILABLE:
        if input("\n  Copy to clipboard? [y/N]: ").strip().lower() == "y":
            clipboard_copy(pw)


def cmd_check():
    hdr("Strength Checker")
    pw = getpass.getpass("  Enter password: ")
    PasswordUtils.display_strength(pw)
    AuditLog.write("CHECK_STRENGTH")


def cmd_export(vault: Vault):
    hdr("Export Vault")
    warn("Exports are PLAINTEXT. Keep them secure!")
    fmt = input("  [1] JSON   [2] Text : ").strip()
    ts  = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    if fmt == "1":
        path = os.path.join(EXPORT_DIR, f"0xkey_export_{ts}.json")
        vault.export_json(path)
    elif fmt == "2":
        path = os.path.join(EXPORT_DIR, f"0xkey_export_{ts}.txt")
        vault.export_text(path)
    else:
        err("Invalid choice."); return
    ok(f"Exported → {path}")


def cmd_audit():
    hdr("Audit Log  [last 20 events]")
    records = AuditLog.tail(20)
    if not records:
        info("No records yet."); return
    for r in records:
        icon   = Fore.GREEN + "✔" if r["success"] else Fore.RED + "✖"
        ts     = r["timestamp"][:19].replace("T", " ")
        event  = r["event"]
        detail = f" — {r['detail']}" if r.get("detail") else ""
        print(f"  {icon}{Style.RESET_ALL}  {Fore.WHITE}{ts}{Style.RESET_ALL}  "
              f"{Fore.CYAN}{event:<20}{Style.RESET_ALL}{detail}")


def cmd_change_master(vault: Vault):
    hdr("Change Master Password")
    current = getpass.getpass("  Current password: ")
    if not verify_master(current):
        err("Incorrect password.")
        AuditLog.write("CHANGE_MASTER", "wrong current password", success=False)
        return
    new_pw = prompt_master(confirm=True)
    PasswordUtils.display_strength(new_pw)
    score, _, _ = PasswordUtils.strength(new_pw)
    if score < 2:
        warn("New password is weak.")
        if input("  Continue? [y/N]: ").strip().lower() != "y":
            return
    set_master(new_pw)
    vault._master = new_pw
    vault._save()
    AuditLog.write("CHANGE_MASTER", "master password updated")
    ok("Master password changed. Vault re-encrypted.")


# ═════════════════════════════════════════════════════════════════════════════
#  MENU
# ═════════════════════════════════════════════════════════════════════════════

MENU = """
  {b}╔══════════════════════════════════╗{r}
  {b}║  {g}0xKey{b}  —  MAIN MENU            ║{r}
  {b}╠══════════════════════════════════╣{r}
  {b}║{r}  {c}1{r}  Add entry                     {b}║{r}
  {b}║{r}  {c}2{r}  List all entries              {b}║{r}
  {b}║{r}  {c}3{r}  Search                        {b}║{r}
  {b}║{r}  {c}4{r}  Retrieve password             {b}║{r}
  {b}║{r}  {c}5{r}  Delete entry                  {b}║{r}
  {b}║{r}  {c}6{r}  Generate password             {b}║{r}
  {b}║{r}  {c}7{r}  Check strength                {b}║{r}
  {b}║{r}  {c}8{r}  Export vault                  {b}║{r}
  {b}║{r}  {c}9{r}  Audit log                     {b}║{r}
  {b}║{r}  {c}0{r}  Change master password        {b}║{r}
  {b}║{r}  {c}q{r}  Quit                          {b}║{r}
  {b}╚══════════════════════════════════╝{r}
""".format(
    b=Fore.CYAN + Style.BRIGHT,
    g=Fore.GREEN + Style.BRIGHT,
    c=Fore.YELLOW + Style.BRIGHT,
    r=Style.RESET_ALL,
)


def interactive_loop(vault: Vault):
    actions = {
        "1": cmd_add,
        "2": cmd_list,
        "3": cmd_search,
        "4": cmd_get,
        "5": cmd_delete,
        "8": cmd_export,
        "9": cmd_audit,
        "0": cmd_change_master,
    }
    while True:
        print(MENU)
        choice = input("  Select: ").strip().lower()
        print()
        if choice == "q":
            ok("Session closed. Stay sharp. 🔐")
            break
        elif choice == "6":
            cmd_generate()
        elif choice == "7":
            cmd_check()
        elif choice in actions:
            actions[choice](vault)
        else:
            warn("Invalid option.")


# ═════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    banner()

    parser = argparse.ArgumentParser(description="0xKey Password Manager")
    parser.add_argument("--init",     action="store_true", help="Initialise a new vault")
    parser.add_argument("--generate", action="store_true", help="Generate a password and exit")
    parser.add_argument("--check",    action="store_true", help="Check password strength and exit")
    parser.add_argument("--audit",    action="store_true", help="Print audit log and exit")
    parser.add_argument("--version",  action="store_true", help="Print version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"  0xKey v{APP_VERSION}")
        return

    if args.init:
        cmd_init(); return

    if args.generate:
        cmd_generate(); return

    if args.check:
        cmd_check(); return

    if not master_exists():
        info("No vault found. Let's create one.")
        cmd_init()

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        pw = getpass.getpass("  🔑  Master password: ")
        if verify_master(pw):
            AuditLog.write("UNLOCK_VAULT", "successful")
            ok("Vault unlocked.\n")
            break
        else:
            AuditLog.write("UNLOCK_VAULT", f"failed attempt {attempt}", success=False)
            remaining = max_attempts - attempt
            if remaining:
                err(f"Wrong password. {remaining} attempt(s) left.")
            else:
                err("Too many failed attempts. Exiting.")
                sys.exit(1)

    if args.audit:
        Vault(pw)
        cmd_audit(); return

    vault = Vault(pw)
    info(f"{vault.count()} entr{'y' if vault.count() == 1 else 'ies'} in vault.")

    interactive_loop(vault)


if __name__ == "__main__":
    main()