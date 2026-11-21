# -*- coding: utf-8 -*-
"""
Capsule – silnik analizy.

Ten moduł NIGDY nie uruchamia badanych plików. Wszystko, co robi, to czytanie
bajtów i wyciąganie z nich informacji (analiza statyczna).

Zawiera:
  * analizę pliku (typ, hashe, entropia, ciągi znaków, IOC, struktura PE,
    makra, skrypty, pochodzenie pliku),
  * ocenę zagrożenia (punkty 0–100 + werdykt),
  * opis zachowania „po ludzku”,
  * kwarantannę (zaszyfrowany „pojemnik” + metadane),
  * raport HTML.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import html
import io
import json
import math
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time
import zipfile
from collections import Counter

WERSJA = "0.4.2"

# ---------------------------------------------------------------------------
# Katalog danych programu
# ---------------------------------------------------------------------------

def katalog_danych() -> str:
    if os.name == "nt":
        baza = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        sciezka = os.path.join(baza, "Capsule")
    else:
        sciezka = os.path.join(os.path.expanduser("~"), ".capsule")
    sciezka = os.environ.get("CAPSULE_DANE", sciezka)
    for pod in ("", "kwarantanna", "raporty", "reguly_yara"):
        os.makedirs(os.path.join(sciezka, pod), exist_ok=True)
    return sciezka


# ---------------------------------------------------------------------------
# Sygnatury i reguły
# ---------------------------------------------------------------------------

# Plik testowy EICAR (nieszkodliwy, standardowy test antywirusów).
# Składany w locie, żeby sam kod programu nie był wykrywany jako EICAR.
_EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-" +
          "ANTIVIRUS-TEST-FILE!$H+H*").encode()

ZNANE_HASHE_DOMYSLNE = {
    hashlib.sha256(_EICAR).hexdigest(): "EICAR – plik testowy antywirusów",
}

REGULY_DOMYSLNE = [
    {
        "nazwa": "Przyklad.NotkaOkupu",
        "opis": "Tekst typowy dla notki z żądaniem okupu (ransomware).",
        "ciagi": ["your files have been encrypted", "twoje pliki zostały zaszyfrowane",
                  "to decrypt your files", "decryption key", ".onion"],
        "min": 2,
        "waga": 50,
    },
    {
        "nazwa": "Przyklad.KradziezHasel",
        "opis": "Odwołania do plików z hasłami przeglądarek.",
        "ciagi": ["Login Data", "logins.json", "key4.db", "Local State",
                  "Cookies", "wallet.dat"],
        "min": 3,
        "waga": 40,
    },
]


def wczytaj_znane_hashe() -> dict:
    hashe = dict(ZNANE_HASHE_DOMYSLNE)
    plik = os.path.join(katalog_danych(), "znane_hashe.json")
    if not os.path.exists(plik):
        with open(plik, "w", encoding="utf-8") as f:
            json.dump({"_info": "Dopisz tu: \"sha256\": \"nazwa zagrożenia\""}, f,
                      ensure_ascii=False, indent=2)
    try:
        with open(plik, encoding="utf-8") as f:
            for k, v in json.load(f).items():
                if len(k) == 64:
                    hashe[k.lower()] = v
    except (OSError, ValueError):
        pass
    try:   # pobrane przez „Aktualizuj sygnatury” (capsule_dodatki)
        with open(os.path.join(katalog_danych(), "znane_hashe_online.json"), encoding="utf-8") as f:
            for k, v in json.load(f).items():
                if len(k) == 64:
                    hashe.setdefault(k.lower(), v)
    except (OSError, ValueError):
        pass
    return hashe


_ZLE_ADRESY = {"mtime": None, "zbior": set()}


def normalizuj_adres(url: str) -> str:
    """Adres do porównań: małe litery w schemacie i hoście, bez końcowego '/'."""
    m = re.match(r"^(https?|ftp)://([^/?#]+)(.*)$", url.strip(), re.I)
    if not m:
        return url.strip().lower()
    return f"{m.group(1).lower()}://{m.group(2).lower()}{m.group(3)}".rstrip("/")


def wczytaj_zle_adresy() -> set:
    """Zbiór groźnych adresów pobranych z URLhaus (plik zle_adresy.txt), z pamięcią podręczną."""
    plik = os.path.join(katalog_danych(), "zle_adresy.txt")
    try:
        mt = os.path.getmtime(plik)
    except OSError:
        return set()
    if _ZLE_ADRESY["mtime"] != mt:
        try:
            with open(plik, encoding="utf-8") as f:
                _ZLE_ADRESY["zbior"] = {normalizuj_adres(l) for l in f if l.strip()}
            _ZLE_ADRESY["mtime"] = mt
        except OSError:
            return set()
    return _ZLE_ADRESY["zbior"]


def wczytaj_reguly() -> list:
    plik = os.path.join(katalog_danych(), "reguly.json")
    if not os.path.exists(plik):
        with open(plik, "w", encoding="utf-8") as f:
            json.dump(REGULY_DOMYSLNE, f, ensure_ascii=False, indent=2)
    try:
        with open(plik, encoding="utf-8") as f:
            reguly = json.load(f)
        return [r for r in reguly if isinstance(r, dict) and r.get("ciagi")]
    except (OSError, ValueError):
        return list(REGULY_DOMYSLNE)


def _wczytaj_yara():
    """Opcjonalnie: jeśli zainstalowano yara-python, ładuje reguły *.yar."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    folder = os.path.join(katalog_danych(), "reguly_yara")
    pliki = {f: os.path.join(folder, f) for f in os.listdir(folder)
             if f.lower().endswith((".yar", ".yara"))}
    if not pliki:
        return None
    try:
        return yara.compile(filepaths=pliki)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Narzędzia podstawowe
# ---------------------------------------------------------------------------

def hashe(dane: bytes) -> dict:
    return {
        "md5": hashlib.md5(dane).hexdigest(),
        "sha1": hashlib.sha1(dane).hexdigest(),
        "sha256": hashlib.sha256(dane).hexdigest(),
    }


def entropia(dane: bytes) -> float:
    if not dane:
        return 0.0
    n = len(dane)
    return -sum(c / n * math.log2(c / n) for c in Counter(dane).values())


def rozmiar_czytelny(n: int) -> str:
    for jedn in ("B", "KB", "MB", "GB"):
        if n < 1024 or jedn == "GB":
            return f"{n:.0f} {jedn}" if jedn == "B" else f"{n:.1f} {jedn}"
        n /= 1024
    return str(n)


def zrzut_hex(dane: bytes, limit: int = 4096) -> str:
    wiersze = []
    for i in range(0, min(len(dane), limit), 16):
        kawalek = dane[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in kawalek)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in kawalek)
        wiersze.append(f"{i:08x}  {hx:<47}  {asc}")
    if len(dane) > limit:
        wiersze.append(f"... (pokazano {limit} z {len(dane)} bajtów)")
    return "\n".join(wiersze)


def ciagi_znakow(dane: bytes, min_dl: int = 5, limit: int = 20000) -> list:
    """Wyciąga czytelne napisy ASCII i UTF-16LE (jak narzędzie `strings`)."""
    wynik = []
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_dl, dane):
        wynik.append(m.group().decode("ascii"))
        if len(wynik) >= limit:
            return wynik
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_dl, dane):
        wynik.append(m.group().decode("utf-16le"))
        if len(wynik) >= limit:
            break
    return wynik


def rozbroj(ioc: str) -> str:
    """Zamienia adres na niekliknięty (http -> hxxp, . -> [.])."""
    if "[.]" in ioc:
        return ioc
    m = re.match(r"^(https?|ftp)(://)([^/?#]+)(.*)$", ioc, re.I)
    if m:
        schemat = m.group(1).lower().replace("http", "hxxp").replace("ftp", "fxp")
        return schemat + m.group(2) + m.group(3).replace(".", "[.]") + m.group(4)
    return ioc.replace(".", "[.]")


# ---------------------------------------------------------------------------
# Rozpoznawanie typu pliku
# ---------------------------------------------------------------------------

ROZSZ_WYKONYWALNE = {".exe", ".dll", ".scr", ".com", ".pif", ".sys", ".cpl", ".msi"}
ROZSZ_SKRYPTY = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat",
                 ".cmd", ".hta", ".sh", ".py"}
ROZSZ_DOKUMENTY = {".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt",
                   ".pptm", ".pptx", ".rtf", ".pdf"}
ROZSZ_INNE_RYZYKO = {".lnk", ".zip", ".rar", ".7z", ".iso", ".img", ".jar",
                     ".txt", ".html", ".htm", ".url"}
ROZSZ_NIEWINNE_PRZYNETY = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg",
                           ".jpeg", ".png", ".txt", ".mp3", ".mp4", ".zip"}


def rozpoznaj_typ(dane: bytes, nazwa: str) -> str:
    roz = os.path.splitext(nazwa)[1].lower()
    if dane[:2] == b"MZ":
        return "PE (program/biblioteka Windows)"
    if dane[:4] == b"\x7fELF":
        return "ELF (program Linux)"
    if dane[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "Mach-O (program macOS)"
    if dane[:4] == b"%PDF":
        return "Dokument PDF"
    if dane[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "Dokument Office (stary format OLE)"
    if dane[:4] == b"PK\x03\x04":
        if roz in (".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"):
            return "Dokument Office (OOXML)"
        if roz == ".jar":
            return "Archiwum Java (JAR)"
        return "Archiwum ZIP"
    if dane[:4] == b"Rar!":
        return "Archiwum RAR"
    if dane[:6] == b"7z\xbc\xaf\x27\x1c":
        return "Archiwum 7z"
    if dane[:4] == b"\x4c\x00\x00\x00":
        return "Skrót Windows (LNK)"
    if dane[:5] == b"{\\rtf":
        return "Dokument RTF"
    if roz in ROZSZ_SKRYPTY or dane[:2] == b"#!":
        return f"Skrypt ({roz or 'shebang'})"
    if roz in (".html", ".htm", ".hta"):
        return "Strona HTML / HTA"
    if dane[:3] in (b"\xff\xd8\xff",) or dane[:8] == b"\x89PNG\r\n\x1a\n":
        return "Obraz"
    return f"Inny ({roz or 'bez rozszerzenia'})"


def czy_warto_analizowac(sciezka: str) -> bool:
    roz = os.path.splitext(sciezka)[1].lower()
    if roz in ROZSZ_WYKONYWALNE | ROZSZ_SKRYPTY | ROZSZ_DOKUMENTY | ROZSZ_INNE_RYZYKO:
        return True
    try:
        with open(sciezka, "rb") as f:
            poczatek = f.read(8)
    except OSError:
        return False
    return poczatek[:2] in (b"MZ", b"PK", b"#!") or poczatek[:4] in (b"\x7fELF", b"%PDF")


# ---------------------------------------------------------------------------
# Parser PE (pliki .exe / .dll) – bez zewnętrznych bibliotek
# ---------------------------------------------------------------------------

MASZYNY = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0xaa64: "ARM64", 0x1c0: "ARM"}
PODSYSTEMY = {1: "natywny (sterownik)", 2: "okienkowy (GUI)", 3: "konsolowy",
              9: "Windows CE", 10: "EFI"}


def parsuj_pe(dane: bytes) -> dict | None:
    try:
        if dane[:2] != b"MZ" or len(dane) < 0x40:
            return None
        pe = struct.unpack_from("<I", dane, 0x3C)[0]
        if dane[pe:pe + 4] != b"PE\x00\x00":
            return None
        maszyna, n_sekcji, czas, _, _, rozm_opt, cechy = struct.unpack_from("<HHIIIHH", dane, pe + 4)
        opt = pe + 24
        magic = struct.unpack_from("<H", dane, opt)[0]
        is64 = magic == 0x20B
        punkt_wejscia = struct.unpack_from("<I", dane, opt + 16)[0]
        podsystem = struct.unpack_from("<H", dane, opt + 68)[0]
        off_dd = opt + (112 if is64 else 96)
        n_dd = struct.unpack_from("<I", dane, off_dd - 4)[0]
        katalogi = []
        for i in range(min(n_dd, 16)):
            katalogi.append(struct.unpack_from("<II", dane, off_dd + i * 8))

        sekcje = []
        off_s = opt + rozm_opt
        for i in range(min(n_sekcji, 96)):
            b = off_s + i * 40
            nazwa = dane[b:b + 8].rstrip(b"\x00").decode("latin-1")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", dane, b + 8)
            ch = struct.unpack_from("<I", dane, b + 36)[0]
            surowe = dane[rptr:rptr + rsize]
            sekcje.append({
                "nazwa": nazwa, "va": va, "vsize": vsize, "rsize": rsize, "rptr": rptr,
                "entropia": round(entropia(surowe), 2),
                "wykonywalna": bool(ch & 0x20000000),
                "zapisywalna": bool(ch & 0x80000000),
            })

        def rva2off(rva):
            for s in sekcje:
                if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                    return rva - s["va"] + s["rptr"]
            return None

        def cstr(off, maks=256):
            if off is None or off >= len(dane):
                return ""
            koniec = dane.find(b"\x00", off, off + maks)
            return dane[off:koniec if koniec != -1 else off + maks].decode("latin-1")

        importy: dict[str, list] = {}
        if len(katalogi) > 1 and katalogi[1][0]:
            off = rva2off(katalogi[1][0])
            for _ in range(512):
                if off is None or off + 20 > len(dane):
                    break
                oft, _, _, rva_nazwy, ft = struct.unpack_from("<IIIII", dane, off)
                if not (oft or rva_nazwy or ft):
                    break
                dll = cstr(rva2off(rva_nazwy)).lower()
                funkcje = []
                t_off = rva2off(oft or ft)
                rozm = 8 if is64 else 4
                flaga = 1 << 63 if is64 else 1 << 31
                for _ in range(4096):
                    if t_off is None or t_off + rozm > len(dane):
                        break
                    wart = struct.unpack_from("<Q" if is64 else "<I", dane, t_off)[0]
                    if not wart:
                        break
                    if wart & flaga:
                        funkcje.append(f"#{wart & 0xFFFF}")
                    else:
                        nazwa_f = cstr((rva2off(wart & 0x7FFFFFFF) or -10) + 2)
                        if nazwa_f:
                            funkcje.append(nazwa_f)
                    t_off += rozm
                if dll:
                    importy.setdefault(dll, []).extend(funkcje)
                off += 20

        koniec_sekcji = max((s["rptr"] + s["rsize"] for s in sekcje), default=0)
        podpis = katalogi[4] if len(katalogi) > 4 else (0, 0)
        if podpis[1] and podpis[0] >= koniec_sekcji:
            koniec_sekcji = max(koniec_sekcji, podpis[0] + podpis[1])
        try:
            data_kompilacji = _dt.datetime.fromtimestamp(czas, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except (OverflowError, OSError, ValueError):
            data_kompilacji = f"nieprawidłowa ({czas})"

        return {
            "architektura": MASZYNY.get(maszyna, hex(maszyna)),
            "bity": 64 if is64 else 32,
            "dll": bool(cechy & 0x2000),
            "podsystem": PODSYSTEMY.get(podsystem, str(podsystem)),
            "znacznik_czasu": czas,
            "data_kompilacji": data_kompilacji,
            "punkt_wejscia": hex(punkt_wejscia),
            "sekcje": sekcje,
            "importy": importy,
            "ma_podpis": bool(podpis[1]),
            "dotnet": len(katalogi) > 14 and bool(katalogi[14][1]),
            "nadmiar_bajtow": max(0, len(dane) - koniec_sekcji) if koniec_sekcji else 0,
        }
    except (struct.error, IndexError, ValueError):
        return {"blad": "Uszkodzona lub celowo zniekształcona struktura PE"}


def informacje_o_wersji(dane: bytes) -> dict:
    """Wyciąga z zasobów PE m.in. nazwę firmy i oryginalną nazwę pliku."""
    klucze = ("CompanyName", "ProductName", "FileDescription", "OriginalFilename",
              "InternalName", "FileVersion", "LegalCopyright")
    wynik = {}
    for przes in (0, 1):
        tekst = dane[przes:].decode("utf-16le", errors="ignore")
        for k in klucze:
            if k in wynik:
                continue
            m = re.search(k + r"\x00+([^\x00]{1,120})", tekst)
            if m and m.group(1).isprintable():
                wynik[k] = m.group(1).strip()
    return wynik


# ---------------------------------------------------------------------------
# Heurystyki – co plik potrafi zrobić
# ---------------------------------------------------------------------------

# kategoria -> (opis po ludzku, waga, lista funkcji API)
API_PODEJRZANE = {
    "Wstrzykiwanie kodu": ("Może wstrzykiwać własny kod do innych działających programów "
                           "(technika ukrywania się).", 35,
                           ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                            "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "QueueUserAPC",
                            "SetThreadContext", "NtWriteVirtualMemory", "RtlCreateUserThread"]),
    "Podsłuch klawiatury": ("Może rejestrować naciskane klawisze (keylogger).", 30,
                            ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                             "GetKeyboardState", "RegisterRawInputDevices"]),
    "Kradzież haseł": ("Może odszyfrowywać zapisane hasła (np. z przeglądarki).", 25,
                       ["CryptUnprotectData", "CredEnumerateA", "CredEnumerateW",
                        "CredReadA", "CredReadW", "LsaRetrievePrivateData"]),
    "Pobieranie plików z sieci": ("Może pobierać inne pliki z internetu (downloader).", 20,
                                  ["URLDownloadToFileA", "URLDownloadToFileW",
                                   "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile",
                                   "WinHttpReadData", "HttpSendRequestA", "HttpSendRequestW"]),
    "Zapis w autostarcie/rejestrze": ("Zmienia rejestr systemu – może się dopisać do "
                                      "autostartu.", 10,
                                      ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                                       "RegCreateKeyExW"]),
    "Instalacja usługi": ("Może instalować usługę systemową (działanie w tle po "
                          "restarcie).", 20, ["CreateServiceA", "CreateServiceW"]),
    "Wykrywanie debuggera": ("Sprawdza, czy ktoś go analizuje (typowe dla malware).", 10,
                             ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                              "NtQueryInformationProcess", "OutputDebugStringA"]),
    "Szyfrowanie danych": ("Używa funkcji szyfrujących – samo w sobie normalne, ale "
                           "ransomware też tak działa.", 8,
                           ["CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "CryptImportKey"]),
    "Zrzuty ekranu": ("Może robić zrzuty ekranu.", 10,
                      ["BitBlt", "GetDesktopWindow", "PrintWindow"]),
    "Uruchamianie programów": ("Może uruchamiać inne programy.", 5,
                               ["WinExec", "ShellExecuteA", "ShellExecuteW",
                                "ShellExecuteExW", "CreateProcessA", "CreateProcessW"]),
    "Komunikacja sieciowa": ("Łączy się z siecią.", 5,
                             ["WSAStartup", "connect", "send", "recv", "InternetOpenA",
                              "InternetOpenW", "WinHttpOpen", "InternetConnectA"]),
}

# (regex, kategoria, opis po ludzku, waga)
WZORCE_TEKSTOWE = [
    (r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}", "Zaciemniony skrypt",
     "Uruchamia PowerShell z ukrytym (zakodowanym Base64) poleceniem.", 30),
    (r"FromBase64String", "Zaciemniony skrypt", "Dekoduje ukryte dane z Base64.", 10),
    (r"\b(IEX|Invoke-Expression)\b", "Wykonywanie kodu w locie",
     "Wykonuje kod zbudowany lub pobrany w trakcie działania.", 15),
    (r"DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer|wget |curl ",
     "Pobieranie plików z sieci", "Pobiera coś z internetu.", 15),
    (r"-w(indowstyle)?\s+hidden", "Ukrywanie się", "Uruchamia okno w trybie ukrytym.", 15),
    (r"-ep\s+bypass|-ExecutionPolicy\s+Bypass", "Omijanie zabezpieczeń",
     "Wyłącza zabezpieczenie skryptów PowerShell.", 15),
    (r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|wbadmin\s+delete",
     "Niszczenie kopii zapasowych",
     "Usuwa kopie zapasowe systemu – klasyczny krok ransomware!", 45),
    (r"bcdedit.{0,40}recoveryenabled\s+no", "Niszczenie kopii zapasowych",
     "Wyłącza tryb naprawy systemu.", 30),
    (r"Add-MpPreference.{0,40}Exclusion|Set-MpPreference.{0,40}Disable",
     "Wyłączanie antywirusa", "Próbuje wyłączyć lub oszukać Windows Defendera.", 40),
    (r"CurrentVersion\\Run(Once)?\b", "Zapis w autostarcie/rejestrze",
     "Odwołuje się do klucza autostartu w rejestrze.", 20),
    (r"schtasks(\.exe)?\s+/create", "Zapis w autostarcie/rejestrze",
     "Tworzy zaplanowane zadanie (uruchamianie co jakiś czas).", 20),
    (r"certutil(\.exe)?.{0,20}-urlcache|bitsadmin(\.exe)?\s+/transfer|mshta(\.exe)?\s+http",
     "Nadużycie narzędzi systemowych",
     "Używa wbudowanych narzędzi Windows do pobrania kodu (technika LOLBin).", 30),
    (r"WScript\.Shell|Shell\.Application", "Uruchamianie programów",
     "Uruchamia polecenia systemowe ze skryptu.", 10),
    (r"\b(AutoOpen|Document_Open|Workbook_Open|Auto_Open)\b", "Makro uruchamiane automatycznie",
     "Dokument zawiera makro uruchamiane przy otwarciu.", 35),
    (r"/JavaScript|/JS\b", "Skrypt w PDF", "PDF zawiera kod JavaScript.", 15),
    (r"/OpenAction|/AA\b", "Akcja przy otwarciu PDF", "PDF wykonuje akcję zaraz po otwarciu.", 10),
    (r"/Launch\b", "Uruchamianie programów", "PDF próbuje uruchomić program.", 30),
    (r"\b(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b", "Kryptowaluty",
     "Zawiera coś, co wygląda na adres portfela Bitcoin.", 10),
    (r"[a-z2-7]{56}\.onion|[a-z2-7]{16}\.onion", "Sieć Tor",
     "Odwołuje się do ukrytej usługi w sieci Tor.", 20),
    (r"UPX0|UPX1|UPX!", "Spakowany plik", "Plik spakowany pakerem UPX (ukrywa zawartość).", 15),
]
WZORCE_SKOMPILOWANE = [(re.compile(w, re.I), k, o, p) for w, k, o, p in WZORCE_TEKSTOWE]

RE_URL = re.compile(r"(?:https?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}")
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}\b")
RE_REJESTR = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\x00\"'\r\n]{3,150}", re.I)

# Adresy, które same w sobie są „normalne” w plikach (certyfikaty, schematy)
NIEWINNE_DOMENY = ("schemas.microsoft.com", "www.w3.org", "ocsp.", "crl.", "digicert.com",
                   "verisign.com", "microsoft.com/pki", "sectigo.com", "globalsign",
                   "usertrust.com", "symcb.com", "symcd.com", "thawte.com", "ns.adobe.com",
                   "purl.org", "openxmlformats.org")


KAWALEK_TEKSTU = 256 * 1024     # tyle tekstu przeszukujemy naraz; potem krótka przerwa dla okna


def _po_kawalkach(tekst: str, dzialanie):
    """Wywołuje dzialanie(fragment) dla kolejnych kawałków tekstu (z małym zakładem na styku).

    Wyrażenia regularne trzymają blokadę interpretera, więc jedno wyszukiwanie w 30 MB
    zamrażało okno programu na kilka sekund. Dzięki kawałkom i krótkim przerwom okno
    pozostaje responsywne. dzialanie zwraca True, aby przerwać (np. gdy wszystko znaleziono).
    """
    n = len(tekst)
    if n <= KAWALEK_TEKSTU:
        dzialanie(tekst)
        return
    for start in range(0, n, KAWALEK_TEKSTU):
        if dzialanie(tekst[start:start + KAWALEK_TEKSTU + 400]):
            return
        time.sleep(0.001)


def szukaj_wzorce(tekst: str, wzorce: list) -> dict:
    """{indeks: dopasowanie} – pierwsze trafienie każdego wzorca (regex jest pierwszym elementem krotki)."""
    wyniki = {}

    def krok(fragment):
        for i, w in enumerate(wzorce):
            if i not in wyniki:
                m = w[0].search(fragment)
                if m:
                    wyniki[i] = m
        return len(wyniki) == len(wzorce)

    _po_kawalkach(tekst, krok)
    return wyniki


def wyciagnij_ioc(tekst: str) -> dict:
    listy = ([], [], [], [])

    def krok(fragment):
        for lst, rx in zip(listy, (RE_URL, RE_IP, RE_EMAIL, RE_REJESTR)):
            if len(lst) < 5000:                      # dalsze trafienia i tak nie trafią na ekran
                lst.extend(rx.findall(fragment))

    _po_kawalkach(tekst, krok)
    urle = sorted({u.rstrip(".,);'\"") for u in listy[0]
                   if not any(d in u for d in NIEWINNE_DOMENY)})
    ip = sorted({i for i in listy[1]
                 if not i.startswith(("0.", "127.", "255.")) and i.count(".") == 3
                 and not re.fullmatch(r"\d+\.0\.0\.0|1\.0\.\d+\.\d+|\d\.\d\.\d\.\d", i)
                 and not all(int(o) <= 20 for o in i.split("."))})  # numery wersji
    return {
        "adresy_url": urle[:200],
        "adresy_ip": ip[:200],
        "emaile": sorted(set(listy[2]))[:100],
        "klucze_rejestru": sorted({k.strip() for k in listy[3]})[:100],
    }


# ---------------------------------------------------------------------------
# Pochodzenie pliku
# ---------------------------------------------------------------------------

STREFY = {0: "ten komputer", 1: "sieć lokalna (intranet)", 2: "zaufane witryny",
          3: "INTERNET (plik pobrany z sieci)", 4: "witryny z listy zablokowanych"}


def pochodzenie(sciezka: str) -> dict:
    wynik: dict = {"sciezka": sciezka}
    try:
        st = os.stat(sciezka)
        fmt = lambda t: _dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")
        wynik["utworzono"] = fmt(getattr(st, "st_birthtime", st.st_ctime))
        wynik["zmodyfikowano"] = fmt(st.st_mtime)
        wynik["ostatni_dostep"] = fmt(st.st_atime)
    except OSError:
        pass

    # Windows zapisuje „Znak sieci” (Mark of the Web) w ukrytym strumieniu pliku
    if os.name == "nt":
        try:
            with open(sciezka + ":Zone.Identifier", encoding="utf-8", errors="ignore") as f:
                for linia in f:
                    if "=" in linia:
                        k, v = linia.strip().split("=", 1)
                        if k == "ZoneId":
                            wynik["strefa"] = STREFY.get(int(v), v) if v.isdigit() else v
                        elif k == "HostUrl":
                            wynik["pobrano_z"] = v
                        elif k == "ReferrerUrl":
                            wynik["strona_odsylajaca"] = v
        except OSError:
            pass

    s = sciezka.lower().replace("/", "\\")
    if "\\start menu\\programs\\startup" in s or "\\autostart" in s:
        wynik["uwaga_lokalizacja"] = "Plik leży w folderze AUTOSTARTU – uruchamia się z Windows."
    elif "\\appdata\\local\\temp" in s or "\\windows\\temp" in s or s.startswith("/tmp"):
        wynik["uwaga_lokalizacja"] = "Plik leży w folderze tymczasowym (częste miejsce dla malware)."
    elif "\\appdata\\" in s:
        wynik["uwaga_lokalizacja"] = "Plik leży w ukrytym folderze AppData."
    elif "\\downloads\\" in s or "\\pobrane\\" in s:
        wynik["uwaga_lokalizacja"] = "Plik leży w folderze Pobrane."
    return wynik


def sprawdz_podpis_windows(sciezka: str) -> dict | None:
    """Weryfikuje podpis cyfrowy przez PowerShell (tylko Windows)."""
    if os.name != "nt":
        return None
    sc = sciezka.replace("'", "''")
    polecenie = (f"$s=Get-AuthenticodeSignature -LiteralPath '{sc}';"
                 "[pscustomobject]@{Status=[string]$s.Status;"
                 "Wystawca=[string]$s.SignerCertificate.Subject}|ConvertTo-Json -Compress")
    try:
        wyn = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", polecenie],
                             capture_output=True, text=True, timeout=20,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        dane = json.loads(wyn.stdout or "{}")
        return {"status": dane.get("Status", "?"), "wystawca": dane.get("Wystawca", "")}
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Główna analiza
# ---------------------------------------------------------------------------

MAKS_ROZMIAR = 150 * 1024 * 1024


def analizuj_plik(sciezka: str, pelna: bool = True) -> dict:
    """Analizuje plik na dysku. pelna=False – szybszy tryb dla skanera."""
    rozmiar = os.path.getsize(sciezka)
    with open(sciezka, "rb") as f:
        dane = f.read(MAKS_ROZMIAR)
    wynik = analizuj_dane(dane, os.path.basename(sciezka), pelna=pelna,
                          sciezka=sciezka, rozmiar=rozmiar)
    return wynik


def _dodaj(znal: list, kategoria: str, opis: str, waga: int, dowod: str = ""):
    for z in znal:
        if z["kategoria"] == kategoria and z["opis"] == opis:
            if dowod and dowod not in z["dowod"]:
                z["dowod"] = (z["dowod"] + ", " + dowod)[:300]
            return
    znal.append({"kategoria": kategoria, "opis": opis, "waga": waga, "dowod": dowod[:300]})


def analizuj_dane(dane: bytes, nazwa: str, pelna: bool = True, sciezka: str | None = None,
                  rozmiar: int | None = None, meta_pochodzenia: dict | None = None) -> dict:
    znaleziska: list = []
    typ = rozpoznaj_typ(dane, nazwa)
    h = hashe(dane)
    wynik = {
        "nazwa": nazwa,
        "rozmiar": rozmiar if rozmiar is not None else len(dane),
        "typ": typ,
        "hashe": h,
        "entropia": round(entropia(dane[:8 * 1024 * 1024]), 2),
        "data_analizy": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "znaleziska": znaleziska,
        "sygnatura": None,
    }

    # 1. Znane sygnatury
    znane = wczytaj_znane_hashe()
    if h["sha256"] in znane:
        wynik["sygnatura"] = znane[h["sha256"]]
    elif _EICAR in dane[:1024]:
        wynik["sygnatura"] = ZNANE_HASHE_DOMYSLNE[hashlib.sha256(_EICAR).hexdigest()]
    if wynik["sygnatura"]:
        _dodaj(znaleziska, "Znana sygnatura", f"Plik rozpoznany jako: {wynik['sygnatura']}", 100)

    # 2. Nazwa pliku
    czesci = nazwa.lower().split(".")
    roz = "." + czesci[-1] if len(czesci) > 1 else ""
    if len(czesci) >= 3 and "." + czesci[-2] in ROZSZ_NIEWINNE_PRZYNETY and \
            roz in ROZSZ_WYKONYWALNE | ROZSZ_SKRYPTY | {".lnk"}:
        _dodaj(znaleziska, "Podwójne rozszerzenie",
               f"Nazwa udaje plik {czesci[-2].upper()}, a naprawdę jest to {roz} – "
               "klasyczna sztuczka, by nakłonić do uruchomienia.", 40, nazwa)
    if "‮" in nazwa:
        _dodaj(znaleziska, "Ukryta nazwa", "Nazwa zawiera znak odwracający tekst (RLO), "
               "który maskuje prawdziwe rozszerzenie.", 40)
    if dane[:2] == b"MZ" and roz not in ROZSZ_WYKONYWALNE and roz:
        _dodaj(znaleziska, "Fałszywe rozszerzenie",
               f"To program Windows, choć udaje plik {roz}.", 35)

    # 3. Tekst do przeszukania
    limit_tekstu = (30 if pelna else 12) * 1024 * 1024
    tekst = dane[:limit_tekstu].decode("latin-1")
    if dane.count(b"\x00") > len(dane) // 8:
        tekst += "\n" + dane[:limit_tekstu].decode("utf-16le", errors="ignore")

    # 4. Struktura PE
    pe = parsuj_pe(dane) if dane[:2] == b"MZ" else None
    wynik["pe"] = pe
    if pe and "blad" not in pe:
        wszystkie_api = {f for funk in pe["importy"].values() for f in funk}
        for kat, (opis, waga, lista) in API_PODEJRZANE.items():
            trafione = [f for f in lista if f in wszystkie_api]
            if kat == "Wstrzykiwanie kodu" and len(trafione) < 2:
                continue
            if trafione:
                _dodaj(znaleziska, kat, opis, waga, ", ".join(trafione))
        liczba_importow = sum(len(v) for v in pe["importy"].values())
        if pe["sekcje"] and liczba_importow < 10 and not pe["dotnet"]:
            _dodaj(znaleziska, "Ukryte importy",
                   "Program prawie nie deklaruje używanych funkcji – zwykle oznacza to, "
                   "że prawdziwy kod jest spakowany lub zaszyfrowany.", 15,
                   f"{liczba_importow} importów")
        for s in pe["sekcje"]:
            if s["entropia"] > 7.2 and s["rsize"] > 1024:
                _dodaj(znaleziska, "Spakowany plik",
                       "Część programu jest skompresowana lub zaszyfrowana "
                       "(utrudnia analizę).", 15, f"sekcja {s['nazwa']} entropia {s['entropia']}")
            if s["wykonywalna"] and s["zapisywalna"]:
                _dodaj(znaleziska, "Samomodyfikujący się kod",
                       "Sekcja jest jednocześnie zapisywalna i wykonywalna – program może "
                       "zmieniać własny kod w trakcie działania.", 15, s["nazwa"])
        teraz = _dt.datetime.now(_dt.timezone.utc).timestamp()
        if pe["znacznik_czasu"] > teraz + 86400:
            _dodaj(znaleziska, "Sfałszowana data", "Data kompilacji jest z przyszłości.", 5,
                   pe["data_kompilacji"])
        if pe["nadmiar_bajtow"] > 4096:
            _dodaj(znaleziska, "Dane doklejone na końcu",
                   "Za programem doklejono dodatkowe dane (często ukryty ładunek).", 5,
                   rozmiar_czytelny(pe["nadmiar_bajtow"]))
        wynik["wersja"] = informacje_o_wersji(dane)
        orig = wynik["wersja"].get("OriginalFilename", "")
        if orig and orig.lower().rsplit(".", 1)[0] != nazwa.lower().rsplit(".", 1)[0] \
                and orig.lower() not in nazwa.lower():
            _dodaj(znaleziska, "Zmieniona nazwa",
                   f"Program pierwotnie nazywał się „{orig}” – ktoś zmienił mu nazwę.", 5)
    elif pe and "blad" in pe:
        _dodaj(znaleziska, "Uszkodzona struktura", pe["blad"], 15)

    # 5. Wzorce tekstowe (skrypty, makra, PDF, polecenia)
    trafienia = szukaj_wzorce(tekst, WZORCE_SKOMPILOWANE)
    for i, (regex, kat, opis, waga) in enumerate(WZORCE_SKOMPILOWANE):
        m = trafienia.get(i)
        if m:
            if kat == "Kryptowaluty" and not (typ.startswith(("Skrypt", "Inny", "Strona"))):
                continue
            if kat in ("Skrypt w PDF", "Akcja przy otwarciu PDF") and not typ.startswith("Dokument PDF"):
                continue
            _dodaj(znaleziska, kat, opis, waga, m.group()[:80])

    # 6. Makra Office / archiwa
    if dane[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(dane)) as z:
                nazwy = z.namelist()
                wynik["zawartosc_archiwum"] = nazwy[:300]
                if any(n.lower().endswith("vbaproject.bin") for n in nazwy):
                    _dodaj(znaleziska, "Makra w dokumencie",
                           "Dokument zawiera makra (kod VBA) – częsty sposób infekcji.", 20)
                    for n in nazwy:
                        if n.lower().endswith("vbaproject.bin"):
                            vba = z.read(n).decode("latin-1")
                            for regex, kat, opis, waga in WZORCE_SKOMPILOWANE:
                                m = regex.search(vba)
                                if m:
                                    _dodaj(znaleziska, kat, opis, waga, m.group()[:80])
                for n in nazwy:
                    nr = os.path.splitext(n.lower())[1]
                    if nr in ROZSZ_WYKONYWALNE | ROZSZ_SKRYPTY | {".lnk"}:
                        _dodaj(znaleziska, "Program w archiwum",
                               "Archiwum zawiera plik wykonywalny lub skrypt.", 15, n)
                    if len(n.split(".")) >= 3 and nr in ROZSZ_WYKONYWALNE | ROZSZ_SKRYPTY:
                        _dodaj(znaleziska, "Podwójne rozszerzenie",
                               "W archiwum jest plik z podwójnym rozszerzeniem.", 30, n)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
            if typ.startswith("Archiwum ZIP"):
                _dodaj(znaleziska, "Archiwum chronione/uszkodzone",
                       "Nie da się otworzyć archiwum (może być zaszyfrowane hasłem, "
                       "co bywa sposobem na ominięcie antywirusów).", 10)
    if dane[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and b"Attribute VB_" in dane:
        _dodaj(znaleziska, "Makra w dokumencie",
               "Dokument zawiera makra (kod VBA) – częsty sposób infekcji.", 20)

    # 7. Reguły użytkownika (+ opcjonalnie YARA)
    tekst_maly = tekst.lower()
    for r in wczytaj_reguly():
        trafione = [c for c in r["ciagi"] if c.lower() in tekst_maly]
        if len(trafione) >= int(r.get("min", 1)):
            _dodaj(znaleziska, f"Reguła: {r.get('nazwa', '?')}", r.get("opis", ""),
                   int(r.get("waga", 30)), ", ".join(trafione))
    yr = _wczytaj_yara()
    if yr is not None:
        try:
            for m in yr.match(data=dane):
                _dodaj(znaleziska, f"YARA: {m.rule}", m.meta.get("description", "Reguła YARA"),
                       int(m.meta.get("waga", 40)))
        except Exception:
            pass

    # 8. IOC i ciągi znaków
    wynik["ioc"] = wyciagnij_ioc(tekst)
    if wynik["ioc"]["adresy_ip"] and typ.startswith(("Skrypt", "Strona", "Skrót")):
        _dodaj(znaleziska, "Bezpośrednie adresy IP",
               "Skrypt łączy się bezpośrednio z adresem IP zamiast z nazwą strony.", 10,
               ", ".join(wynik["ioc"]["adresy_ip"][:3]))
    zle = wczytaj_zle_adresy()
    if zle:
        trafione = [u for u in wynik["ioc"].get("adresy_url", []) if normalizuj_adres(u) in zle]
        if trafione:
            _dodaj(znaleziska, "Reputacja adresu",
                   "Plik zawiera adres, który jest na liście groźnych adresów (URLhaus) – "
                   "rozsyła złośliwe oprogramowanie.", 45, ", ".join(rozbroj(u) for u in trafione[:3]))
    if pelna:
        wynik["ciagi"] = ciagi_znakow(dane[:20 * 1024 * 1024])
        wynik["hex"] = zrzut_hex(dane)

    # 9. Pochodzenie
    if sciezka:
        poch = pochodzenie(sciezka)
        if pelna and pe and pe.get("ma_podpis"):
            podp = sprawdz_podpis_windows(sciezka)
            if podp:
                poch["podpis"] = podp
        wynik["pochodzenie"] = poch
        if poch.get("uwaga_lokalizacja", "").startswith("Plik leży w folderze AUTOSTARTU") \
                and (pe or typ.startswith(("Skrypt", "Skrót"))):
            _dodaj(znaleziska, "Zapis w autostarcie/rejestrze",
                   "Plik uruchamia się automatycznie przy starcie Windows.", 15)
    elif meta_pochodzenia:
        wynik["pochodzenie"] = meta_pochodzenia

    _ocen(wynik)
    return wynik


def _ocen(wynik: dict):
    znal = wynik["znaleziska"]
    punkty = min(100, sum(z["waga"] for z in znal))
    podpis = (wynik.get("pochodzenie") or {}).get("podpis") or {}
    if podpis.get("status") == "Valid" and not wynik["sygnatura"]:
        punkty = max(0, punkty - 25)
        wynik["uwaga_podpis"] = f"Plik ma ważny podpis cyfrowy: {podpis.get('wystawca', '')}"
    wynik["punkty"] = punkty
    if wynik["sygnatura"] or punkty >= 70:
        wynik["werdykt"] = "ZŁOŚLIWY"
    elif punkty >= 30:
        wynik["werdykt"] = "PODEJRZANY"
    else:
        wynik["werdykt"] = "CZYSTY"
    wynik["podsumowanie"] = opis_po_ludzku(wynik)


def opis_po_ludzku(w: dict) -> list:
    zdania = []
    if w["werdykt"] == "ZŁOŚLIWY":
        zdania.append("Ten plik jest najprawdopodobniej szkodliwy. Nie uruchamiaj go.")
    elif w["werdykt"] == "PODEJRZANY":
        zdania.append("Ten plik zachowuje się podejrzanie. Uruchamiaj go tylko, jeśli na "
                      "pewno wiesz, skąd pochodzi.")
    else:
        zdania.append("Nie znaleziono wyraźnych oznak zagrożenia (to nie jest 100% gwarancji).")
    if w["sygnatura"]:
        zdania.append(f"Rozpoznano go w bazie znanych zagrożeń jako: {w['sygnatura']}.")

    poch = w.get("pochodzenie") or {}
    skad = []
    if poch.get("pobrano_z"):
        skad.append(f"pobrany z adresu {rozbroj(poch['pobrano_z'])}")
    elif poch.get("strefa"):
        skad.append(f"pochodzi ze strefy: {poch['strefa']}")
    if poch.get("strona_odsylajaca"):
        skad.append(f"przez stronę {rozbroj(poch['strona_odsylajaca'])}")
    if skad:
        zdania.append("Skąd się wziął: plik został " + ", ".join(skad) + ".")
    if poch.get("uwaga_lokalizacja"):
        zdania.append(poch["uwaga_lokalizacja"])
    if poch.get("utworzono"):
        zdania.append(f"Pojawił się na dysku: {poch['utworzono']}.")

    zachowania = [z for z in sorted(w["znaleziska"], key=lambda z: -z["waga"])
                  if z["kategoria"] != "Znana sygnatura"]
    if zachowania:
        zdania.append("Co potrafi / do czego służył:")
        zdania.extend("• " + z["opis"] for z in zachowania[:8])
    ioc = w.get("ioc") or {}
    if ioc.get("adresy_url") or ioc.get("adresy_ip"):
        cele = (ioc.get("adresy_url", []) + ioc.get("adresy_ip", []))[:3]
        zdania.append("Kontaktuje się (lub ma zapisane) adresy: " +
                      ", ".join(rozbroj(c) for c in cele) + ".")
    if w.get("uwaga_podpis"):
        zdania.append(w["uwaga_podpis"] + ".")
    d = w.get("defender") or {}
    if d.get("status") in ("czysty", "zagrozenie"):
        zdania.append(d["opis"])
    vt = w.get("vt") or {}
    if vt.get("status") in ("znany", "nieznany"):
        zdania.append(vt["opis"])
    return zdania


# ---------------------------------------------------------------------------
# Kwarantanna – „pojemnik” na zagrożenia
# ---------------------------------------------------------------------------

NAGLOWEK = b"CAPSULE1"


def _xor(dane: bytes, klucz: bytes) -> bytes:
    # szybki XOR całych bloków
    n = len(dane)
    powielony = (klucz * (n // len(klucz) + 1))[:n]
    return (int.from_bytes(dane, "little") ^ int.from_bytes(powielony, "little")).to_bytes(n, "little")


def do_kwarantanny(sciezka: str, analiza: dict | None = None) -> dict:
    """Zamyka plik w pojemniku: szyfruje, zapisuje metadane i usuwa oryginał."""
    with open(sciezka, "rb") as f:
        dane = f.read()
    if analiza is None:
        analiza = analizuj_plik(sciezka, pelna=False)
    sha = hashlib.sha256(dane).hexdigest()
    baza_id = _dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + sha[:8]
    ident, nr = baza_id, 1
    while True:
        # ten sam plik w kilku miejscach w tej samej sekundzie nie może nadpisać wcześniejszego pojemnika
        folder = os.path.join(katalog_danych(), "kwarantanna", ident)
        try:
            os.makedirs(folder)
            break
        except FileExistsError:
            nr += 1
            ident = f"{baza_id}-{nr}"
    klucz = secrets.token_bytes(32)
    plik_probki = os.path.join(folder, "probka.kps")
    with open(plik_probki, "wb") as f:
        f.write(NAGLOWEK + _xor(dane, klucz))
    meta = {
        "id": ident,
        "nazwa": os.path.basename(sciezka),
        "oryginalna_sciezka": os.path.abspath(sciezka),
        "data_kwarantanny": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sha256": sha,
        "rozmiar": len(dane),
        "werdykt": analiza.get("werdykt"),
        "punkty": analiza.get("punkty"),
        "sygnatura": analiza.get("sygnatura"),
        "typ": analiza.get("typ"),
        "pochodzenie": analiza.get("pochodzenie") or pochodzenie(sciezka),
        "klucz": klucz.hex(),
    }
    with open(os.path.join(folder, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    # weryfikacja zanim usuniemy oryginał
    if hashlib.sha256(odczytaj_probke(ident)).hexdigest() != sha:
        shutil.rmtree(folder, ignore_errors=True)
        raise IOError("Błąd zapisu do kwarantanny – oryginał pozostawiono.")
    try:
        os.remove(sciezka)
    except OSError as e:
        shutil.rmtree(folder, ignore_errors=True)
        raise IOError(f"Nie można usunąć oryginału (może jest używany?): {e}")
    zapisz_zdarzenie(f"Kwarantanna: {meta['nazwa']} ({meta['werdykt']})")
    return meta


def lista_kwarantanny() -> list:
    folder = os.path.join(katalog_danych(), "kwarantanna")
    wynik = []
    for ident in sorted(os.listdir(folder), reverse=True):
        p = os.path.join(folder, ident, "meta.json")
        try:
            with open(p, encoding="utf-8") as f:
                wynik.append(json.load(f))
        except (OSError, ValueError):
            continue
    return wynik


def _meta(ident: str) -> dict:
    with open(os.path.join(katalog_danych(), "kwarantanna", ident, "meta.json"), encoding="utf-8") as f:
        return json.load(f)


def odczytaj_probke(ident: str) -> bytes:
    """Odszyfrowuje próbkę TYLKO w pamięci (nie zapisuje jej na dysk)."""
    meta = _meta(ident)
    with open(os.path.join(katalog_danych(), "kwarantanna", ident, "probka.kps"), "rb") as f:
        surowe = f.read()
    if not surowe.startswith(NAGLOWEK):
        raise ValueError("Uszkodzony pojemnik")
    return _xor(surowe[len(NAGLOWEK):], bytes.fromhex(meta["klucz"]))


def analizuj_z_kwarantanny(ident: str) -> dict:
    meta = _meta(ident)
    dane = odczytaj_probke(ident)
    poch = dict(meta.get("pochodzenie") or {})
    poch["oryginalna_sciezka"] = meta["oryginalna_sciezka"]
    poch["data_kwarantanny"] = meta["data_kwarantanny"]
    w = analizuj_dane(dane, meta["nazwa"], pelna=True, meta_pochodzenia=poch)
    w["id_kwarantanny"] = ident
    return w


def przywroc(ident: str, cel: str | None = None) -> str:
    meta = _meta(ident)
    cel = cel or meta["oryginalna_sciezka"]
    if os.path.exists(cel):
        baza, roz = os.path.splitext(cel)
        cel = f"{baza} (przywrócony){roz}"
    os.makedirs(os.path.dirname(cel) or ".", exist_ok=True)
    with open(cel, "wb") as f:
        f.write(odczytaj_probke(ident))
    usun_z_kwarantanny(ident, loguj=False)
    zapisz_zdarzenie(f"Przywrócono: {meta['nazwa']} -> {cel}")
    return cel


def usun_z_kwarantanny(ident: str, loguj: bool = True):
    meta = _meta(ident)
    shutil.rmtree(os.path.join(katalog_danych(), "kwarantanna", ident))
    if loguj:
        zapisz_zdarzenie(f"Usunięto na stałe: {meta['nazwa']}")


# ---------------------------------------------------------------------------
# Stan programu i historia zdarzeń
# ---------------------------------------------------------------------------

def _plik_stanu():
    return os.path.join(katalog_danych(), "stan.json")


def wczytaj_stan() -> dict:
    try:
        with open(_plik_stanu(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"ostatni_skan": None, "przeskanowano": 0, "wykryto": 0, "zdarzenia": []}


def zapisz_stan(stan: dict):
    stan["zdarzenia"] = stan.get("zdarzenia", [])[-300:]
    with open(_plik_stanu(), "w", encoding="utf-8") as f:
        json.dump(stan, f, ensure_ascii=False, indent=2)


_BLOKADA_STANU = threading.Lock()


def zapisz_zdarzenie(tekst: str):
    # blokada, bo zdarzenia zapisuje i okno programu, i wątek Strażnika
    with _BLOKADA_STANU:
        stan = wczytaj_stan()
        stan.setdefault("zdarzenia", []).append(
            [_dt.datetime.now().strftime("%Y-%m-%d %H:%M"), tekst])
        zapisz_stan(stan)


def zeruj_liczniki(czysc_historie: bool = False):
    """Zeruje liczniki z ostatniego skanu (pliki w kwarantannie zostają nietknięte)."""
    with _BLOKADA_STANU:
        stan = wczytaj_stan()
        stan["ostatni_skan"] = None
        stan["przeskanowano"] = 0
        stan["wykryto"] = 0
        if czysc_historie:
            stan["zdarzenia"] = []
        zapisz_stan(stan)


# ---------------------------------------------------------------------------
# Skaner folderów
# ---------------------------------------------------------------------------

def foldery_szybkiego_skanu() -> list:
    dom = os.path.expanduser("~")
    kandydaci = [os.path.join(dom, n) for n in ("Downloads", "Pobrane", "Desktop", "Pulpit")]
    if os.name == "nt":
        kandydaci += [os.environ.get("TEMP", ""),
                      os.path.join(os.environ.get("APPDATA", ""),
                                   r"Microsoft\Windows\Start Menu\Programs\Startup")]
    return [k for k in kandydaci if k and os.path.isdir(k)]


USTAWIENIA_DOMYSLNE = {
    "straznik_wlaczony": False,   # czy Strażnik ma ruszyć razem z programem
    "auto_kwarantanna": False,    # czy ZŁOŚLIWE pliki zamykać w kwarantannie bez pytania
    "uzyj_defendera": True,       # czy dopytywać Defendera o podejrzane pliki
    "powiadomienia": True,        # czy pokazywać okienka z alarmem
    "foldery": [],                # puste = foldery domyślne (Pobrane, Pulpit, Temp, Autostart)
    "vt_klucz": "",               # klucz API VirusTotal (wysyłany jest tylko hash pliku)
    "vt_straznik": False,         # czy Strażnik ma pytać VirusTotal o podejrzane pliki
    "abusech_klucz": "",          # darmowy Auth-Key z auth.abuse.ch (aktualizacja sygnatur)
    "aktualizuj_auto": False,     # codzienna aktualizacja sygnatur
    "aktualizacja_ostatnia": "",  # kiedy ostatnio (YYYY-MM-DD HH:MM)
    "skan_zaplanowany": False,    # czy działa skan zaplanowany
    "skan_godzina": "18:00",      # o której (HH:MM, codziennie)
    "skan_ostatni": "",           # kiedy ostatnio wystartował skan zaplanowany
    "tray_zamykanie": True,       # X w oknie chowa program do zasobnika zamiast go zamykać
    "wabiki": False,              # czy pułapka na ransomware jest włączona
    "wabiki_foldery": [],         # puste = Dokumenty, Pulpit, Obrazy
    "wabiki_auto_zabij": False,   # czy automatycznie zamykać proces podejrzany o szyfrowanie
}


def wczytaj_ustawienia() -> dict:
    wynik = dict(USTAWIENIA_DOMYSLNE)
    try:
        with open(os.path.join(katalog_danych(), "ustawienia.json"), encoding="utf-8") as f:
            zapisane = json.load(f)
        for k in wynik:
            if k in zapisane and type(zapisane[k]) is type(wynik[k]):
                wynik[k] = zapisane[k]
    except (OSError, ValueError):
        pass
    return wynik


def zapisz_ustawienia(u: dict):
    with open(os.path.join(katalog_danych(), "ustawienia.json"), "w", encoding="utf-8") as f:
        json.dump({k: u.get(k, v) for k, v in USTAWIENIA_DOMYSLNE.items()}, f,
                  ensure_ascii=False, indent=2)


def skanuj(foldery: list, postep=None, stop=None, maks_mb: int = 100):
    """Generator: zwraca wyniki analizy podejrzanych plików.

    postep(sciezka, liczba) – wywoływane co plik; stop() -> True przerywa skan.
    """
    licznik = 0
    wykryte = 0
    for folder in foldery:
        for korzen, katalogi, pliki in os.walk(folder):
            katalogi[:] = [k for k in katalogi if k not in ("$Recycle.Bin", "WinSxS", ".git",
                                                             "node_modules", "__pycache__")]
            for p in pliki:
                if stop and stop():
                    return
                sciezka = os.path.join(korzen, p)
                licznik += 1
                if postep:
                    postep(sciezka, licznik)
                try:
                    if os.path.islink(sciezka) or os.path.getsize(sciezka) > maks_mb * 1024 * 1024:
                        continue
                    if not czy_warto_analizowac(sciezka):
                        continue
                    w = analizuj_plik(sciezka, pelna=False)
                except (OSError, PermissionError):
                    continue
                if w["werdykt"] != "CZYSTY":
                    wykryte += 1
                    w["sciezka"] = sciezka
                    yield w
    stan = wczytaj_stan()
    stan["ostatni_skan"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    stan["przeskanowano"] = licznik
    stan["wykryto"] = wykryte
    zapisz_stan(stan)
    zapisz_zdarzenie(f"Skan zakończony: {licznik} plików, wykryto {wykryte}")


# ---------------------------------------------------------------------------
# Microsoft Defender – współpraca (tylko Windows)
# ---------------------------------------------------------------------------
# Capsule nie zastępuje Defendera. Pyta go o zdanie i tłumaczy jego wykrycia.
# Przy skanie używamy -DisableRemediation, więc Defender niczego nie usuwa
# w ramach tego zapytania.

def _bez_okna() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def sciezka_mpcmdrun() -> str | None:
    """Szuka MpCmdRun.exe (wiersz poleceń Defendera)."""
    if os.name != "nt":
        return None
    kandydaci = []
    platforma = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                             r"Microsoft\Windows Defender\Platform")
    if os.path.isdir(platforma):
        for wersja in sorted(os.listdir(platforma), reverse=True):
            kandydaci.append(os.path.join(platforma, wersja, "MpCmdRun.exe"))
    kandydaci.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                                  r"Windows Defender\MpCmdRun.exe"))
    for k in kandydaci:
        if os.path.isfile(k):
            return k
    return None


def _powershell_json(skrypt: str, limit_s: int = 30):
    """Uruchamia krótki skrypt PowerShell i zwraca sparsowany JSON (lub None)."""
    if os.name != "nt":
        return None
    skrypt = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + skrypt   # polskie znaki
    try:
        wyn = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", skrypt],
            capture_output=True, text=True, timeout=limit_s,
            encoding="utf-8", errors="replace", creationflags=_bez_okna())
        tekst = (wyn.stdout or "").strip()
        return json.loads(tekst) if tekst else None
    except Exception:
        return None


def werdykt_defendera(sciezka: str, limit_s: int = 90) -> dict:
    """Prosi Defendera o skan jednego pliku (bez usuwania).

    Zwraca {"status": czysty|zagrozenie|brak|blad, "nazwa": str, "opis": str}.
    """
    mp = sciezka_mpcmdrun()
    if not mp:
        return {"status": "brak", "nazwa": "",
                "opis": "Microsoft Defender niedostępny (inny system albo inny antywirus)."}
    try:
        wyn = subprocess.run(
            [mp, "-Scan", "-ScanType", "3", "-File", sciezka, "-DisableRemediation"],
            capture_output=True, text=True, timeout=limit_s,
            encoding="utf-8", errors="replace", creationflags=_bez_okna())
    except subprocess.TimeoutExpired:
        return {"status": "blad", "nazwa": "", "opis": "Defender nie odpowiedział w czasie."}
    except OSError as e:
        return {"status": "blad", "nazwa": "", "opis": f"Nie udało się uruchomić Defendera: {e}"}
    wyjscie = (wyn.stdout or "") + (wyn.stderr or "")
    # kody wyjścia MpCmdRun: 0 = brak zagrożeń, 2 = znaleziono zagrożenie
    if wyn.returncode == 0:
        return {"status": "czysty", "nazwa": "",
                "opis": "Microsoft Defender nie znalazł zagrożeń w tym pliku."}
    if wyn.returncode == 2:
        m = re.search(r"(?im)^\s*(?:Threat|Zagro\w+)\s*:\s*(.+?)\s*$", wyjscie)
        nazwa = m.group(1) if m else "nieznane"
        return {"status": "zagrozenie", "nazwa": nazwa,
                "opis": f"Microsoft Defender rozpoznał ten plik jako zagrożenie: {nazwa}."}
    return {"status": "blad", "nazwa": "",
            "opis": f"Defender zwrócił nieoczekiwany kod ({wyn.returncode})."}


def dolacz_defendera(w: dict, wynik_defendera: dict | None = None) -> dict:
    """Dopisuje werdykt Defendera do wyniku analizy i przelicza ocenę."""
    d = wynik_defendera or werdykt_defendera(w.get("sciezka") or "")
    w["defender"] = d
    if d["status"] == "zagrozenie":
        _dodaj(w["znaleziska"], "Defender",
               f"Microsoft Defender również uznaje ten plik za groźny ({d['nazwa']}).",
               40, d["nazwa"])
        _ocen(w)
    else:
        w["podsumowanie"] = opis_po_ludzku(w)
    return w


# ---------------------------------------------------------------------------
# VirusTotal (API v3) – do serwera idzie WYŁĄCZNIE skrót SHA-256, nigdy plik
# ---------------------------------------------------------------------------
import collections as _collections
import time as _time
import urllib.error as _uerr
import urllib.request as _ureq

_VT_ZAPYTANIA = _collections.deque()      # znaczniki czasu ostatnich zapytań (darmowy limit: 4/min)
_VT_CACHE = {}


def vt_sprawdz(sha256: str, klucz: str, czekaj: bool = True, limit_s: int = 20) -> dict:
    """Pyta VirusTotal o hash. Zwraca {status, zlosliwe, podejrzane, razem, etykieta, opis, link}.

    status: znany | nieznany | klucz | limit | blad.  czekaj=False zamiast czekać na limit
    zwraca status 'limit' (dla automatycznych zapytań Strażnika).
    """
    link = "https://www.virustotal.com/gui/file/" + sha256
    if not klucz:
        return {"status": "klucz", "link": link, "opis": "Brak klucza API VirusTotal (Ustawienia)."}
    if sha256 in _VT_CACHE:
        return _VT_CACHE[sha256]
    teraz = _time.time()
    while _VT_ZAPYTANIA and teraz - _VT_ZAPYTANIA[0] > 60:
        _VT_ZAPYTANIA.popleft()
    if len(_VT_ZAPYTANIA) >= 4:
        if not czekaj:
            return {"status": "limit", "link": link,
                    "opis": "Darmowy limit VirusTotal (4 zapytania na minutę) – spróbuj za chwilę."}
        _time.sleep(max(0.0, 61 - (teraz - _VT_ZAPYTANIA[0])))
    _VT_ZAPYTANIA.append(_time.time())
    zapytanie = _ureq.Request("https://www.virustotal.com/api/v3/files/" + sha256,
                              headers={"x-apikey": klucz, "Accept": "application/json",
                                       "User-Agent": "Capsule/" + WERSJA})
    try:
        with _ureq.urlopen(zapytanie, timeout=limit_s) as odp:
            dane = json.load(odp)
    except _uerr.HTTPError as e:
        if e.code == 404:
            wynik = {"status": "nieznany", "link": link,
                     "opis": "VirusTotal nie zna tego pliku (nikt go jeszcze tam nie wysłał)."}
            _VT_CACHE[sha256] = wynik
            return wynik
        if e.code in (401, 403):
            return {"status": "klucz", "link": link, "opis": "VirusTotal odrzucił klucz API – sprawdź go."}
        if e.code == 429:
            return {"status": "limit", "link": link, "opis": "Przekroczono limit zapytań VirusTotal."}
        return {"status": "blad", "link": link, "opis": f"VirusTotal zwrócił błąd {e.code}."}
    except (OSError, ValueError) as e:
        return {"status": "blad", "link": link, "opis": f"Brak połączenia z VirusTotal: {e}"}
    atr = (dane.get("data") or {}).get("attributes") or {}
    st = atr.get("last_analysis_stats") or {}
    zl, podej = int(st.get("malicious", 0)), int(st.get("suspicious", 0))
    razem = sum(int(v) for k, v in st.items() if k in ("malicious", "suspicious", "undetected", "harmless"))
    etykieta = ((atr.get("popular_threat_classification") or {}).get("suggested_threat_label") or "")
    opis = f"VirusTotal: {zl} z {razem} silników antywirusowych uznaje ten plik za groźny"
    opis += f" ({etykieta})." if etykieta else "."
    wynik = {"status": "znany", "zlosliwe": zl, "podejrzane": podej, "razem": razem,
             "etykieta": etykieta, "opis": opis, "link": link}
    _VT_CACHE[sha256] = wynik
    return wynik


def dolacz_vt(w: dict, klucz: str, czekaj: bool = True) -> dict:
    """Dopisuje opinię VirusTotal do wyniku analizy i przelicza ocenę."""
    vt = vt_sprawdz(w["hashe"]["sha256"], klucz, czekaj=czekaj)
    w["vt"] = vt
    if vt["status"] == "znany":
        if vt["zlosliwe"] >= 5:
            _dodaj(w["znaleziska"], "VirusTotal", vt["opis"], 70 if vt["zlosliwe"] >= 10 else 40,
                   vt.get("etykieta", ""))
        elif vt["zlosliwe"] >= 1:
            _dodaj(w["znaleziska"], "VirusTotal",
                   vt["opis"] + " Pojedyncze wykrycia bywają fałszywymi alarmami.", 10)
    _ocen(w)
    return w


SEVERITY_DEFENDERA = {1: "niskie", 2: "średnie", 4: "wysokie", 5: "krytyczne"}


def stan_defendera() -> dict | None:
    """Czy Defender działa i jak świeże ma sygnatury."""
    dane = _powershell_json(
        "$s=Get-MpComputerStatus;[pscustomobject]@{"
        "Wlaczony=[bool]$s.AntivirusEnabled;"
        "CzasRzeczywisty=[bool]$s.RealTimeProtectionEnabled;"
        "WiekSygnatur=[int]$s.AntivirusSignatureAge;"
        "Wersja=[string]$s.AntivirusSignatureVersion}|ConvertTo-Json -Compress")
    if not isinstance(dane, dict):
        return None
    return {"wlaczony": dane.get("Wlaczony"), "czas_rzeczywisty": dane.get("CzasRzeczywisty"),
            "wiek_sygnatur_dni": dane.get("WiekSygnatur"), "wersja_sygnatur": dane.get("Wersja")}


def historia_defendera(limit: int = 30) -> list:
    """Ostatnie wykrycia Defendera: [{czas, nazwa, waga, plik, usunieto, proces}]."""
    limit = max(1, min(int(limit), 200))
    skrypt = (
        "$t=@{};Get-MpThreat|ForEach-Object{$t[[string]$_.ThreatID]=$_};"
        "Get-MpThreatDetection|Sort-Object InitialDetectionTime -Descending|"
        f"Select-Object -First {limit}|ForEach-Object{{$x=$t[[string]$_.ThreatID];"
        "[pscustomobject]@{Czas=$_.InitialDetectionTime.ToString('yyyy-MM-dd HH:mm');"
        "Nazwa=[string]$x.ThreatName;Waga=[int]$x.SeverityID;"
        "Zasoby=(@($_.Resources)-join '; ');Sukces=[bool]$_.ActionSuccess;"
        "Proces=[string]$_.ProcessName}}|ConvertTo-Json -Compress")
    dane = _powershell_json(skrypt, limit_s=45)
    if dane is None:
        return []
    if isinstance(dane, dict):      # PowerShell zwraca pojedynczy obiekt bez listy
        dane = [dane]
    wynik = []
    for d in dane:
        plik = re.sub(r"(?i)\bfile:_?", "", d.get("Zasoby", ""))
        wynik.append({
            "czas": d.get("Czas", ""), "nazwa": d.get("Nazwa") or "nieznane",
            "waga": SEVERITY_DEFENDERA.get(d.get("Waga"), "nieznana"),
            "plik": plik, "usunieto": bool(d.get("Sukces")),
            "proces": d.get("Proces", "")})
    return wynik


def opis_wykrycia_defendera(h: dict) -> str:
    """Wykrycie Defendera wyjaśnione zwykłym językiem."""
    zdanie = f"{h['czas']}: Defender wykrył „{h['nazwa']}” (zagrożenie {h['waga']})"
    if h["plik"]:
        zdanie += f" w: {h['plik']}"
    zdanie += (". Zagrożenie zostało zneutralizowane." if h["usunieto"]
               else ". Defender nie potwierdził usunięcia – sprawdź w Zabezpieczeniach Windows.")
    return zdanie


# ---------------------------------------------------------------------------
# Strażnik – obserwacja folderów w czasie (prawie) rzeczywistym
# ---------------------------------------------------------------------------
# Strażnik co kilka sekund porównuje listę plików z poprzednią. Nowy lub
# zmieniony plik jest analizowany dopiero, gdy przestanie się zmieniać
# (przeglądarka kończy pobieranie). Uwaga: to NIE blokuje uruchomienia pliku.
# Zauważa i alarmuje po fakcie – blokowanie przed startem wymaga sterownika
# systemowego, którego nie da się zrobić w programie napisanym w Pythonie.

class Straznik:
    TYMCZASOWE = {".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload"}
    POMIJANE_KATALOGI = {"$Recycle.Bin", "WinSxS", ".git", "node_modules", "__pycache__"}
    LIMIT_PLIKOW = 20000
    MAKS_PROB = 15            # ile razy ponawiać plik zablokowany przez inny program

    def __init__(self, foldery: list, zdarzenie=None, auto_kwarantanna: bool = False,
                 uzyj_defendera: bool = True, interwal: float = 2.0,
                 glebokosc: int = 2, maks_mb: int = 100, vt_klucz: str = ""):
        self.foldery = list(foldery)
        self.zdarzenie = zdarzenie          # zdarzenie(rodzaj, dane)
        self.auto_kwarantanna = auto_kwarantanna
        self.uzyj_defendera = uzyj_defendera
        self.interwal = interwal
        self.glebokosc = glebokosc
        self.maks_mb = maks_mb
        self.vt_klucz = vt_klucz            # niepusty = pytaj VirusTotal o podejrzane pliki
        self.sprawdzono = 0
        self.wykryto = 0
        self._stop = threading.Event()
        self._watek = None
        self._znane = {}
        self._oczekujace = {}
        self._proby = {}

    @property
    def dziala(self) -> bool:
        return self._watek is not None and self._watek.is_alive()

    @property
    def aktywny(self) -> bool:
        """Działa i nikt nie kazał mu się zatrzymać."""
        return self.dziala and not self._stop.is_set()

    def start(self):
        if self.dziala:
            return
        self._stop.clear()
        self._znane = self._migawka()       # to, co już leży w folderach, uznajemy za tło
        self._oczekujace = {}
        self._proby = {}
        self._watek = threading.Thread(target=self._petla, name="CapsuleStraznik", daemon=True)
        self._watek.start()
        self._emit("start", {"foldery": self.foldery, "plikow": len(self._znane)})

    def stop(self, czekaj: bool = True):
        self._stop.set()
        if czekaj and self._watek is not None:
            self._watek.join(timeout=5)
        self._emit("stop", {"sprawdzono": self.sprawdzono, "wykryto": self.wykryto})

    # --- wnętrze ---------------------------------------------------------

    def _emit(self, rodzaj: str, dane: dict):
        if self.zdarzenie:
            try:
                self.zdarzenie(rodzaj, dane)
            except Exception:
                pass        # błąd w oknie nie może zabić Strażnika

    def _migawka(self) -> dict:
        wynik = {}
        for folder in self.foldery:
            baza = folder.rstrip("\\/").count(os.sep)
            for korzen, katalogi, pliki in os.walk(folder):
                glebokosc = korzen.rstrip("\\/").count(os.sep) - baza
                if glebokosc >= self.glebokosc:
                    katalogi[:] = []
                else:
                    katalogi[:] = [k for k in katalogi if k not in self.POMIJANE_KATALOGI]
                for p in pliki:
                    sc = os.path.join(korzen, p)
                    try:
                        st = os.stat(sc)
                    except OSError:
                        continue
                    wynik[sc] = (st.st_mtime_ns, st.st_size)
                    if len(wynik) >= self.LIMIT_PLIKOW:
                        return wynik
        return wynik

    def _petla(self):
        while not self._stop.wait(self.interwal):
            try:
                self._krok()
            except Exception as e:
                self._emit("blad", {"tekst": str(e)})

    def _krok(self):
        teraz = self._migawka()
        for sc, sig in teraz.items():
            if self._znane.get(sc) == sig:
                continue
            if self._oczekujace.get(sc) != sig:
                self._oczekujace[sc] = sig      # dopiero się zmienia – poczekaj
                continue
            # ta sama sygnatura w dwóch odczytach pod rząd = plik jest gotowy
            if self._stop.is_set():
                return
            self._sprawdz(sc, sig)
        for sc in [s for s in self._oczekujace if s not in teraz]:
            self._oczekujace.pop(sc, None)
            self._proby.pop(sc, None)
        for sc in [s for s in self._znane if s not in teraz]:
            self._znane.pop(sc, None)

    def _zakoncz_plik(self, sc: str, sig):
        self._znane[sc] = sig
        self._oczekujace.pop(sc, None)
        self._proby.pop(sc, None)

    def _sprawdz(self, sc: str, sig):
        if os.path.splitext(sc)[1].lower() in self.TYMCZASOWE or sig[1] > self.maks_mb * 1024 * 1024:
            self._zakoncz_plik(sc, sig)
            return
        try:
            if os.path.islink(sc) or not czy_warto_analizowac(sc):
                self._zakoncz_plik(sc, sig)
                return
            with open(sc, "rb"):        # test: czy inny program nie trzyma pliku
                pass
            w = analizuj_plik(sc, pelna=False)
        except OSError:
            proby = self._proby.get(sc, 0) + 1
            self._proby[sc] = proby
            if proby >= self.MAKS_PROB:
                self._zakoncz_plik(sc, sig)     # poddajemy się
            return                              # inaczej spróbujemy w następnym kroku
        self._zakoncz_plik(sc, sig)
        self.sprawdzono += 1
        w["sciezka"] = sc
        if w["werdykt"] == "CZYSTY":
            self._emit("sprawdzony", {"sciezka": sc, "werdykt": "CZYSTY"})
            return
        if self.uzyj_defendera:
            dolacz_defendera(w)
        if self.vt_klucz:
            dolacz_vt(w, self.vt_klucz, czekaj=False)
        self.wykryto += 1
        zapisz_zdarzenie(f"Strażnik: {w['werdykt']} – {w['nazwa']}")
        if w["werdykt"] == "ZŁOŚLIWY" and self.auto_kwarantanna:
            try:
                meta = do_kwarantanny(sc, w)
                w["id_kwarantanny"] = meta["id"]
                self._emit("kwarantanna", w)
            except (OSError, IOError) as e:
                self._emit("blad", {"tekst": f"Nie udało się zamknąć {w['nazwa']}: {e}"})
        self._emit("wykrycie", w)


# ---------------------------------------------------------------------------
# System: autostart, procesy, połączenia sieciowe (Windows)
# ---------------------------------------------------------------------------
# Wszystko tu to ODCZYT stanu systemu (plus odwracalne wyłączanie autostartu
# i zamykanie wskazanego procesu). Żaden badany plik nie jest uruchamiany.

ROZSZ_POLECEN = r"exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|dll|scr|lnk|msi|hta"
RE_EXE = re.compile(r'^\s*"?([A-Za-z]:\\[^"]*?\.(?:' + ROZSZ_POLECEN + r'))"?', re.I)
RE_PODEJRZANE_POLECENIE = re.compile(
    r"(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,}|\biex\b|invoke-expression|downloadstring|"
    r"downloadfile|frombase64string|mshta|regsvr32.+(scrobj|/i:http)|bitsadmin.+/transfer|"
    r"certutil.+-urlcache|rundll32.+javascript|-windowstyle\s+hidden|-w\s+hidden)", re.I)
PODEJRZANE_PORTY = {4444: "Metasploit/reverse shell", 1337: "typowy port backdoorów",
                    31337: "typowy port backdoorów", 6667: "IRC (sterowanie botnetem)",
                    9001: "Tor", 9050: "Tor", 5555: "często używany przez trojany (ADB/RAT)"}
PROCESY_SYSTEMOWE = {  # nazwa -> katalog, w którym MUSI leżeć
    "svchost.exe": "system32", "lsass.exe": "system32", "csrss.exe": "system32",
    "winlogon.exe": "system32", "services.exe": "system32", "smss.exe": "system32",
    "wininit.exe": "system32", "taskhostw.exe": "system32", "dwm.exe": "system32",
    "explorer.exe": "windows"}
NIETYKALNE_PROCESY = {"system", "registry", "idle", "system idle process", "smss.exe", "csrss.exe",
                      "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "memcompression",
                      "svchost.exe", "dwm.exe", "lsm.exe", "fontdrvhost.exe"}
_CACHE_OCEN = {}


def _windir() -> str:
    return os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\") + "\\"


def _zaufane_katalogi() -> tuple:
    return (_windir(), os.environ.get("ProgramFiles", r"C:\Program Files").lower().rstrip("\\") + "\\",
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower().rstrip("\\") + "\\")


def wyciagnij_exe(polecenie: str) -> str:
    """Wyciąga ścieżkę programu z linii poleceń ('"C:\\a b\\x.exe" -arg')."""
    polecenie = os.path.expandvars((polecenie or "").strip())
    m = RE_EXE.match(polecenie)
    return m.group(1) if m else ""


def podpisy_hurtem(sciezki: list) -> dict:
    """{sciezka_lower: {"status","wystawca"}} – sprawdza podpisy partiami (jedno wywołanie PowerShell)."""
    wynik = {}
    unikalne = sorted({s for s in sciezki if s})
    for i in range(0, len(unikalne), 40):
        partia = unikalne[i:i + 40]
        lista = ",".join("'" + s.replace("'", "''") + "'" for s in partia)
        dane = _powershell_json(
            f"@({lista})|ForEach-Object{{$s=Get-AuthenticodeSignature -LiteralPath $_ "
            "-ErrorAction SilentlyContinue;[pscustomobject]@{Sciezka=$_;Status=[string]$s.Status;"
            "Wystawca=[string]$s.SignerCertificate.Subject}}|ConvertTo-Json -Compress", limit_s=120)
        if isinstance(dane, dict):
            dane = [dane]
        for d in dane or []:
            wynik[d["Sciezka"].lower()] = {"status": d.get("Status", "?"),
                                           "wystawca": (d.get("Wystawca") or "")[:80]}
    return wynik


def _analiza_pliku_z_cache(sciezka: str):
    try:
        st = os.stat(sciezka)
    except OSError:
        return None
    klucz = (sciezka.lower(), st.st_mtime_ns, st.st_size)
    if klucz not in _CACHE_OCEN:
        try:
            _CACHE_OCEN[klucz] = (analizuj_plik(sciezka, pelna=False)
                                  if st.st_size <= 60 * 1024 * 1024 and czy_warto_analizowac(sciezka)
                                  else None)
        except OSError:
            _CACHE_OCEN[klucz] = None
    return _CACHE_OCEN[klucz]


def _werdykt_z_punktow(punkty: int, sygnatura=None) -> str:
    return "ZŁOŚLIWY" if (sygnatura or punkty >= 70) else "PODEJRZANY" if punkty >= 30 else "CZYSTY"


def ocen_wpis(sciezka_exe: str, polecenie: str = "", podpis: dict | None = None,
              nazwa_procesu: str = "") -> dict:
    """Ocena programu uruchamianego przez autostart/proces: punkty, powody, werdykt."""
    punkty, powody = 0, []
    s = (sciezka_exe or "").lower()
    status = (podpis or {}).get("status")

    if polecenie and RE_PODEJRZANE_POLECENIE.search(polecenie):
        punkty += 40
        powody.append("Polecenie wygląda na ukrywanie lub pobieranie kodu (zakodowane/ukryte polecenie, "
                      "pobieranie z sieci).")
    nazwa = (nazwa_procesu or os.path.basename(s)).lower()
    if nazwa in PROCESY_SYSTEMOWE and s:
        oczekiwany = _windir() + ("system32\\" if PROCESY_SYSTEMOWE[nazwa] == "system32" else "")
        if os.path.dirname(s).rstrip("\\") + "\\" != oczekiwany:
            punkty += 60
            powody.append(f"Udaje proces systemowy {nazwa}, ale leży poza {oczekiwany}.")
    if status == "Valid":
        # Ważny podpis: plik pochodzi od zidentyfikowanego wydawcy i nie został zmieniony.
        # Heurystyki importów API (przeglądarki, OneDrive, Steam…) dawałyby tu same fałszywe alarmy,
        # więc oceniamy tylko polecenie i udawanie procesu systemowego.
        wystawca = (podpis or {}).get("wystawca", "")[:60]
        powody.insert(0, f"Podpisany cyfrowo ({wystawca}) – plik nie został zmieniony od podpisania.")
        punkty = min(100, punkty)
        return {"punkty": punkty, "werdykt": _werdykt_z_punktow(punkty), "sygnatura": None,
                "powody": powody}
    if s:
        if not os.path.exists(sciezka_exe):
            punkty += 15
            powody.append("Plik, który ma być uruchamiany, nie istnieje (pozostałość po programie "
                          "albo ślad po usuniętym złośliwym pliku).")
        else:
            if any(m in s for m in ("\\temp\\", "\\downloads\\", "\\pobrane\\", "\\appdata\\roaming\\",
                                    "\\users\\public\\", "\\programdata\\")) and "\\microsoft\\" not in s:
                punkty += 20
                powody.append("Leży w miejscu, z którego zwykle nie uruchamia się zaufanych programów "
                              "(Temp, Pobrane, AppData, ProgramData).")
            if status in ("NotSigned", "HashMismatch", "NotTrusted"):
                punkty += 10 if status == "NotSigned" else 30
                powody.append({"NotSigned": "Brak podpisu cyfrowego – nie wiadomo, kto go stworzył.",
                               "HashMismatch": "Podpis jest uszkodzony – plik zmieniono po podpisaniu.",
                               "NotTrusted": "Podpis nie jest zaufany."}[status])
            w = _analiza_pliku_z_cache(sciezka_exe)
            if w:
                # bez podpisu analiza importów jest tylko wskazówką – jej wkład ograniczamy
                punkty += w["punkty"] if w["sygnatura"] else min(w["punkty"], 40)
                if w["sygnatura"]:
                    powody.insert(0, f"Znane zagrożenie: {w['sygnatura']}.")
                for z in sorted(w["znaleziska"], key=lambda z: -z["waga"])[:3]:
                    powody.append(z["opis"])
                sygn = w["sygnatura"]
                punkty = min(100, punkty)
                return {"punkty": punkty, "werdykt": _werdykt_z_punktow(punkty, sygn),
                        "sygnatura": sygn, "powody": powody}
    punkty = min(100, punkty)
    return {"punkty": punkty, "werdykt": _werdykt_z_punktow(punkty), "sygnatura": None,
            "powody": powody or ["Nic podejrzanego nie znaleziono."]}


# --------------------------------------------------------------- autostart
RUN_KLUCZE = [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
              ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
              ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
              ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
              ("HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")]


def foldery_autostartu() -> list:
    wynik = []
    if os.environ.get("APPDATA"):
        wynik.append(os.path.join(os.environ["APPDATA"], r"Microsoft\Windows\Start Menu\Programs\Startup"))
    if os.environ.get("ProgramData"):
        wynik.append(os.path.join(os.environ["ProgramData"],
                                  r"Microsoft\Windows\Start Menu\Programs\StartUp"))
    return wynik


def _wpisy_rejestru() -> list:
    if os.name != "nt":
        return []
    import winreg
    uchwyty = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    wpisy = []
    for hive, sciezka in RUN_KLUCZE:
        try:
            with winreg.OpenKey(uchwyty[hive], sciezka) as k:
                i = 0
                while True:
                    try:
                        nazwa, dane, typ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    wpisy.append({"typ": "rejestr", "zrodlo": f"Rejestr {hive}\\…\\{sciezka.split(chr(92))[-1]}",
                                  "nazwa": nazwa, "polecenie": str(dane),
                                  "dane": {"hive": hive, "klucz": sciezka, "nazwa": nazwa,
                                           "wartosc": dane, "reg_typ": typ}})
        except OSError:
            continue
    return wpisy


def _wpisy_folderow() -> list:
    wpisy = []
    for f in foldery_autostartu():
        try:
            for n in os.listdir(f):
                if n.lower() == "desktop.ini":
                    continue
                p = os.path.join(f, n)
                if os.path.isfile(p):
                    wpisy.append({"typ": "folder", "zrodlo": "Folder Autostart", "nazwa": n,
                                  "polecenie": p, "dane": {"sciezka": p}})
        except OSError:
            continue
    return wpisy


def parsuj_zadania(dane) -> list:
    """JSON z Get-ScheduledTask -> wpisy (pomija wbudowane zadania Microsoft i wyłączone)."""
    if isinstance(dane, dict):
        dane = [dane]
    wpisy = []
    for d in dane or []:
        sciezka_zad = d.get("Sciezka") or "\\"
        if sciezka_zad.lower().startswith("\\microsoft\\") or d.get("Stan") == "Disabled":
            continue
        akcja = (d.get("Akcja") or "").strip()
        if not akcja:
            continue
        wpisy.append({"typ": "zadanie", "zrodlo": "Harmonogram zadań", "nazwa": d.get("Nazwa", "?"),
                      "polecenie": akcja,
                      "dane": {"nazwa": d.get("Nazwa", ""), "sciezka": sciezka_zad}})
    return wpisy


def parsuj_uslugi(dane) -> list:
    """JSON z Win32_Service -> wpisy (tylko autostartujące spoza katalogu Windows)."""
    if isinstance(dane, dict):
        dane = [dane]
    wpisy = []
    for d in dane or []:
        sciezka = (d.get("PathName") or "").strip()
        if not sciezka or os.path.expandvars(sciezka).lower().lstrip('"').startswith(_windir()):
            continue
        wpisy.append({"typ": "usluga", "zrodlo": "Usługa (autostart)",
                      "nazwa": d.get("DisplayName") or d.get("Name", "?"), "polecenie": sciezka,
                      "dane": {"nazwa": d.get("Name", "")}})
    return wpisy


def audyt_autostartu(postep=None) -> list:
    """Wszystko, co uruchamia się z Windows, z oceną. Posortowane od najgroźniejszych."""
    if os.name != "nt":
        return []
    wpisy = _wpisy_rejestru() + _wpisy_folderow()
    wpisy += parsuj_zadania(_powershell_json(
        "Get-ScheduledTask|ForEach-Object{[pscustomobject]@{Nazwa=$_.TaskName;Sciezka=$_.TaskPath;"
        "Stan=[string]$_.State;Akcja=((@($_.Actions)|ForEach-Object{($_.Execute+' '+$_.Arguments).Trim()})"
        "-join '; ')}}|ConvertTo-Json -Compress", limit_s=60))
    wpisy += parsuj_uslugi(_powershell_json(
        "Get-CimInstance Win32_Service|Where-Object{$_.StartMode -eq 'Auto'}|Select-Object "
        "Name,DisplayName,PathName|ConvertTo-Json -Compress", limit_s=40))
    for i, w in enumerate(wpisy):
        w["id"] = str(i)
        w["sciezka_exe"] = (w["polecenie"] if w["typ"] == "folder" else wyciagnij_exe(w["polecenie"]))
    podpisy = podpisy_hurtem([w["sciezka_exe"] for w in wpisy if w["sciezka_exe"]
                              and os.path.exists(w["sciezka_exe"])])
    for i, w in enumerate(wpisy):
        if postep:
            postep(i + 1, len(wpisy))
        w.update(ocen_wpis(w["sciezka_exe"], w["polecenie"],
                           podpisy.get(w["sciezka_exe"].lower())))
    wpisy.sort(key=lambda w: -w["punkty"])
    return wpisy


# Wyłączanie autostartu jest ODWRACALNE: kopia trafia do autostart_kopia.json
def _plik_kopii_autostartu() -> str:
    return os.path.join(katalog_danych(), "autostart_kopia.json")


def lista_wylaczonych() -> list:
    try:
        with open(_plik_kopii_autostartu(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def _zapisz_wylaczone(lista: list):
    with open(_plik_kopii_autostartu(), "w", encoding="utf-8") as f:
        json.dump(lista, f, ensure_ascii=False, indent=2)


def wylacz_autostart(wpis: dict) -> str:
    """Wyłącza pozycję autostartu (z kopią do przywrócenia). Zwraca opis lub rzuca IOError."""
    typ, d = wpis["typ"], wpis["dane"]
    kopia = {"id": secrets.token_hex(4), "kiedy": _dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
             "typ": typ, "nazwa": wpis["nazwa"], "polecenie": wpis["polecenie"], "dane": dict(d)}
    if typ == "rejestr":
        import winreg
        hive = winreg.HKEY_CURRENT_USER if d["hive"] == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, d["klucz"], 0, winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, d["nazwa"])
        except PermissionError:
            raise IOError("Brak uprawnień. Wpisy HKLM wymagają uruchomienia Capsule jako administrator.")
        except OSError as e:
            raise IOError(f"Nie można usunąć wpisu z rejestru: {e}")
    elif typ == "folder":
        cel_dir = os.path.join(katalog_danych(), "autostart_kopia", kopia["id"])
        os.makedirs(cel_dir, exist_ok=True)
        cel = os.path.join(cel_dir, os.path.basename(d["sciezka"]))
        try:
            shutil.move(d["sciezka"], cel)
        except OSError as e:
            raise IOError(f"Nie można przenieść pliku: {e}")
        kopia["dane"]["kopia"] = cel
    elif typ == "zadanie":
        wyn = _powershell_json(
            f"try{{Disable-ScheduledTask -TaskName '{d['nazwa'].replace(chr(39), chr(39) * 2)}' "
            f"-TaskPath '{d['sciezka'].replace(chr(39), chr(39) * 2)}' -ErrorAction Stop|Out-Null;"
            "'ok'|ConvertTo-Json}catch{$_.Exception.Message|ConvertTo-Json}")
        if wyn != "ok":
            raise IOError(f"Nie udało się wyłączyć zadania: {wyn or 'brak odpowiedzi (uprawnienia?)'}")
    else:
        raise IOError("Usług nie wyłączamy z Capsule (ryzyko uszkodzenia systemu). "
                      "Zrobisz to w services.msc.")
    lista = lista_wylaczonych()
    lista.append(kopia)
    _zapisz_wylaczone(lista)
    zapisz_zdarzenie(f"Wyłączono z autostartu: {wpis['nazwa']}")
    return f"Wyłączono: {wpis['nazwa']}"


def przywroc_autostart(ident: str) -> str:
    lista = lista_wylaczonych()
    kopia = next((k for k in lista if k["id"] == ident), None)
    if not kopia:
        raise IOError("Nie ma takiej kopii.")
    typ, d = kopia["typ"], kopia["dane"]
    if typ == "rejestr":
        import winreg
        hive = winreg.HKEY_CURRENT_USER if d["hive"] == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        with winreg.OpenKey(hive, d["klucz"], 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, d["nazwa"], 0, d.get("reg_typ", winreg.REG_SZ), d["wartosc"])
    elif typ == "folder":
        shutil.move(d["kopia"], d["sciezka"])
    elif typ == "zadanie":
        _powershell_json(f"Enable-ScheduledTask -TaskName '{d['nazwa'].replace(chr(39), chr(39) * 2)}' "
                         f"-TaskPath '{d['sciezka'].replace(chr(39), chr(39) * 2)}'|Out-Null")
    _zapisz_wylaczone([k for k in lista if k["id"] != ident])
    zapisz_zdarzenie(f"Przywrócono do autostartu: {kopia['nazwa']}")
    return f"Przywrócono: {kopia['nazwa']}"


# ------------------------------------------------------------------ procesy
def parsuj_procesy(dane) -> list:
    if isinstance(dane, dict):
        dane = [dane]
    return [{"pid": int(d.get("ProcessId", 0)), "nazwa": d.get("Name") or "?",
             "sciezka": d.get("ExecutablePath") or "", "rodzic": int(d.get("ParentProcessId") or 0),
             "polecenie": (d.get("CommandLine") or "")[:400]} for d in dane or []]


def grupuj_procesy(procesy: list) -> list:
    """Jeden wiersz na program (np. 21 procesów opera.exe -> 'opera.exe', pidy=[...])."""
    grupy = {}
    for p in procesy:
        k = (p["sciezka"].lower(), p["nazwa"].lower())
        if k not in grupy:
            grupy[k] = dict(p, pidy=[p["pid"]], liczba=1)
        else:
            grupy[k]["pidy"].append(p["pid"])
            grupy[k]["liczba"] += 1
            grupy[k]["pid"] = min(grupy[k]["pid"], p["pid"])
    return list(grupy.values())


def lista_procesow(postep=None) -> list:
    """Działające procesy z oceną ryzyka (posortowane od najgroźniejszych)."""
    if os.name != "nt":
        return []
    procesy = parsuj_procesy(_powershell_json(
        "Get-CimInstance Win32_Process|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,"
        "CommandLine|ConvertTo-Json -Compress", limit_s=60))
    podpisy = podpisy_hurtem([p["sciezka"] for p in procesy if p["sciezka"]])
    oceny = {}
    for i, p in enumerate(procesy):
        if postep:
            postep(i + 1, len(procesy))
        klucz = (p["sciezka"].lower(), p["nazwa"].lower())
        if klucz not in oceny:
            if not p["sciezka"]:
                oceny[klucz] = {"punkty": 0, "werdykt": "CZYSTY", "sygnatura": None,
                                "powody": ["Proces systemowy (Windows nie udostępnia jego ścieżki)."]}
            else:
                oceny[klucz] = ocen_wpis(p["sciezka"], p["polecenie"],
                                         podpisy.get(p["sciezka"].lower()), p["nazwa"])
        p.update(oceny[klucz])
    procesy = grupuj_procesy(procesy)
    procesy.sort(key=lambda p: (-p["punkty"], p["nazwa"].lower()))
    return procesy


def zakoncz_proces(pid: int, nazwa: str = "") -> str:
    """Kończy wskazany proces (taskkill). Odmawia dla procesów krytycznych i samego Capsule."""
    if pid in (0, 4, os.getpid()):
        raise IOError("Tego procesu nie wolno zamykać.")
    if nazwa.lower() in NIETYKALNE_PROCESY:
        raise IOError(f"{nazwa} to krytyczny proces Windows – jego zamknięcie zawiesiłoby system.")
    wyn = subprocess.run(["taskkill", "/PID", str(int(pid)), "/F"], capture_output=True, text=True,
                         timeout=20, errors="replace", creationflags=_bez_okna())
    if wyn.returncode != 0:
        raise IOError((wyn.stdout + wyn.stderr).strip() or "taskkill nie powiódł się (uprawnienia?)")
    zapisz_zdarzenie(f"Zakończono proces: {nazwa} (PID {pid})")
    return f"Zakończono {nazwa} (PID {pid})"


# --------------------------------------------------------------- połączenia
def _prywatny(ip: str) -> bool:
    return (ip.startswith(("10.", "192.168.", "127.", "169.254.", "fe80", "::1", "fc", "fd"))
            or re.match(r"^172\.(1[6-9]|2\d|3[01])\.", ip) is not None or ip in ("0.0.0.0", "::", ""))


def parsuj_polaczenia(dane, procesy: list) -> list:
    """Get-NetTCPConnection + lista procesów -> oceniona lista połączeń."""
    if isinstance(dane, dict):
        dane = [dane]
    po_pid = {pid: p for p in procesy for pid in p.get("pidy", [p["pid"]])}
    wynik = []
    for d in dane or []:
        stan = str(d.get("State", ""))
        zdalny, port = d.get("RemoteAddress") or "", int(d.get("RemotePort") or 0)
        lokalny = d.get("LocalAddress") or ""
        if stan == "Established":
            if _prywatny(zdalny) and port not in PODEJRZANE_PORTY:
                continue                      # ruch w sieci lokalnej pomijamy, żeby nie zaśmiecać
            kierunek = "wychodzące"
        elif stan == "Listen" and not lokalny.startswith(("127.", "::1")):
            kierunek = "nasłuchuje"
        else:
            continue
        p = po_pid.get(int(d.get("OwningProcess") or 0), {})
        punkty, powody = p.get("punkty", 0), list(p.get("powody", []))[:2] if p.get("punkty", 0) >= 30 else []
        if port in PODEJRZANE_PORTY and kierunek == "wychodzące":
            punkty += 30
            powody.append(f"Port {port}: {PODEJRZANE_PORTY[port]}.")
        if kierunek == "nasłuchuje" and p.get("punkty", 0) >= 30:
            powody.append("Podejrzany program otwiera port i czeka na połączenia z zewnątrz.")
        punkty = min(100, punkty)
        wynik.append({"pid": int(d.get("OwningProcess") or 0), "proces": p.get("nazwa", "?"),
                      "sciezka": p.get("sciezka", ""), "lokalny": f"{lokalny}:{d.get('LocalPort')}",
                      "zdalny": f"{zdalny}:{port}" if kierunek == "wychodzące" else "—",
                      "stan": kierunek, "punkty": punkty, "werdykt": _werdykt_z_punktow(punkty),
                      "powody": powody or ["—"]})
    wynik.sort(key=lambda c: (-c["punkty"], c["proces"].lower()))
    return wynik


def polaczenia_sieciowe(procesy: list | None = None) -> list:
    if os.name != "nt":
        return []
    procesy = procesy if procesy is not None else lista_procesow()
    dane = _powershell_json(
        "Get-NetTCPConnection|Where-Object{$_.State -in 'Established','Listen'}|ForEach-Object{"
        "[pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;"
        "RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;State=[string]$_.State;"
        "OwningProcess=$_.OwningProcess}}|ConvertTo-Json -Compress", limit_s=40)
    return parsuj_polaczenia(dane, procesy)


# ---------------------------------------------------------------------------
# Raport HTML
# ---------------------------------------------------------------------------

KOLORY = {"ZŁOŚLIWY": "#c62828", "PODEJRZANY": "#ef6c00", "CZYSTY": "#2e7d32"}


def raport_html(w: dict) -> str:
    e = html.escape
    kolor = KOLORY.get(w["werdykt"], "#555")
    wiersz = lambda k, v: f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>"

    poch = w.get("pochodzenie") or {}
    etykiety = {"sciezka": "Ścieżka", "oryginalna_sciezka": "Oryginalna ścieżka",
                "strefa": "Strefa (Znak sieci)", "pobrano_z": "Pobrano z",
                "strona_odsylajaca": "Strona odsyłająca", "utworzono": "Utworzono",
                "zmodyfikowano": "Zmodyfikowano", "ostatni_dostep": "Ostatni dostęp",
                "data_kwarantanny": "Kwarantanna od", "uwaga_lokalizacja": "Lokalizacja"}
    wiersze_poch = "".join(wiersz(etykiety[k], rozbroj(v) if k in ("pobrano_z", "strona_odsylajaca") else v)
                           for k, v in poch.items() if k in etykiety)
    if poch.get("podpis"):
        wiersze_poch += wiersz("Podpis cyfrowy", f"{poch['podpis']['status']} {poch['podpis']['wystawca']}")
    if w.get("wersja"):
        wiersze_poch += "".join(wiersz(k, v) for k, v in w["wersja"].items())

    znal = "".join(
        f"<tr><td><b>{e(z['kategoria'])}</b></td><td>{e(z['opis'])}</td>"
        f"<td class=dow>{e(z['dowod'])}</td><td>{z['waga']}</td></tr>"
        for z in sorted(w["znaleziska"], key=lambda z: -z["waga"])) or \
        "<tr><td colspan=4>Brak znalezisk.</td></tr>"

    tech = wiersz("Typ", w["typ"]) + wiersz("Rozmiar", rozmiar_czytelny(w["rozmiar"])) + \
        wiersz("Entropia", f"{w['entropia']} / 8") + \
        "".join(wiersz(k.upper(), v) for k, v in w["hashe"].items())
    pe = w.get("pe")
    sekcje_html = ""
    if pe and "blad" not in pe:
        tech += wiersz("Architektura", pe["architektura"]) + \
            wiersz("Rodzaj", "biblioteka DLL" if pe["dll"] else f"program {pe['podsystem']}") + \
            wiersz("Data kompilacji", pe["data_kompilacji"]) + \
            wiersz(".NET", "tak" if pe["dotnet"] else "nie") + \
            wiersz("Biblioteki", ", ".join(pe["importy"].keys()) or "brak")
        sekcje_html = "<h2>Sekcje programu</h2><table><tr><th>Nazwa</th><th>Rozmiar</th>" \
                      "<th>Entropia</th><th>Uprawnienia</th></tr>" + "".join(
            f"<tr><td>{e(s['nazwa'])}</td><td>{rozmiar_czytelny(s['rsize'])}</td>"
            f"<td>{s['entropia']}</td><td>{'X' if s['wykonywalna'] else '-'}"
            f"{'W' if s['zapisywalna'] else '-'}</td></tr>" for s in pe["sekcje"]) + "</table>"

    ioc = w.get("ioc") or {}
    ioc_html = ""
    for k, nazwa in (("adresy_url", "Adresy URL"), ("adresy_ip", "Adresy IP"),
                     ("emaile", "E-maile"), ("klucze_rejestru", "Klucze rejestru")):
        if ioc.get(k):
            ioc_html += f"<h3>{nazwa}</h3><ul>" + "".join(
                f"<li><code>{e(rozbroj(x) if k != 'klucze_rejestru' else x)}</code></li>"
                for x in ioc[k][:50]) + "</ul>"
    ioc_html = ioc_html or "<p>Nie znaleziono.</p>"

    podsum = "".join(f"<p>{e(z)}</p>" for z in w["podsumowanie"])
    vt = f"https://www.virustotal.com/gui/file/{w['hashe']['sha256']}"
    return f"""<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8">
<title>Raport Capsule – {e(w['nazwa'])}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;max-width:960px;margin:30px auto;color:#222;padding:0 16px}}
.werdykt{{background:{kolor};color:#fff;padding:18px 24px;border-radius:10px}}
.werdykt h1{{margin:0;font-size:26px}} .werdykt p{{margin:4px 0 0}}
.ramka{{background:#f5f7fa;border-left:4px solid {kolor};padding:10px 18px;border-radius:6px}}
table{{border-collapse:collapse;width:100%;margin:8px 0 18px}}
th,td{{border-bottom:1px solid #e3e3e3;padding:6px 8px;text-align:left;vertical-align:top;font-size:14px}}
th{{background:#fafafa;width:220px}} td.dow{{font-family:Consolas,monospace;font-size:12px;color:#555;word-break:break-all}}
code{{word-break:break-all}} h2{{border-bottom:2px solid #eee;padding-bottom:4px;margin-top:30px}}
.stopka{{color:#888;font-size:12px;margin-top:40px}}
</style></head><body>
<div class="werdykt"><h1>{e(w['werdykt'])} – {e(w['nazwa'])}</h1>
<p>Poziom zagrożenia: <b>{w['punkty']}/100</b> · analiza: {e(w['data_analizy'])}</p></div>
<h2>W skrócie</h2><div class="ramka">{podsum}</div>
<h2>Pochodzenie</h2><table>{wiersze_poch or wiersz('Brak danych', '-')}</table>
<h2>Zachowanie i znaleziska</h2>
<table><tr><th>Kategoria</th><th>Co to znaczy</th><th>Dowód</th><th>Waga</th></tr>{znal}</table>
<h2>Szczegóły techniczne</h2><table>{tech}</table>{sekcje_html}
<h2>Wskaźniki (IOC)</h2>{ioc_html}
<p>Sprawdź opinię innych antywirusów (wysyłany jest tylko hash, nie plik):
<a href="{vt}">{e(vt)}</a></p>
<p class="stopka">Raport wygenerowany przez Capsule {WERSJA}. Analiza statyczna – plik nie był uruchamiany.
Adresy zostały „rozbrojone” (hxxp, [.]), żeby nie dało się ich przypadkiem kliknąć.</p>
</body></html>"""


def zapisz_raport(w: dict, sciezka: str | None = None) -> str:
    if not sciezka:
        bezpieczna = re.sub(r"[^\w.-]", "_", w["nazwa"])[:60]
        sciezka = os.path.join(katalog_danych(), "raporty",
                               f"{_dt.datetime.now():%Y%m%d-%H%M%S}_{bezpieczna}.html")
    with open(sciezka, "w", encoding="utf-8") as f:
        f.write(raport_html(w))
    zapisz_zdarzenie(f"Raport: {w['nazwa']} ({w['werdykt']})")
    return sciezka


def lista_raportow() -> list:
    folder = os.path.join(katalog_danych(), "raporty")
    pliki = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".html")]
    return sorted(pliki, key=os.path.getmtime, reverse=True)
