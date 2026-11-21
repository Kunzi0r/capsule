# -*- coding: utf-8 -*-
"""
Capsule – dodatki: praca w tle, pułapka na ransomware, aktualizacja sygnatur, harmonogram.

  * JednaInstancja      – tylko jedna kopia programu; druga kopia budzi pierwszą,
  * skrót na pulpicie, wpis autostartu z Windows,
  * czy_pora_na_skan    – logika skanów zaplanowanych (czysta funkcja, łatwa do testów),
  * PulapkaRansomware   – ukryte pliki-wabiki + wskazanie procesu, który je rusza,
  * aktualizuj_sygnatury – pobieranie publicznych list zagrożeń (abuse.ch).

Nic tu nie uruchamia badanych plików.
"""

from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import capsule_engine as silnik

KATALOG_PROGRAMU = os.path.dirname(os.path.abspath(__file__))
PORT_INSTANCJI = 47653


# ---------------------------------------------------------------------------
# Tylko jedna kopia programu
# ---------------------------------------------------------------------------

class JednaInstancja:
    """Pierwsza kopia nasłuchuje na 127.0.0.1; kolejna wysyła jej „pokaż się” i kończy pracę."""

    def __init__(self, port: int = PORT_INSTANCJI):
        self.port = port
        self._gniazdo = None

    def zajmij(self) -> bool:
        """True – jesteśmy pierwsi. False – inna kopia już działa."""
        g = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt":
                # Windows: SO_REUSEADDR pozwoliłby zająć port drugiej kopii, więc blokujemy go na wyłączność
                g.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                # Linux/macOS: bez tego port po ostatnim połączeniu bywa zajęty (TIME_WAIT) przez ~minutę
                g.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            g.bind(("127.0.0.1", self.port))
            g.listen(5)
        except OSError:
            g.close()
            return False
        self._gniazdo = g
        return True

    def nasluchuj(self, po_wiadomosci):
        """po_wiadomosci(sciezka_lub_None) – wywoływane z wątku tła."""
        def petla():
            while self._gniazdo is not None:
                try:
                    pol, _ = self._gniazdo.accept()
                except OSError:
                    return
                try:
                    pol.settimeout(2)
                    linia = pol.recv(4096).decode("utf-8", "replace").strip()
                    if linia.startswith("POKAZ"):
                        sciezka = linia[5:].strip() or None
                        po_wiadomosci(sciezka)
                except OSError:
                    pass
                finally:
                    pol.close()
        threading.Thread(target=petla, name="CapsuleInstancja", daemon=True).start()

    def zamknij(self):
        g, self._gniazdo = self._gniazdo, None
        if g is not None:
            try:
                g.shutdown(socket.SHUT_RDWR)      # budzi wątek czekający w accept()
            except OSError:
                pass
            try:
                g.close()
            except OSError:
                pass

    def obudz_dzialajaca(self, sciezka: str | None = None) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=2) as p:
                p.sendall(("POKAZ " + (sciezka or "")).encode("utf-8"))
            return True
        except OSError:
            return False


# ---------------------------------------------------------------------------
# Ikona, skrót na pulpicie, autostart z Windows
# ---------------------------------------------------------------------------

def sciezka_ikony() -> str | None:
    """capsule.ico obok programu; jeśli brak, próbuje go narysować (potrzebny Pillow)."""
    ico = os.path.join(KATALOG_PROGRAMU, "capsule.ico")
    if os.path.isfile(ico):
        return ico
    ico = os.path.join(silnik.katalog_danych(), "capsule.ico")
    if not os.path.isfile(ico):
        try:
            import capsule_ikona
            capsule_ikona.zapisz_ico(ico)
        except Exception:
            return None
    return ico


def pythonw() -> str:
    """Interpreter bez okna konsoli (pythonw.exe), jeśli jest obok python.exe."""
    exe = sys.executable
    if os.name == "nt" and os.path.basename(exe).lower() == "python.exe":
        kandydat = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.isfile(kandydat):
            return kandydat
    return exe


def polecenie_uruchomienia(ukryty: bool = False) -> str:
    return (f'"{pythonw()}" "{os.path.join(KATALOG_PROGRAMU, "capsule.py")}"'
            + (" --ukryty" if ukryty else ""))


_KLUCZ_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"


def autostart_wlaczony() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KLUCZ_RUN) as k:
            winreg.QueryValueEx(k, "Capsule")
        return True
    except OSError:
        return False


def ustaw_autostart(wlacz: bool):
    """Uruchamianie Capsule razem z Windows (w tle, od razu schowany do zasobnika)."""
    if os.name != "nt":
        raise OSError("Autostart działa tylko na Windows.")
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _KLUCZ_RUN, 0, winreg.KEY_SET_VALUE) as k:
        if wlacz:
            winreg.SetValueEx(k, "Capsule", 0, winreg.REG_SZ, polecenie_uruchomienia(ukryty=True))
        else:
            try:
                winreg.DeleteValue(k, "Capsule")
            except FileNotFoundError:
                pass


def _ps_cytat(tekst: str) -> str:
    return "'" + tekst.replace("'", "''") + "'"


def folder_specjalny(nazwa: str) -> str | None:
    """Np. 'Desktop' albo 'Programs' – z uwzględnieniem przekierowań (OneDrive)."""
    dane = silnik._powershell_json(f"[Environment]::GetFolderPath({_ps_cytat(nazwa)})|ConvertTo-Json")
    return dane if isinstance(dane, str) and os.path.isdir(dane) else None


def utworz_skrot(folder: str, nazwa: str = "Capsule.lnk") -> str:
    """Tworzy skrót do Capsule (z ikoną) w podanym folderze. Zwraca ścieżkę skrótu."""
    if os.name != "nt":
        raise OSError("Skróty .lnk działają tylko na Windows.")
    lnk = os.path.join(folder, nazwa)
    ico = sciezka_ikony() or ""
    skrypt = (
        "$w=New-Object -ComObject WScript.Shell;"
        f"$s=$w.CreateShortcut({_ps_cytat(lnk)});"
        f"$s.TargetPath={_ps_cytat(pythonw())};"
        f"$s.Arguments={_ps_cytat(chr(34) + os.path.join(KATALOG_PROGRAMU, 'capsule.py') + chr(34))};"
        f"$s.WorkingDirectory={_ps_cytat(KATALOG_PROGRAMU)};"
        f"$s.Description={_ps_cytat('Capsule – laboratorium bezpieczeństwa')};"
        + (f"$s.IconLocation={_ps_cytat(ico)};" if ico else "")
        + "$s.Save();'ok'|ConvertTo-Json")
    if silnik._powershell_json(skrypt, limit_s=20) != "ok" or not os.path.isfile(lnk):
        raise OSError("Nie udało się utworzyć skrótu.")
    return lnk


def utworz_skroty() -> list:
    """Skrót na pulpicie i w menu Start. Zwraca listę utworzonych ścieżek."""
    wynik = []
    for nazwa in ("Desktop", "Programs"):
        folder = folder_specjalny(nazwa)
        if folder:
            wynik.append(utworz_skrot(folder))
    if not wynik:
        raise OSError("Nie znaleziono folderu pulpitu.")
    return wynik


# ---------------------------------------------------------------------------
# Harmonogram skanów (wewnątrz programu; działa, gdy Capsule jest uruchomiony w tle)
# ---------------------------------------------------------------------------

FORMAT_CZASU = "%Y-%m-%d %H:%M"


def _czas(tekst: str):
    try:
        return _dt.datetime.strptime(tekst, FORMAT_CZASU)
    except (ValueError, TypeError):
        return None


def czy_pora_na_skan(ust: dict, teraz: _dt.datetime | None = None) -> bool:
    """Skan zaplanowany jest należny, gdy minęła dzisiejsza godzina skanu, a dzisiaj jeszcze go nie było.

    Dzięki temu skan, który „przespał” komputer, wykona się zaraz po uruchomieniu programu.
    """
    if not ust.get("skan_zaplanowany"):
        return False
    teraz = teraz or _dt.datetime.now()
    try:
        g, m = (int(x) for x in str(ust.get("skan_godzina", "18:00")).split(":"))
        termin = teraz.replace(hour=g, minute=m, second=0, microsecond=0)
    except ValueError:
        return False
    ostatni = _czas(ust.get("skan_ostatni", ""))
    return teraz >= termin and (ostatni is None or ostatni < termin)


def czy_pora_na_aktualizacje(ust: dict, teraz: _dt.datetime | None = None, co_godzin: int = 24) -> bool:
    if not ust.get("aktualizuj_auto") or not ust.get("abusech_klucz"):
        return False
    teraz = teraz or _dt.datetime.now()
    ostatnia = _czas(ust.get("aktualizacja_ostatnia", ""))
    return ostatnia is None or teraz - ostatnia >= _dt.timedelta(hours=co_godzin)


def poprawna_godzina(tekst: str) -> bool:
    return re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", tekst.strip()) is not None


# ---------------------------------------------------------------------------
# Aktualizacja sygnatur (abuse.ch – wymaga darmowego Auth-Key z auth.abuse.ch)
# ---------------------------------------------------------------------------
# UWAGA: dokumentacja eksportów abuse.ch jest za logowaniem, więc parsery są
# celowo tolerancyjne (szukają hashy i adresów w dowolnej kolumnie).

RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
RE_URL = re.compile(r"https?://[^\s\",<>']+", re.I)


def parsuj_hashe_malwarebazaar(tekst: str) -> dict:
    """CSV z MalwareBazaar -> {sha256: nazwa rodziny}."""
    wynik, naglowek = {}, []
    for linia in tekst.splitlines():
        if linia.startswith("#"):
            if "sha256" in linia.lower():
                naglowek = [c.strip().lower() for c in linia.lstrip("# ").split(",")]
            continue
        if not linia.strip():
            continue
        try:
            pola = next(csv.reader([linia], skipinitialspace=True))
        except csv.Error:
            continue
        sha = next((p.strip().lower() for p in pola if RE_SHA256.match(p.strip())), None)
        if not sha:
            continue
        nazwa = ""
        if "signature" in naglowek and len(pola) == len(naglowek):
            nazwa = pola[naglowek.index("signature")].strip()
        if not nazwa or nazwa.lower() in ("n/a", "none", "null"):
            nazwa = "wpis z MalwareBazaar"
        wynik[sha] = f"{nazwa} (MalwareBazaar)"
    return wynik


def parsuj_adresy_urlhaus(tekst: str) -> set:
    """CSV/tekst z URLhaus -> zbiór adresów URL."""
    wynik = set()
    for linia in tekst.splitlines():
        if linia.startswith("#"):
            continue
        for u in RE_URL.findall(linia):
            wynik.add(silnik.normalizuj_adres(u))
    return wynik


def _pobierz(url: str, limit_s: int = 60, maks_mb: int = 60) -> str:
    zapytanie = urllib.request.Request(url, headers={"User-Agent": "Capsule/" + silnik.WERSJA})
    with urllib.request.urlopen(zapytanie, timeout=limit_s) as odp:
        dane = odp.read(maks_mb * 1024 * 1024)
    return dane.decode("utf-8", "replace")


def aktualizuj_sygnatury(klucz: str, pobierz=_pobierz) -> dict:
    """Pobiera listy z abuse.ch i zapisuje je w katalogu danych. Zwraca {hashe, adresy, bledy}."""
    wynik = {"hashe": 0, "adresy": 0, "bledy": []}
    if not klucz.strip():
        wynik["bledy"].append("Brak Auth-Key z auth.abuse.ch (Ustawienia → Integracje).")
        return wynik
    klucz = klucz.strip()
    zrodla = (
        ("MalwareBazaar", f"https://mb-api.abuse.ch/v2/files/exports/{klucz}/recent.csv"),
        ("URLhaus", f"https://urlhaus-api.abuse.ch/v2/files/exports/{klucz}/recent.csv"),
    )
    dane_dir = silnik.katalog_danych()
    for nazwa, url in zrodla:
        try:
            tekst = pobierz(url)
        except urllib.error.HTTPError as e:
            wynik["bledy"].append(f"{nazwa}: HTTP {e.code}" +
                                  (" (zły klucz?)" if e.code in (401, 403) else ""))
            continue
        except (OSError, ValueError) as e:
            wynik["bledy"].append(f"{nazwa}: {e}")
            continue
        if nazwa == "MalwareBazaar":
            hashe = parsuj_hashe_malwarebazaar(tekst)
            if hashe:
                with open(os.path.join(dane_dir, "znane_hashe_online.json"), "w", encoding="utf-8") as f:
                    json.dump(hashe, f, ensure_ascii=False)
            else:
                wynik["bledy"].append("MalwareBazaar: nie znaleziono hashy w pobranym pliku.")
            wynik["hashe"] = len(hashe)
        else:
            adresy = parsuj_adresy_urlhaus(tekst)
            if adresy:
                with open(os.path.join(dane_dir, "zle_adresy.txt"), "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(adresy)))
            else:
                wynik["bledy"].append("URLhaus: nie znaleziono adresów w pobranym pliku.")
            wynik["adresy"] = len(adresy)
    if wynik["hashe"] or wynik["adresy"]:
        silnik.zapisz_zdarzenie(f"Zaktualizowano sygnatury: {wynik['hashe']} hashy, "
                                f"{wynik['adresy']} adresów")
    return wynik


# ---------------------------------------------------------------------------
# Pułapka na ransomware
# ---------------------------------------------------------------------------
# Ransomware szyfruje pliki po kolei. Ukryte pliki-wabiki o nazwach zaczynających
# się od „!” (sortują się pierwsze) trafiają w jego ręce szybko. Gdy wabik zostanie
# zmieniony, usunięty albo przemianowany, Capsule alarmuje i pokazuje, które procesy
# właśnie intensywnie zapisywały dane na dysk.
# To sygnał ostrzegawczy, nie gwarancja: wykryje atak, gdy pierwszy wabik zostanie ruszony.

WABIKI_NAZWY = ("!_capsule_wabik.docx", "!_capsule_wabik.xlsx", "!_capsule_wabik.pdf",
                "!_capsule_wabik.jpg", "!_capsule_wabik.txt")
_NAGLOWKI = {".docx": b"PK\x03\x04", ".xlsx": b"PK\x03\x04", ".pdf": b"%PDF-1.7\n",
             ".jpg": b"\xff\xd8\xff\xe0", ".txt": b""}


def _plik_wabikow() -> str:
    return os.path.join(silnik.katalog_danych(), "wabiki.json")


def foldery_wabikow_domyslne() -> list:
    dom = os.path.expanduser("~")
    kandydaci = []
    for n in ("Documents", "Dokumenty", "Desktop", "Pulpit", "Pictures", "Obrazy"):
        kandydaci.append(os.path.join(dom, n))
        kandydaci.append(os.path.join(dom, "OneDrive", n))
    wynik, widziane = [], set()
    for k in kandydaci:
        if os.path.isdir(k) and os.path.normcase(k) not in widziane:
            widziane.add(os.path.normcase(k))
            wynik.append(k)
    return wynik


def _ukryj(sciezka: str):
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(sciezka, 0x2)     # FILE_ATTRIBUTE_HIDDEN
        except Exception:
            pass


def wczytaj_wabiki() -> dict:
    try:
        with open(_plik_wabikow(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def zaloz_wabiki(foldery: list) -> dict:
    """Tworzy ukryte wabiki w folderach. Zwraca {sciezka: sha256}."""
    wabiki = wczytaj_wabiki()
    for folder in foldery:
        if not os.path.isdir(folder):
            continue
        for nazwa in WABIKI_NAZWY:
            sc = os.path.join(folder, nazwa)
            if sc in wabiki and os.path.isfile(sc):
                continue
            tresc = _NAGLOWKI[os.path.splitext(nazwa)[1]] + secrets.token_bytes(24 * 1024)
            if nazwa.endswith(".txt"):
                tresc = ("Plik-wabik programu Capsule. Nie zmieniaj go i nie usuwaj – "
                         "służy do wykrywania ransomware.\n").encode() * 200
            try:
                with open(sc, "wb") as f:
                    f.write(tresc)
                _ukryj(sc)
                wabiki[sc] = hashlib.sha256(tresc).hexdigest()
            except OSError:
                continue
    with open(_plik_wabikow(), "w", encoding="utf-8") as f:
        json.dump(wabiki, f, ensure_ascii=False, indent=1)
    return wabiki


def usun_wabiki() -> int:
    """Usuwa wszystkie wabiki z dysku i z rejestru. Zwraca liczbę usuniętych."""
    n = 0
    for sc in list(wczytaj_wabiki()):
        try:
            if os.name == "nt":      # zdejmij atrybut ukrycia, żeby os.remove nie miał problemu
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(sc, 0x80)
            os.remove(sc)
            n += 1
        except OSError:
            pass
    try:
        os.remove(_plik_wabikow())
    except OSError:
        pass
    return n


def znajdz_sprawcow(probka_s: float = 1.5, ile: int = 3) -> list:
    """Które procesy najwięcej zapisywały na dysk w ciągu probka_s sekund (Windows).

    Zwraca [{pid, nazwa, sciezka, zapisano_mb}] posortowane malejąco.
    """
    if os.name != "nt":
        return []
    skrypt = ("Get-CimInstance Win32_Process|Select-Object ProcessId,Name,ExecutablePath,"
              "@{n='W';e={[int64]$_.WriteTransferCount}}|ConvertTo-Json -Compress")

    def migawka():
        dane = silnik._powershell_json(skrypt, limit_s=30)
        if isinstance(dane, dict):
            dane = [dane]
        return {int(d["ProcessId"]): d for d in dane or []}

    pierwsza = migawka()
    import time
    time.sleep(probka_s)
    druga = migawka()
    wyniki = []
    for pid, d in druga.items():
        if pid in (0, 4, os.getpid()) or pid not in pierwsza:
            continue
        delta = int(d.get("W") or 0) - int(pierwsza[pid].get("W") or 0)
        if delta > 0:
            wyniki.append({"pid": pid, "nazwa": d.get("Name") or "?",
                           "sciezka": d.get("ExecutablePath") or "",
                           "zapisano_mb": round(delta / 1048576, 1)})
    wyniki.sort(key=lambda x: -x["zapisano_mb"])
    return wyniki[:ile]


class StrazWabikow:
    """Co ~1 s sprawdza wabiki. Przy naruszeniu woła zdarzenie('wabik', dane) w wątku tła."""

    def __init__(self, zdarzenie, interwal: float = 1.0):
        self.zdarzenie = zdarzenie
        self.interwal = interwal
        self._stop = threading.Event()
        self._watek = None
        self._stan = {}          # sciezka -> (mtime_ns, size)
        self._alarmy = set()     # wabiki, o których już alarmowaliśmy

    @property
    def dziala(self) -> bool:
        return self._watek is not None and self._watek.is_alive()

    def start(self):
        if self.dziala:
            return
        self._stop.clear()
        self._alarmy.clear()
        wabiki = wczytaj_wabiki()
        self._wzorce = wabiki
        self._stan = {}
        for sc in wabiki:
            try:
                st = os.stat(sc)
                self._stan[sc] = (st.st_mtime_ns, st.st_size)
            except OSError:
                pass
        self._watek = threading.Thread(target=self._petla, name="CapsuleWabiki", daemon=True)
        self._watek.start()

    def stop(self):
        self._stop.set()
        if self._watek is not None:
            self._watek.join(timeout=3)

    def liczba(self) -> int:
        return len(self._stan)

    def _petla(self):
        while not self._stop.wait(self.interwal):
            try:
                self._krok()
            except Exception:
                pass

    def _sprawdz_jeden(self, sc: str, sha: str):
        """Zwraca opis naruszenia albo None."""
        try:
            st = os.stat(sc)
        except OSError:
            return "wabik został usunięty lub przemianowany"
        if self._stan.get(sc) == (st.st_mtime_ns, st.st_size):
            return None
        try:
            with open(sc, "rb") as f:
                biezacy = hashlib.sha256(f.read()).hexdigest()
        except OSError:
            return None                # chwilowo zablokowany – sprawdzimy za sekundę
        self._stan[sc] = (st.st_mtime_ns, st.st_size)
        return None if biezacy == sha else "zawartość wabika została zmieniona (zaszyfrowana?)"

    def _krok(self):
        naruszone = []
        for sc, sha in self._wzorce.items():
            if sc in self._alarmy or sc not in self._stan:
                continue
            powod = self._sprawdz_jeden(sc, sha)
            if powod:
                self._alarmy.add(sc)
                naruszone.append({"sciezka": sc, "powod": powod})
        if naruszone:
            # jeden alarm na serię (ransomware rusza wiele wabików naraz)
            sprawcy = znajdz_sprawcow()
            self.zdarzenie("wabik", {"wabiki": naruszone, "sprawcy": sprawcy,
                                     "kiedy": _dt.datetime.now().strftime("%H:%M:%S")})
