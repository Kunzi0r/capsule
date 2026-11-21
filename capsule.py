# -*- coding: utf-8 -*-
"""
Capsule – skaner, kwarantanna i laboratorium analizy złośliwych plików.

Uruchomienie:   python capsule.py            (otwiera pulpit)
                python capsule.py plik.exe   (od razu analizuje wskazany plik)
                python capsule.py --ukryty   (start w tle, w zasobniku – tak startuje z Windows)
                python capsule.py --instaluj (tworzy skrót na pulpicie i w menu Start)

Wymaga tylko Pythona 3.10+ (tkinter jest w standardowej instalacji na Windows).
Program NIGDY nie uruchamia badanych plików – robi wyłącznie analizę statyczną.
"""

import os
import queue
import subprocess
import sys
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import capsule_engine as silnik
import capsule_dodatki as dodatki
import capsule_tray as tray

# --------------------------------------------------------------------------- wygląd
# Motyw „terminal”: czarne tło, zielona czcionka
TLO = "#000000"            # tło całej aplikacji
POLE = "#050805"           # tło tabel, pól tekstowych, kafelków
PANEL = "#020402"          # panel boczny
PANEL_AKTYWNY = "#0c2414"  # aktywna pozycja menu
RAMKA = "#0f5a2a"          # obramowania
ZIELONY = "#33ff66"        # główny kolor tekstu
ZIELONY_CIEMNY = "#1f9e44" # opisy, tekst drugoplanowy
ZAZNACZENIE = "#0f4d24"    # zaznaczony wiersz
AKCENT = "#0d3b1c"         # tło głównych przycisków
TEKST_JASNY = ZIELONY
# Zagrożenia nadal wyróżnione kolorem, żeby od razu rzucały się w oczy
KOLOR_WERDYKTU = {"ZŁOŚLIWY": "#ff4d4d", "PODEJRZANY": "#ffb000", "CZYSTY": ZIELONY}
CZCIONKA = ("Consolas", 10)
CZCIONKA_MONO = ("Consolas", 10)
POLE_PUSTE, POLE_ZAZNACZONE = "☐", "☑"


def _dt_teraz() -> str:
    import datetime as dt
    return dt.datetime.now().strftime(dodatki.FORMAT_CZASU)


def otworz_systemowo(sciezka: str):
    """Otwiera plik (np. raport HTML) lub folder w domyślnym programie."""
    if sys.platform.startswith("win"):
        os.startfile(sciezka)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", sciezka])
    else:
        subprocess.Popen(["xdg-open", sciezka])


class Kafelek(tk.Frame):
    def __init__(self, rodzic, tytul):
        super().__init__(rodzic, bg=POLE, highlightbackground=RAMKA,
                         highlightthickness=1, padx=16, pady=12)
        tk.Label(self, text=tytul.upper(), bg=POLE, fg=ZIELONY_CIEMNY, font=("Consolas", 9)).pack(anchor="w")
        self.wartosc = tk.Label(self, text="–", bg=POLE, fg=ZIELONY,
                                font=("Consolas", 20, "bold"))
        self.wartosc.pack(anchor="w")

    def ustaw(self, tekst, kolor=ZIELONY):
        self.wartosc.config(text=tekst, fg=kolor)


# =========================================================================== APLIKACJA
class Capsule(tk.Tk):
    def __init__(self, ukryty: bool = False):
        super().__init__()
        self._ustaw_ikone()
        self.title(f"Capsule {silnik.WERSJA} – laboratorium bezpieczeństwa")
        self.geometry("1180x740")
        self.minsize(980, 620)
        self.configure(bg=TLO)
        self.kolejka: "queue.Queue" = queue.Queue()
        self.ustawienia = silnik.wczytaj_ustawienia()
        self.straznik = None
        self.zatrzymywanie = False
        self.toasty = []
        self.zasobnik = None
        self.instancja = None
        self.straz_wabikow = None
        self.ostrzezono_o_tle = False
        self.ostatni_alarm_wabika = None

        styl = ttk.Style(self)
        styl.theme_use("clam")
        styl.configure(".", font=CZCIONKA, background=TLO, foreground=ZIELONY,
                       bordercolor=RAMKA, lightcolor=RAMKA, darkcolor=RAMKA,
                       troughcolor=POLE, focuscolor=ZIELONY, insertcolor=ZIELONY,
                       selectbackground=ZAZNACZENIE, selectforeground=ZIELONY)
        styl.configure("TFrame", background=TLO)
        styl.configure("TLabel", background=TLO, foreground=ZIELONY)
        styl.configure("Treeview", rowheight=26, font=CZCIONKA, background=POLE,
                       fieldbackground=POLE, foreground=ZIELONY, bordercolor=RAMKA)
        styl.map("Treeview", background=[("selected", ZAZNACZENIE)],
                 foreground=[("selected", ZIELONY)])
        styl.configure("Treeview.Heading", font=("Consolas", 10, "bold"), background="#0a1a0f",
                       foreground=ZIELONY, relief="flat")
        styl.map("Treeview.Heading", background=[("active", PANEL_AKTYWNY)])
        styl.configure("TButton", padding=(12, 6), background="#0a140c", foreground=ZIELONY,
                       bordercolor=RAMKA)
        styl.map("TButton", background=[("disabled", TLO), ("active", PANEL_AKTYWNY)],
                 foreground=[("disabled", "#1a4d2a")])
        styl.configure("Akcent.TButton", foreground=ZIELONY, background=AKCENT, padding=(14, 7))
        styl.map("Akcent.TButton", background=[("disabled", TLO), ("active", "#15592b")],
                 foreground=[("disabled", "#1a4d2a")])
        styl.configure("TNotebook", background=TLO, bordercolor=RAMKA)
        styl.configure("TNotebook.Tab", padding=(14, 6), background="#0a140c", foreground=ZIELONY_CIEMNY)
        styl.map("TNotebook.Tab", background=[("selected", PANEL_AKTYWNY)],
                 foreground=[("selected", ZIELONY)])
        styl.configure("TEntry", fieldbackground=POLE, foreground=ZIELONY, insertcolor=ZIELONY)
        styl.configure("Vertical.TScrollbar", background="#0a1a0f", troughcolor=TLO,
                       arrowcolor=ZIELONY, bordercolor=RAMKA)
        styl.configure("Horizontal.TProgressbar", background=ZIELONY, troughcolor=POLE,
                       bordercolor=RAMKA)
        styl.configure("Naglowek.TLabel", font=("Consolas", 18, "bold"), background=TLO,
                       foreground=ZIELONY)
        styl.configure("Opis.TLabel", foreground=ZIELONY_CIEMNY, background=TLO)
        # okna dialogowe (wybór pliku, listy) też w ciemnym stylu
        self.option_add("*Background", TLO)
        self.option_add("*Foreground", ZIELONY)
        self.option_add("*selectBackground", ZAZNACZENIE)
        self.option_add("*selectForeground", ZIELONY)
        self.option_add("*insertBackground", ZIELONY)
        self.option_add("*TCombobox*Listbox.background", POLE)

        self._buduj_panel_boczny()
        self.obszar = tk.Frame(self, bg=TLO)
        self.obszar.pack(side="left", fill="both", expand=True)

        self.strony = {
            "pulpit": StronaPulpit(self.obszar, self),
            "ochrona": StronaOchrona(self.obszar, self),
            "system": StronaSystem(self.obszar, self),
            "ustawienia": StronaUstawienia(self.obszar, self),
            "skaner": StronaSkaner(self.obszar, self),
            "kwarantanna": StronaKwarantanna(self.obszar, self),
            "laboratorium": StronaLaboratorium(self.obszar, self),
            "raporty": StronaRaporty(self.obszar, self),
        }
        self.pokaz("pulpit")
        self.after(100, self._obsluz_kolejke)
        self.protocol("WM_DELETE_WINDOW", self._zamknij)
        self._uruchom_zasobnik()
        self.bind("<Unmap>", self._po_unmap)
        if self.ustawienia["straznik_wlaczony"]:
            self.after(600, lambda: self.ustaw_straznika(True))
        if self.ustawienia["wabiki"]:
            self.after(900, lambda: self.ustaw_wabiki(True, cicho=True))
        self.after(15000, self._tik_harmonogramu)
        if ukryty:
            self.after(50, self.ukryj if self.zasobnik else self.iconify)

    # ---------------------------------------------------------------- nawigacja
    def _buduj_panel_boczny(self):
        panel = tk.Frame(self, bg=PANEL, width=210, highlightbackground=RAMKA,
                         highlightthickness=1)
        panel.pack(side="left", fill="y")
        panel.pack_propagate(False)
        tk.Label(panel, text="◉ CAPSULE", bg=PANEL, fg=ZIELONY,
                 font=("Consolas", 18, "bold")).pack(anchor="w", padx=20, pady=(22, 2))
        tk.Label(panel, text="> skaner · kwarantanna · lab_", bg=PANEL, fg=ZIELONY_CIEMNY,
                 font=("Consolas", 9)).pack(anchor="w", padx=20, pady=(0, 24))
        self.przyciski_nav = {}
        for klucz, etykieta in (("pulpit", "🏠  Pulpit"), ("ochrona", "🛡  Ochrona"),
                                ("system", "⚙  System"), ("skaner", "🔍  Skaner"),
                                ("kwarantanna", "📦  Kwarantanna"),
                                ("laboratorium", "🔬  Laboratorium"), ("raporty", "📄  Raporty"),
                                ("ustawienia", "🔧  Ustawienia")):
            b = tk.Label(panel, text=etykieta, bg=PANEL, fg=TEKST_JASNY, anchor="w",
                         font=("Consolas", 11), padx=20, pady=10, cursor="hand2")
            b.pack(fill="x")
            b.bind("<Button-1>", lambda e, k=klucz: self.pokaz(k))
            self.przyciski_nav[klucz] = b
        tk.Label(panel, text="Pliki NIE są uruchamiane.\nTylko analiza statyczna.",
                 bg=PANEL, fg=ZIELONY_CIEMNY, font=("Consolas", 8), justify="left"
                 ).pack(side="bottom", anchor="w", padx=20, pady=16)

    def pokaz(self, klucz):
        for k, s in self.strony.items():
            s.pack_forget()
            self.przyciski_nav[k].config(bg=PANEL)
        self.przyciski_nav[klucz].config(bg=PANEL_AKTYWNY)
        strona = self.strony[klucz]
        strona.pack(fill="both", expand=True, padx=24, pady=20)
        if hasattr(strona, "odswiez"):
            strona.odswiez()

    # ------------------------------------------------- komunikacja z wątkami
    def w_tle(self, funkcja, *argumenty, gotowe=None, blad=None):
        """Uruchamia funkcję w osobnym wątku, wynik oddaje do GUI przez kolejkę."""
        def praca():
            try:
                wynik = funkcja(*argumenty)
                if gotowe:
                    self.kolejka.put((gotowe, (wynik,)))
            except Exception as e:  # noqa: BLE001
                self.kolejka.put((blad or self._pokaz_blad, (e,)))
        threading.Thread(target=praca, daemon=True).start()

    def _pokaz_blad(self, e):
        messagebox.showerror("Capsule", str(e))

    def _obsluz_kolejke(self):
        try:
            while True:
                funkcja, argumenty = self.kolejka.get_nowait()
                funkcja(*argumenty)
        except queue.Empty:
            pass
        self.after(100, self._obsluz_kolejke)

    # ------------------------------------------------------ wspólne akcje
    def analizuj_plik(self, sciezka=None):
        if not sciezka:
            sciezka = filedialog.askopenfilename(title="Wybierz plik do analizy")
            if not sciezka:
                return
        self.pokaz("laboratorium")
        self.strony["laboratorium"].zbadaj_plik(sciezka)

    def analizuj_z_kwarantanny(self, ident):
        self.pokaz("laboratorium")
        self.strony["laboratorium"].zbadaj_kwarantanne(ident)

    # --------------------------------------------- ikona, zasobnik, praca w tle
    def _ustaw_ikone(self):
        """Ikona okna i paska zadań (Windows). Bez pliku .ico zostaje domyślna."""
        if os.name != "nt":
            return
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Capsule.Security.Lab")
        except Exception:
            pass
        ico = dodatki.sciezka_ikony()
        if ico:
            try:
                self.iconbitmap(default=ico)
            except tk.TclError:
                pass

    def _uruchom_zasobnik(self):
        if not tray.dostepny():
            return
        try:
            do_kolejki = lambda f: (lambda: self.kolejka.put((f, ())))
            self.zasobnik = tray.Zasobnik(
                f"Capsule {silnik.WERSJA}", otworz=do_kolejki(self.pokaz_okno),
                przelacz_straznika=do_kolejki(self.przelacz_straznika),
                szybki_skan=do_kolejki(self.skan_z_zasobnika),
                zamknij=do_kolejki(self._zamknij_calkowicie),
                straznik_dziala=self.straznik_dziala)
            self.zasobnik.start()
        except Exception:  # noqa: BLE001  – bez zasobnika program działa jak dotąd
            self.zasobnik = None

    def okno_widoczne(self) -> bool:
        return self.state() not in ("withdrawn", "iconic")

    def ukryj(self):
        self.withdraw()

    def pokaz_okno(self, sciezka=None):
        self.deiconify()
        self.lift()
        self.focus_force()
        if self.zasobnik:
            self.zasobnik.ustaw_alarm(False)
        if sciezka and os.path.isfile(sciezka):
            self.analizuj_plik(sciezka)

    def _po_unmap(self, e):
        # minimalizacja = schowanie do zasobnika (program pracuje dalej)
        if e.widget is self and self.zasobnik and self.state() == "iconic":
            self.after(50, self.ukryj)

    def skan_z_zasobnika(self):
        foldery = silnik.foldery_szybkiego_skanu()
        if foldery and not self.strony["skaner"].trwa:
            self.strony["skaner"].start(foldery, zaplanowany=True)

    def komunikat(self, tytul, tekst, kolor, akcja=None):
        """Okienko w rogu ekranu, a gdy program jest schowany – powiadomienie z zasobnika."""
        if self.okno_widoczne():
            self.powiadom(tytul, tekst, kolor, akcja)
        elif self.zasobnik:
            self.zasobnik.powiadom(tytul, tekst)
            self.zasobnik.ustaw_alarm(True)
        else:
            self.powiadom(tytul, tekst, kolor, akcja)

    # --------------------------------------------------------- skany zaplanowane
    def _tik_harmonogramu(self):
        try:
            u = self.ustawienia
            if dodatki.czy_pora_na_aktualizacje(u):
                self.aktualizuj_sygnatury(cicho=True)
            if dodatki.czy_pora_na_skan(u) and not self.strony["skaner"].trwa:
                u["skan_ostatni"] = _dt_teraz()
                self.zapisz_ustawienia()
                foldery = silnik.foldery_szybkiego_skanu()
                if foldery:
                    silnik.zapisz_zdarzenie("Skan zaplanowany: start")
                    self.strony["skaner"].start(foldery, zaplanowany=True)
        finally:
            self.after(60000, self._tik_harmonogramu)

    def po_skanie(self, wykryto: int, zaplanowany: bool):
        if not zaplanowany:
            return
        if wykryto:
            self.komunikat("⚠ Skan zakończony", f"Znaleziono podejrzanych plików: {wykryto}. "
                           "Kliknij, aby otworzyć Skaner.", KOLOR_WERDYKTU["PODEJRZANY"],
                           lambda: self.pokaz("skaner"))

    def aktualizuj_sygnatury(self, cicho=False):
        klucz = self.ustawienia["abusech_klucz"]
        if not klucz:
            if not cicho:
                messagebox.showinfo("Capsule", "Wpisz najpierw Auth-Key z auth.abuse.ch "
                                    "(Ustawienia → Integracje).")
            return

        def gotowe(wynik):
            self.ustawienia["aktualizacja_ostatnia"] = _dt_teraz()
            self.zapisz_ustawienia()
            self.strony["ustawienia"].po_aktualizacji(wynik)

        self.ustawienia["aktualizacja_ostatnia"] = _dt_teraz()      # nie ponawiaj co minutę przy błędzie
        self.w_tle(lambda: dodatki.aktualizuj_sygnatury(klucz), gotowe=gotowe,
                   blad=lambda e: self.strony["ustawienia"].po_aktualizacji(
                       {"hashe": 0, "adresy": 0, "bledy": [str(e)]}))

    # ------------------------------------------------------ pułapka na ransomware
    def ustaw_wabiki(self, wlacz: bool, cicho: bool = False) -> bool:
        if wlacz and not (self.straz_wabikow and self.straz_wabikow.dziala):
            foldery = self.ustawienia["wabiki_foldery"] or dodatki.foldery_wabikow_domyslne()
            if not foldery:
                if not cicho:
                    messagebox.showinfo("Capsule", "Nie znaleziono folderów Dokumenty/Pulpit/Obrazy. "
                                        "Dodaj własny folder.")
                return False
            try:
                dodatki.zaloz_wabiki(foldery)
            except OSError as e:
                messagebox.showerror("Capsule", f"Nie udało się założyć wabików: {e}")
                return False
            self.straz_wabikow = dodatki.StrazWabikow(
                lambda r, d: self.kolejka.put((self._zdarzenie_wabika, (r, d))))
            self.straz_wabikow.start()
            silnik.zapisz_zdarzenie(f"Pułapka na ransomware włączona ({self.straz_wabikow.liczba()} wabików)")
        elif not wlacz and self.straz_wabikow:
            self.straz_wabikow.stop()
            self.straz_wabikow = None
            silnik.zapisz_zdarzenie("Pułapka na ransomware wyłączona")
        self.ustawienia["wabiki"] = wlacz
        self.zapisz_ustawienia()
        self.strony["ustawienia"].odswiez_wabiki()
        return True

    def _zdarzenie_wabika(self, rodzaj, dane):
        if rodzaj != "wabik":
            return
        self.ostatni_alarm_wabika = dane
        sprawcy = dane.get("sprawcy") or []
        nazwy = ", ".join(f"{s['nazwa']} ({s['zapisano_mb']} MB)" for s in sprawcy) or "nie ustalono"
        silnik.zapisz_zdarzenie(f"ALARM RANSOMWARE: zmieniono wabiki ({len(dane['wabiki'])}). "
                                f"Podejrzane procesy: {nazwy}")
        uwaga = ""
        if self.ustawienia["wabiki_auto_zabij"] and sprawcy:
            s = sprawcy[0]
            try:
                silnik.zakoncz_proces(s["pid"], s["nazwa"])
                uwaga = f" Zakończono proces {s['nazwa']}."
            except Exception as e:  # noqa: BLE001
                uwaga = f" Nie udało się zakończyć {s['nazwa']}: {e}"
        self.strony["ochrona"].dodaj_alarm_wabika(dane, nazwy)
        self.strony["ustawienia"].pokaz_alarm_wabika(dane)
        self.komunikat("⛔ MOŻLIWY RANSOMWARE", f"Ktoś zmienia pliki-wabiki ({len(dane['wabiki'])}). "
                       f"Podejrzane procesy: {nazwy}.{uwaga} Odłącz komputer od sieci, jeśli to nie ty.",
                       KOLOR_WERDYKTU["ZŁOŚLIWY"],
                       lambda: (self.pokaz("ustawienia"), self.strony["ustawienia"].zakladki.select(2)))

    def _zamknij_calkowicie(self):
        """Pełne zamknięcie (np. z menu zasobnika): zatrzymuje Strażnika, pułapkę i ikonę."""
        if self.straznik is not None:
            self.straznik.stop(czekaj=False)
        if self.straz_wabikow is not None:
            self.straz_wabikow.stop()
        if self.zasobnik:
            self.zasobnik.stop()
        if self.instancja:
            self.instancja.zamknij()
        self.destroy()

    # ------------------------------------------------------------ Strażnik
    def straznik_dziala(self) -> bool:
        return self.straznik is not None and self.straznik.aktywny

    def zapisz_ustawienia(self):
        try:
            silnik.zapisz_ustawienia(self.ustawienia)
        except OSError:
            pass

    def przelacz_straznika(self):
        self.ustaw_straznika(not self.straznik_dziala())

    def ustaw_straznika(self, wlacz: bool):
        if self.zatrzymywanie:
            return
        if wlacz and not self.straznik_dziala():
            foldery = self.ustawienia["foldery"] or silnik.foldery_szybkiego_skanu()
            if not foldery:
                messagebox.showinfo("Capsule", "Nie ma żadnego folderu do obserwowania. "
                                    "Dodaj folder na stronie Ochrona.")
                return
            self.straznik = silnik.Straznik(
                foldery, zdarzenie=self._z_watku,
                auto_kwarantanna=self.ustawienia["auto_kwarantanna"],
                uzyj_defendera=self.ustawienia["uzyj_defendera"],
                vt_klucz=self._klucz_vt_dla_straznika())
            self.straznik.start()
        elif not wlacz and self.straznik_dziala():
            self.zatrzymywanie = True      # stop() czeka na wątek, więc robimy to w tle
            self.w_tle(self.straznik.stop, False)
        self.ustawienia["straznik_wlaczony"] = wlacz
        self.zapisz_ustawienia()
        self.odswiez_straznika()

    def _klucz_vt_dla_straznika(self) -> str:
        return self.ustawienia["vt_klucz"] if self.ustawienia["vt_straznik"] else ""

    def zastosuj_opcje_straznika(self):
        """Zmiana opcji w Ustawieniach działa od razu, bez restartu Strażnika."""
        if self.straznik is not None:
            self.straznik.vt_klucz = self._klucz_vt_dla_straznika()

    def _z_watku(self, rodzaj, dane):
        """Wywoływane z wątku Strażnika – oddaje zdarzenie oknu przez kolejkę."""
        self.kolejka.put((self._zdarzenie_straznika, (rodzaj, dane)))

    def odswiez_straznika(self):
        for s in self.strony.values():
            if hasattr(s, "odswiez_straznika"):
                s.odswiez_straznika()

    def _zdarzenie_straznika(self, rodzaj, dane):
        if rodzaj == "start":
            silnik.zapisz_zdarzenie(f"Strażnik włączony (obserwowane foldery: {len(dane['foldery'])})")
        elif rodzaj == "stop":
            self.zatrzymywanie = False
            silnik.zapisz_zdarzenie("Strażnik wyłączony")
        elif rodzaj == "wykrycie":
            self.strony["ochrona"].dodaj_wykrycie(dane)
            if self.ustawienia["powiadomienia"]:
                self._alarm(dane)
        elif rodzaj == "blad":
            self.strony["ochrona"].pokaz_blad(dane["tekst"])
        self.odswiez_straznika()

    def _alarm(self, w):
        w_kwar = bool(w.get("id_kwarantanny"))
        tytul = f"{'⛔' if w['werdykt'] == 'ZŁOŚLIWY' else '⚠'} {w['werdykt']}: {w['nazwa']}"
        tekst = ("Zamknięto w kwarantannie. " if w_kwar else "Plik leży na dysku – nie uruchamiaj go. ")
        d = w.get("defender") or {}
        if d.get("status") == "zagrozenie":
            tekst += f"Defender też: {d['nazwa']}. "
        vt = w.get("vt") or {}
        if vt.get("status") == "znany" and vt["zlosliwe"]:
            tekst += f"VirusTotal: {vt['zlosliwe']}/{vt['razem']}. "
        tekst += f"Punkty: {w['punkty']}/100."
        akcja = ((lambda: self.analizuj_z_kwarantanny(w["id_kwarantanny"])) if w_kwar
                 else (lambda: self.analizuj_plik(w["sciezka"])))
        self.komunikat(tytul, tekst, KOLOR_WERDYKTU.get(w["werdykt"], ZIELONY), akcja)

    def powiadom(self, tytul, tekst, kolor, akcja=None):
        """Małe okienko w rogu ekranu (bez zewnętrznych bibliotek). Klik = zbadaj."""
        self.toasty = [t for t in self.toasty if t.winfo_exists()]
        while len(self.toasty) >= 3:
            self.toasty.pop(0).destroy()
        t = tk.Toplevel(self, bg=TLO, highlightbackground=kolor, highlightcolor=kolor,
                        highlightthickness=2)
        t.overrideredirect(True)
        t.attributes("-topmost", True)
        pola = [
            tk.Label(t, text=tytul, bg=TLO, fg=kolor, font=("Consolas", 11, "bold"),
                     anchor="w", justify="left", wraplength=350),
            tk.Label(t, text=tekst, bg=TLO, fg=ZIELONY, font=CZCIONKA, anchor="w",
                     justify="left", wraplength=350),
            tk.Label(t, text="kliknij, aby zbadać w laboratorium", bg=TLO, fg=ZIELONY_CIEMNY,
                     font=("Consolas", 8), anchor="w"),
        ]
        for p in pola:
            p.pack(fill="x", padx=14, pady=(8 if p is pola[0] else 2, 8 if p is pola[-1] else 0))

        def kliknij(_e=None):
            self._zamknij_toast(t)
            if akcja:
                self.deiconify()
                self.lift()
                akcja()

        for el in (t, *pola):
            el.bind("<Button-1>", kliknij)
        self.toasty.append(t)
        self._uloz_toasty()
        try:
            self.bell()
        except tk.TclError:
            pass
        t.after(15000, lambda: self._zamknij_toast(t))

    def _zamknij_toast(self, t):
        if t.winfo_exists():
            t.destroy()
        self.toasty = [x for x in self.toasty if x.winfo_exists()]
        self._uloz_toasty()

    def _uloz_toasty(self):
        szer = 380
        y = self.winfo_screenheight() - 80
        for t in reversed(self.toasty):
            t.update_idletasks()
            h = t.winfo_reqheight()
            y -= h + 10
            t.geometry(f"{szer}x{h}+{self.winfo_screenwidth() - szer - 20}+{y}")

    def _zamknij(self):
        if self.zasobnik and self.ustawienia["tray_zamykanie"]:
            self.ukryj()                       # X chowa program do zasobnika – pracuje dalej
            if not self.ostrzezono_o_tle:
                self.ostrzezono_o_tle = True
                self.zasobnik.powiadom("Capsule działa w tle",
                                       "Ikona jest przy zegarze. Kliknij ją, aby otworzyć okno; "
                                       "prawy przycisk → Zamknij Capsule, aby wyłączyć program.")
            return
        if self.straznik_dziala():
            if not messagebox.askyesno(
                    "Capsule", "Strażnik jest włączony.\nPo zamknięciu okna przestanie pilnować "
                               "folderów (włączy się sam przy następnym uruchomieniu).\n\nZamknąć?"):
                return
            self.straznik.stop(czekaj=False)
        self._zamknij_calkowicie()


def naglowek(rodzic, tytul, opis):
    ttk.Label(rodzic, text=tytul, style="Naglowek.TLabel").pack(anchor="w")
    ttk.Label(rodzic, text=opis, style="Opis.TLabel").pack(anchor="w", pady=(0, 14))


def tabela(rodzic, kolumny, szerokosci, wysokosc=14, pola_wyboru=False, po_zmianie=None):
    """Tabela w stylu terminala. pola_wyboru=True dodaje kwadraciki ☐/☑ w 1. kolumnie."""
    ramka = tk.Frame(rodzic, bg=TLO, highlightbackground=RAMKA, highlightthickness=1)
    drzewo = ttk.Treeview(ramka, columns=kolumny, height=wysokosc,
                          show="tree headings" if pola_wyboru else "headings")
    drzewo.po_zmianie = po_zmianie
    if pola_wyboru:
        drzewo.column("#0", width=48, minwidth=48, stretch=False, anchor="center")
        drzewo.heading("#0", text=POLE_PUSTE, command=lambda: przelacz_wszystkie(drzewo))
        drzewo.bind("<Button-1>", lambda e: _klik_pola(drzewo, e))
        drzewo.bind("<space>", lambda e: [przelacz_pole(drzewo, i) for i in drzewo.selection()] and "break")
    for k, s in zip(kolumny, szerokosci):
        drzewo.heading(k, text=k, anchor="w")      # nagłówek przy lewej krawędzi, jak wartości
        drzewo.column(k, width=s, stretch=(s >= 250), anchor="w")
    przewijak = ttk.Scrollbar(ramka, orient="vertical", command=drzewo.yview)
    drzewo.configure(yscrollcommand=przewijak.set)
    drzewo.pack(side="left", fill="both", expand=True)
    przewijak.pack(side="right", fill="y")
    for werdykt, kolor in KOLOR_WERDYKTU.items():
        drzewo.tag_configure(werdykt, foreground=kolor)
    return ramka, drzewo


# ------------------------------------------------------------- kwadraciki ☐ / ☑
def wstaw_wiersz(drzewo, values, tags=(), iid=None, zaznaczony=False):
    return drzewo.insert("", "end", iid=iid, values=values, tags=tags,
                         text=POLE_ZAZNACZONE if zaznaczony else POLE_PUSTE)


def czy_zaznaczony(drzewo, iid):
    return drzewo.item(iid, "text") == POLE_ZAZNACZONE


def zaznaczone(drzewo):
    return [i for i in drzewo.get_children() if czy_zaznaczony(drzewo, i)]


def ustaw_pole(drzewo, iid, stan):
    drzewo.item(iid, text=POLE_ZAZNACZONE if stan else POLE_PUSTE)


def _po_zmianie(drzewo):
    wiersze = drzewo.get_children()
    wszystkie = bool(wiersze) and all(czy_zaznaczony(drzewo, i) for i in wiersze)
    drzewo.heading("#0", text=POLE_ZAZNACZONE if wszystkie else POLE_PUSTE)
    if drzewo.po_zmianie:
        drzewo.po_zmianie()


def przelacz_pole(drzewo, iid):
    ustaw_pole(drzewo, iid, not czy_zaznaczony(drzewo, iid))
    _po_zmianie(drzewo)


def ustaw_wszystkie(drzewo, stan, warunek=None):
    for i in drzewo.get_children():
        if warunek is None or warunek(i):
            ustaw_pole(drzewo, i, stan)
    _po_zmianie(drzewo)


def przelacz_wszystkie(drzewo):
    wiersze = drzewo.get_children()
    ustaw_wszystkie(drzewo, not (wiersze and all(czy_zaznaczony(drzewo, i) for i in wiersze)))


def _klik_pola(drzewo, e):
    """Kliknięcie w kwadracik przełącza go (bez zmiany zaznaczenia wiersza)."""
    if drzewo.identify_region(e.x, e.y) == "tree" or drzewo.identify_column(e.x) == "#0":
        iid = drzewo.identify_row(e.y)
        if iid:
            przelacz_pole(drzewo, iid)
            return "break"
    return None


def baner(rodzic, rozmiar):
    lbl = tk.Label(rodzic, text="", bg=POLE, fg=ZIELONY, font=("Consolas", rozmiar, "bold"),
                   anchor="w", padx=18, pady=14, highlightthickness=2, highlightbackground=RAMKA)
    lbl.pack(fill="x", pady=(0, 16))
    return lbl


def ustaw_baner(lbl, tekst, kolor):
    lbl.config(text=tekst, fg=kolor, highlightbackground=kolor, highlightcolor=kolor)


def pole_tekstowe(rodzic, mono=False):
    ramka = tk.Frame(rodzic, bg=POLE, highlightbackground=RAMKA, highlightthickness=1)
    t = tk.Text(ramka, wrap="word" if not mono else "none", relief="flat", padx=12, pady=10,
                font=CZCIONKA_MONO if mono else ("Consolas", 11), bg=POLE, fg=ZIELONY,
                insertbackground=ZIELONY, selectbackground=ZAZNACZENIE,
                selectforeground=ZIELONY, highlightthickness=0)
    przew = ttk.Scrollbar(ramka, orient="vertical", command=t.yview)
    t.configure(yscrollcommand=przew.set)
    przew.pack(side="right", fill="y")
    t.pack(side="left", fill="both", expand=True)
    return ramka, t


def ustaw_tekst(pole, tekst):
    pole.config(state="normal")
    pole.delete("1.0", "end")
    pole.insert("1.0", tekst)
    pole.config(state="disabled")


# =========================================================================== PULPIT
class StronaPulpit(tk.Frame):
    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        naglowek(self, "Pulpit", "Stan ochrony i szybkie akcje")

        self.baner = baner(self, 14)

        kafelki = tk.Frame(self, bg=TLO)
        kafelki.pack(fill="x")
        self.k_skan = Kafelek(kafelki, "Ostatni skan")
        self.k_pliki = Kafelek(kafelki, "Sprawdzonych plików")
        self.k_wykryte = Kafelek(kafelki, "Wykryte zagrożenia")
        self.k_kwar = Kafelek(kafelki, "W kwarantannie")
        self.k_straznik = Kafelek(kafelki, "Strażnik")
        for i, k in enumerate((self.k_skan, self.k_pliki, self.k_wykryte, self.k_kwar,
                               self.k_straznik)):
            k.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            kafelki.columnconfigure(i, weight=1)

        akcje = tk.Frame(self, bg=TLO)
        akcje.pack(fill="x", pady=18)
        self.b_straznik = ttk.Button(akcje, text="🛡 Włącz Strażnika", style="Akcent.TButton",
                                     command=app.przelacz_straznika)
        self.b_straznik.pack(side="left")
        ttk.Button(akcje, text="⚡ Szybki skan",
                   command=lambda: (app.pokaz("skaner"), app.strony["skaner"].szybki())
                   ).pack(side="left", padx=10)
        ttk.Button(akcje, text="📁 Skanuj folder…",
                   command=lambda: (app.pokaz("skaner"), app.strony["skaner"].wybierz_folder())
                   ).pack(side="left")
        ttk.Button(akcje, text="🔬 Rozłóż plik na czynniki pierwsze…",
                   command=app.analizuj_plik).pack(side="left", padx=10)
        ttk.Button(akcje, text="🔄 Odśwież", command=self.odswiez).pack(side="right")
        ttk.Button(akcje, text="🧹 Wyzeruj liczniki", command=self.wyzeruj).pack(side="right", padx=10)

        ttk.Label(self, text="> HISTORIA ZDARZEŃ", font=("Consolas", 11, "bold")).pack(anchor="w")
        ramka, self.historia = tabela(self, ("Kiedy", "Zdarzenie"), (150, 700), wysokosc=10)
        ramka.pack(fill="both", expand=True, pady=(6, 0))

    def wyzeruj(self):
        silnik.zeruj_liczniki()
        self.odswiez()

    def odswiez(self):
        stan = silnik.wczytaj_stan()
        kwar = silnik.lista_kwarantanny()
        self.k_skan.ustaw(stan.get("ostatni_skan") or "nigdy")
        self.k_pliki.ustaw(str(stan.get("przeskanowano", 0)))
        wykr = stan.get("wykryto", 0)
        self.k_wykryte.ustaw(str(wykr), KOLOR_WERDYKTU["ZŁOŚLIWY"] if wykr else ZIELONY)
        self.k_kwar.ustaw(str(len(kwar)))
        if not stan.get("ostatni_skan"):
            ustaw_baner(self.baner, "ℹ  Nie wykonano jeszcze żadnego skanu – zacznij od szybkiego skanu.",
                        ZIELONY_CIEMNY)
        elif wykr:
            ustaw_baner(self.baner, f"⚠  Ostatni skan znalazł {wykr} podejrzanych plików – sprawdź Skaner.",
                        KOLOR_WERDYKTU["PODEJRZANY"])
        else:
            ustaw_baner(self.baner, "✔  Ostatni skan nie wykrył zagrożeń.", KOLOR_WERDYKTU["CZYSTY"])
        self.historia.delete(*self.historia.get_children())
        for kiedy, co in reversed(stan.get("zdarzenia", [])[-50:]):
            self.historia.insert("", "end", values=(kiedy, co))
        self.odswiez_straznika()

    def odswiez_straznika(self):
        if self.app.zatrzymywanie:
            self.k_straznik.ustaw("wyłączanie…", ZIELONY_CIEMNY)
            self.b_straznik.config(state="disabled")
        elif self.app.straznik_dziala():
            self.k_straznik.ustaw("WŁĄCZONY", KOLOR_WERDYKTU["CZYSTY"])
            self.b_straznik.config(text="■ Wyłącz Strażnika", state="normal")
        else:
            self.k_straznik.ustaw("wyłączony", KOLOR_WERDYKTU["PODEJRZANY"])
            self.b_straznik.config(text="🛡 Włącz Strażnika", state="normal")


# =========================================================================== OCHRONA
def przelacznik(rodzic, tekst, zmienna, komenda):
    """Pole wyboru w motywie terminala."""
    return tk.Checkbutton(rodzic, text=tekst, variable=zmienna, command=komenda, bg=TLO,
                          fg=ZIELONY, activebackground=TLO, activeforeground=ZIELONY,
                          selectcolor=POLE, font=CZCIONKA, anchor="w", highlightthickness=0,
                          bd=0, cursor="hand2")


class StronaOchrona(tk.Frame):
    """Strażnik (obserwacja folderów) + współpraca z Microsoft Defenderem."""

    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        self.wyniki = {}
        self.def_zaladowano = False
        self.def_historia = []
        naglowek(self, "Ochrona", "Strażnik pilnuje folderów i sprawdza każdy nowy plik – "
                                  "obok Microsoft Defendera, nie zamiast niego")

        self.baner = baner(self, 13)
        pasek = tk.Frame(self, bg=TLO)
        pasek.pack(fill="x")
        self.b_straznik = ttk.Button(pasek, text="🛡 Włącz Strażnika", style="Akcent.TButton",
                                     command=app.przelacz_straznika)
        self.b_straznik.pack(side="left")
        self.l_liczniki = ttk.Label(pasek, text="", style="Opis.TLabel")
        self.l_liczniki.pack(side="right")

        u = app.ustawienia
        self.v_auto = tk.BooleanVar(value=u["auto_kwarantanna"])
        self.v_def = tk.BooleanVar(value=u["uzyj_defendera"])
        self.v_pow = tk.BooleanVar(value=u["powiadomienia"])
        opcje = tk.Frame(self, bg=TLO)
        opcje.pack(fill="x", pady=(12, 4))
        przelacznik(opcje, "Złośliwe pliki zamykaj w kwarantannie automatycznie",
                    self.v_auto, self._zmien_opcje).pack(anchor="w")
        przelacznik(opcje, "Podejrzane pliki sprawdzaj też w Microsoft Defenderze",
                    self.v_def, self._zmien_opcje).pack(anchor="w")
        przelacznik(opcje, "Pokazuj okienko z powiadomieniem",
                    self.v_pow, self._zmien_opcje).pack(anchor="w")

        folderki = tk.Frame(self, bg=TLO)
        folderki.pack(fill="x", pady=(6, 10))
        self.l_foldery = ttk.Label(folderki, text="", style="Opis.TLabel", wraplength=720,
                                   justify="left")
        self.l_foldery.pack(side="left", fill="x", expand=True)
        ttk.Button(folderki, text="➕ Dodaj folder…", command=self.dodaj_folder).pack(side="right")
        ttk.Button(folderki, text="↺ Domyślne", command=self.domyslne_foldery).pack(side="right", padx=8)

        self.zakladki = ttk.Notebook(self)
        self.zakladki.pack(fill="both", expand=True)

        # ---- zakładka 1: wykrycia Strażnika
        ramka1 = tk.Frame(self.zakladki, bg=TLO)
        wybor = tk.Frame(ramka1, bg=TLO)
        wybor.pack(fill="x", pady=(6, 6))
        ttk.Button(wybor, text="☑ Zaznacz wszystkie",
                   command=lambda: ustaw_wszystkie(self.drzewo, True)).pack(side="left")
        ttk.Button(wybor, text="☐ Odznacz wszystkie",
                   command=lambda: ustaw_wszystkie(self.drzewo, False)).pack(side="left", padx=8)
        self.l_zazn = ttk.Label(wybor, text="", style="Opis.TLabel")
        self.l_zazn.pack(side="right")
        ramka, self.drzewo = tabela(ramka1, ("Czas", "Werdykt", "Plik", "Defender", "Gdzie jest"),
                                    (90, 100, 250, 330, 150), pola_wyboru=True,
                                    po_zmianie=self._licz_zaznaczone)
        ramka.pack(fill="both", expand=True)
        self.drzewo.bind("<Double-1>", lambda e: self.do_laboratorium())
        dol = tk.Frame(ramka1, bg=TLO)
        dol.pack(fill="x", pady=(8, 4))
        ttk.Button(dol, text="🔬 Zbadaj w laboratorium", command=self.do_laboratorium).pack(side="left")
        ttk.Button(dol, text="📦 Zaznaczone do kwarantanny", style="Akcent.TButton",
                   command=self.zaznaczone_do_kwarantanny).pack(side="left", padx=8)
        self.zakladki.add(ramka1, text="Wykrycia Strażnika")

        # ---- zakładka 2: Microsoft Defender
        ramka2 = tk.Frame(self.zakladki, bg=TLO)
        gora = tk.Frame(ramka2, bg=TLO)
        gora.pack(fill="x", pady=(8, 6))
        self.l_def = ttk.Label(gora, text="", style="Opis.TLabel", wraplength=760, justify="left")
        self.l_def.pack(side="left", fill="x", expand=True)
        ttk.Button(gora, text="↻ Odśwież", command=self.zaladuj_defendera).pack(side="right")
        ramka, self.d_def = tabela(ramka2, ("Czas", "Zagrożenie", "Waga", "Zneutralizowane", "Plik"),
                                   (130, 220, 90, 130, 380), wysokosc=8)
        ramka.pack(fill="both", expand=True)
        self.d_def.bind("<<TreeviewSelect>>", lambda e: self._opisz_wykrycie())
        r, self.t_def = pole_tekstowe(ramka2)
        self.t_def.config(height=4)
        r.pack(fill="x", pady=(8, 4))
        self.zakladki.add(ramka2, text="Microsoft Defender")
        self.zakladki.bind("<<NotebookTabChanged>>", self._zmiana_zakladki)

    # ------------------------------------------------------------ ustawienia
    def _zmien_opcje(self):
        u = self.app.ustawienia
        u["auto_kwarantanna"] = self.v_auto.get()
        u["uzyj_defendera"] = self.v_def.get()
        u["powiadomienia"] = self.v_pow.get()
        self.app.zapisz_ustawienia()
        if self.app.straznik is not None:          # zmiana działa od razu, bez restartu
            self.app.straznik.auto_kwarantanna = u["auto_kwarantanna"]
            self.app.straznik.uzyj_defendera = u["uzyj_defendera"]

    def _foldery(self):
        return self.app.ustawienia["foldery"] or silnik.foldery_szybkiego_skanu()

    def dodaj_folder(self):
        folder = filedialog.askdirectory(title="Folder do obserwowania")
        if not folder:
            return
        lista = list(self.app.ustawienia["foldery"] or silnik.foldery_szybkiego_skanu())
        folder = os.path.normpath(folder)
        if folder not in lista:
            lista.append(folder)
        self.app.ustawienia["foldery"] = lista
        self.app.zapisz_ustawienia()
        self._po_zmianie_folderow()

    def domyslne_foldery(self):
        self.app.ustawienia["foldery"] = []
        self.app.zapisz_ustawienia()
        self._po_zmianie_folderow()

    def _po_zmianie_folderow(self):
        self.odswiez_straznika()
        if self.app.straznik_dziala():
            messagebox.showinfo("Capsule", "Nowa lista folderów zadziała po ponownym "
                                           "włączeniu Strażnika (wyłącz i włącz go).")

    # ------------------------------------------------------------- stan
    def odswiez(self):
        self.odswiez_straznika()

    def odswiez_straznika(self):
        app = self.app
        if app.zatrzymywanie:
            ustaw_baner(self.baner, "⏳  Wyłączanie Strażnika…", ZIELONY_CIEMNY)
            self.b_straznik.config(state="disabled")
        elif app.straznik_dziala():
            ustaw_baner(self.baner, "✔  STRAŻNIK WŁĄCZONY – nowe pliki są sprawdzane na bieżąco",
                        KOLOR_WERDYKTU["CZYSTY"])
            self.b_straznik.config(text="■ Wyłącz Strażnika", state="normal")
        else:
            ustaw_baner(self.baner, "⚠  Strażnik wyłączony – nowe pliki nie są sprawdzane",
                        KOLOR_WERDYKTU["PODEJRZANY"])
            self.b_straznik.config(text="🛡 Włącz Strażnika", state="normal")
        s = app.straznik
        if s is not None:
            self.l_liczniki.config(text=f"w tej sesji: sprawdzono {s.sprawdzono}, wykryto {s.wykryto}")
        self.l_foldery.config(text="Obserwowane foldery (+ podfoldery do 2 poziomów): " +
                                   "; ".join(self._foldery()) +
                                   ("" if app.ustawienia["foldery"] else "   [domyślne]"))

    def pokaz_blad(self, tekst):
        ustaw_baner(self.baner, f"⚠  Strażnik zgłosił problem: {tekst}", KOLOR_WERDYKTU["PODEJRZANY"])

    # ------------------------------------------------------ wykrycia Strażnika
    def dodaj_wykrycie(self, w):
        import datetime as dt
        d = w.get("defender") or {}
        def_txt = {"zagrozenie": "ZAGROŻENIE: " + d.get("nazwa", ""), "czysty": "czysty",
                   "blad": "błąd zapytania", "brak": "niedostępny"}.get(d.get("status"), "–")
        gdzie = "w kwarantannie" if w.get("id_kwarantanny") else "na dysku"
        iid = wstaw_wiersz(self.drzewo, (dt.datetime.now().strftime("%H:%M:%S"), w["werdykt"],
                                         w["nazwa"], def_txt, gdzie), tags=(w["werdykt"],),
                           zaznaczony=False)
        self.drzewo.move(iid, "", 0)            # najnowsze na górze
        self.wyniki[iid] = w
        _po_zmianie(self.drzewo)

    def dodaj_alarm_wabika(self, dane, nazwy):
        import datetime as dt
        iid = wstaw_wiersz(self.drzewo, (dt.datetime.now().strftime("%H:%M:%S"), "ZŁOŚLIWY",
                                         f"RANSOMWARE? zmieniono wabiki: {len(dane['wabiki'])}",
                                         "—", "podejrzane: " + nazwy), tags=("ZŁOŚLIWY",))
        self.drzewo.move(iid, "", 0)
        self.wyniki[iid] = {"nazwa": "alarm wabika", "sciezka": "", "wabik": True}
        _po_zmianie(self.drzewo)

    def _licz_zaznaczone(self):
        self.l_zazn.config(text=f"zaznaczono: {len(zaznaczone(self.drzewo))} z {len(self.wyniki)}")

    def _wybrany(self):
        sel = self.drzewo.selection()
        if not sel:
            messagebox.showinfo("Capsule", "Zaznacz wiersz na liście.")
            return None
        return self.wyniki[sel[0]]

    def do_laboratorium(self):
        w = self._wybrany()
        if not w:
            return
        if w.get("wabik"):
            self.app.pokaz("ustawienia")
            self.app.strony["ustawienia"].zakladki.select(2)
            return
        if w.get("id_kwarantanny"):
            self.app.analizuj_z_kwarantanny(w["id_kwarantanny"])
        elif os.path.exists(w["sciezka"]):
            self.app.analizuj_plik(w["sciezka"])
        else:
            messagebox.showinfo("Capsule", "Tego pliku już nie ma w tym miejscu.")

    def zaznaczone_do_kwarantanny(self):
        iidy = [i for i in zaznaczone(self.drzewo)
                if not self.wyniki[i].get("id_kwarantanny") and not self.wyniki[i].get("wabik")]
        if not iidy:
            messagebox.showinfo("Capsule", "Zaznacz kwadraciki ☐ przy plikach leżących na dysku.")
            return
        if not messagebox.askyesno("Kwarantanna", f"Zamknąć w kwarantannie {len(iidy)} plik(ów)?\n"
                                   "Oryginały zostaną usunięte z obecnego miejsca."):
            return
        bledy = []
        for iid in iidy:
            w = self.wyniki[iid]
            try:
                meta = silnik.do_kwarantanny(w["sciezka"], w)
                w["id_kwarantanny"] = meta["id"]
                self.drzewo.set(iid, "Gdzie jest", "w kwarantannie")
                ustaw_pole(self.drzewo, iid, False)
            except Exception as e:  # noqa: BLE001
                bledy.append(f"{w['nazwa']}: {e}")
        _po_zmianie(self.drzewo)
        if bledy:
            messagebox.showwarning("Kwarantanna", "Nie udało się:\n" + "\n".join(bledy))

    # ------------------------------------------------------ Microsoft Defender
    def _zmiana_zakladki(self, _e=None):
        if self.zakladki.index(self.zakladki.select()) == 1 and not self.def_zaladowano:
            self.zaladuj_defendera()

    def zaladuj_defendera(self):
        self.def_zaladowano = True
        self.l_def.config(text="⏳ Pytam Defendera…")

        def praca():
            return silnik.stan_defendera(), silnik.historia_defendera(50)

        self.app.w_tle(praca, gotowe=self._pokaz_defendera, blad=lambda e: self.l_def.config(
            text=f"Nie udało się odczytać danych Defendera: {e}"))

    def _pokaz_defendera(self, wynik):
        stan, historia = wynik
        if stan is None:
            self.l_def.config(text="Nie można odczytać stanu Defendera (działa tylko na Windows; "
                                   "może też być zainstalowany inny antywirus albo brakuje uprawnień).")
        else:
            wl = "włączony" if stan["wlaczony"] else "WYŁĄCZONY"
            rt = "tak" if stan["czas_rzeczywisty"] else "NIE"
            wiek = stan["wiek_sygnatur_dni"]
            ostrz = "  ← nieświeże, zaktualizuj Windows Update" if isinstance(wiek, int) and wiek > 3 else ""
            self.l_def.config(text=f"Defender: {wl} · ochrona w czasie rzeczywistym: {rt} · "
                                   f"sygnatury sprzed {wiek} dni (wersja {stan['wersja_sygnatur']}){ostrz}")
        self.def_historia = historia
        self.d_def.delete(*self.d_def.get_children())
        for i, h in enumerate(historia):
            self.d_def.insert("", "end", iid=str(i), values=(
                h["czas"], h["nazwa"], h["waga"], "tak" if h["usunieto"] else "NIE", h["plik"]))
        ustaw_tekst(self.t_def, "Wybierz wykrycie z listy, a wyjaśnię je zwykłym językiem."
                    if historia else "Defender nie ma zapisanych wykryć – albo nie można ich odczytać.")

    def _opisz_wykrycie(self):
        sel = self.d_def.selection()
        if sel:
            ustaw_tekst(self.t_def, silnik.opis_wykrycia_defendera(self.def_historia[int(sel[0])]))


# =========================================================================== SYSTEM
class StronaSystem(tk.Frame):
    """Autostart, działające procesy i połączenia sieciowe – z oceną ryzyka (Windows)."""

    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        self.zajety = False
        self.dane = {"autostart": {}, "procesy": {}, "polaczenia": {}}
        self.procesy_cache = None
        naglowek(self, "System", "Co uruchamia się z Windows, co działa teraz i z kim łączy się komputer")
        self.postep = ttk.Progressbar(self, mode="indeterminate")
        self.postep.pack(fill="x", pady=(0, 4))
        self.status = ttk.Label(self, text="Wybierz zakładkę i kliknij Skanuj. To tylko odczyt – "
                                           "nic nie jest zmieniane, dopóki sam o to nie poprosisz.",
                                style="Opis.TLabel")
        self.status.pack(anchor="w", pady=(0, 8))
        self.zakladki = ttk.Notebook(self)
        self.zakladki.pack(fill="both", expand=True)

        # ---- autostart
        pasek, self.d_auto, self.t_auto, dol = self._zakladka(
            "Autostart", ("Werdykt", "Pkt", "Nazwa", "Źródło", "Polecenie", "Dlaczego"),
            (100, 50, 170, 190, 300, 340))
        ttk.Button(pasek, text="🔄 Skanuj autostart", style="Akcent.TButton",
                   command=self.skanuj_autostart).pack(side="left")
        self._przyciski_zaznaczania(pasek, self.d_auto, "autostart")
        ttk.Button(dol, text="⏸ Wyłącz zaznaczone", style="Akcent.TButton",
                   command=self.wylacz_zaznaczone).pack(side="left")
        ttk.Button(dol, text="↩ Przywróć wyłączone…", command=self.przywroc_wylaczone
                   ).pack(side="left", padx=8)
        ttk.Button(dol, text="🔬 Zbadaj plik", command=lambda: self.zbadaj(self.d_auto, "autostart",
                                                                           "sciezka_exe")).pack(side="left")

        # ---- procesy
        pasek, self.d_proc, self.t_proc, dol = self._zakladka(
            "Procesy", ("Werdykt", "Pkt", "PID", "Proces", "Ścieżka", "Dlaczego"),
            (100, 50, 70, 170, 380, 340))
        ttk.Button(pasek, text="🔄 Skanuj procesy", style="Akcent.TButton",
                   command=self.skanuj_procesy).pack(side="left")
        self._przyciski_zaznaczania(pasek, self.d_proc, "procesy")
        ttk.Button(dol, text="■ Zakończ zaznaczone", style="Akcent.TButton",
                   command=self.zakoncz_zaznaczone).pack(side="left")
        ttk.Button(dol, text="🔬 Zbadaj plik", command=lambda: self.zbadaj(self.d_proc, "procesy",
                                                                           "sciezka")).pack(side="left", padx=8)

        # ---- połączenia
        pasek, self.d_siec, self.t_siec, dol = self._zakladka(
            "Połączenia", ("Werdykt", "Pkt", "Proces", "PID", "Lokalny", "Zdalny", "Stan"),
            (100, 50, 170, 70, 270, 270, 110), pola=False)
        ttk.Button(pasek, text="🔄 Skanuj połączenia", style="Akcent.TButton",
                   command=self.skanuj_polaczenia).pack(side="left")
        ttk.Label(pasek, text="Pokazane: ruch do internetu i porty otwarte na świat; sieć domowa jest pomijana.",
                  style="Opis.TLabel").pack(side="right")
        ttk.Button(dol, text="🔬 Zbadaj program", command=lambda: self.zbadaj(self.d_siec, "polaczenia",
                                                                              "sciezka")).pack(side="left")

    # ---------------------------------------------------------------- budowa
    def _zakladka(self, tytul, kolumny, szerokosci, pola=True):
        ramka = tk.Frame(self.zakladki, bg=TLO)
        pasek = tk.Frame(ramka, bg=TLO)
        pasek.pack(fill="x", pady=(8, 6))
        r, drzewo = tabela(ramka, kolumny, szerokosci, wysokosc=12, pola_wyboru=pola,
                           po_zmianie=self._licz if pola else None)
        r.pack(fill="both", expand=True)
        rt, tekst = pole_tekstowe(ramka)
        tekst.config(height=4)
        rt.pack(fill="x", pady=(8, 4))
        dol = tk.Frame(ramka, bg=TLO)
        dol.pack(fill="x", pady=(0, 4))
        self.zakladki.add(ramka, text=tytul)
        drzewo.bind("<<TreeviewSelect>>", lambda e, d=drzewo, t=tekst: self._szczegoly(d, t))
        return pasek, drzewo, tekst, dol

    def _przyciski_zaznaczania(self, pasek, drzewo, klucz):
        ttk.Button(pasek, text="☑ Tylko podejrzane i groźne", command=lambda: (
            ustaw_wszystkie(drzewo, False),
            ustaw_wszystkie(drzewo, True, lambda i: self.dane[klucz][i]["werdykt"] != "CZYSTY"))
                   ).pack(side="left", padx=8)
        ttk.Button(pasek, text="☐ Odznacz", command=lambda: ustaw_wszystkie(drzewo, False)
                   ).pack(side="left")

    def _licz(self):
        pass

    def _szczegoly(self, drzewo, tekst):
        sel = drzewo.selection()
        if not sel:
            return
        for klucz, d in (("autostart", self.d_auto), ("procesy", self.d_proc), ("polaczenia", self.d_siec)):
            if d is drzewo and sel[0] in self.dane[klucz]:
                w = self.dane[klucz][sel[0]]
                linie = list(w["powody"])
                if w.get("polecenie"):
                    linie.append("Polecenie: " + w["polecenie"])
                ustaw_tekst(tekst, "\n".join(linie))

    # ---------------------------------------------------------- wczytywanie
    def odswiez(self):
        pass

    def _laduj(self, funkcja, po_zaladowaniu, opis):
        if os.name != "nt":
            messagebox.showinfo("Capsule", "Ta funkcja czyta stan Windows, więc działa tylko na Windows.")
            return
        if self.zajety:
            return
        self.zajety = True
        self.postep.start(12)
        self.status.config(text=f"⏳ {opis} (może potrwać kilkanaście sekund – sprawdzam podpisy)…")
        self.app.w_tle(funkcja, gotowe=po_zaladowaniu, blad=self._blad)

    def _koniec(self, tekst):
        self.zajety = False
        self.postep.stop()
        self.status.config(text=tekst)

    def _blad(self, e):
        self._koniec(f"Błąd: {e}")

    def _wypelnij(self, drzewo, klucz, lista, wiersz, pola=True):
        drzewo.delete(*drzewo.get_children())
        self.dane[klucz] = {}
        for w in lista:
            if pola:
                iid = wstaw_wiersz(drzewo, wiersz(w), tags=(w["werdykt"],))
            else:
                iid = drzewo.insert("", "end", values=wiersz(w), tags=(w["werdykt"],))
            self.dane[klucz][iid] = w
        if pola:
            _po_zmianie(drzewo)

    @staticmethod
    def _licznik(lista):
        return (f"groźnych: {sum(w['werdykt'] == 'ZŁOŚLIWY' for w in lista)}, "
                f"podejrzanych: {sum(w['werdykt'] == 'PODEJRZANY' for w in lista)}")

    # ------------------------------------------------------------- autostart
    def skanuj_autostart(self):
        self._laduj(silnik.audyt_autostartu, self._po_autostarcie, "Skanuję autostart")

    def _po_autostarcie(self, lista):
        self._wypelnij(self.d_auto, "autostart", lista, lambda w: (
            w["werdykt"], w["punkty"], w["nazwa"], w["zrodlo"], w["polecenie"][:120], w["powody"][0]))
        self._koniec(f"Autostart: {len(lista)} pozycji, {self._licznik(lista)}.")

    def wylacz_zaznaczone(self):
        iidy = zaznaczone(self.d_auto)
        if not iidy:
            messagebox.showinfo("Capsule", "Zaznacz kwadraciki ☐ przy pozycjach do wyłączenia.")
            return
        nazwy = "\n".join("• " + self.dane["autostart"][i]["nazwa"] for i in iidy[:12])
        if not messagebox.askyesno("Wyłącz z autostartu", f"Wyłączyć {len(iidy)} pozycji?\n\n{nazwy}\n\n"
                                   "Program nie zniknie z dysku, tylko przestanie startować z Windows. "
                                   "Możesz to cofnąć przyciskiem „Przywróć wyłączone”."):
            return
        bledy = []
        for i in iidy:
            w = self.dane["autostart"][i]
            try:
                silnik.wylacz_autostart(w)
                self.d_auto.delete(i)
                self.dane["autostart"].pop(i, None)
            except Exception as e:  # noqa: BLE001
                bledy.append(f"{w['nazwa']}: {e}")
        _po_zmianie(self.d_auto)
        if bledy:
            messagebox.showwarning("Autostart", "Nie udało się:\n" + "\n".join(bledy))

    def przywroc_wylaczone(self):
        lista = silnik.lista_wylaczonych()
        if not lista:
            messagebox.showinfo("Capsule", "Capsule nie wyłączył jeszcze żadnej pozycji autostartu.")
            return
        nazwy = "\n".join(f"• {k['nazwa']}  (wyłączono {k['kiedy']})" for k in lista[:12])
        if not messagebox.askyesno("Przywróć", f"Przywrócić do autostartu {len(lista)} pozycji?\n\n{nazwy}"):
            return
        bledy = []
        for k in lista:
            try:
                silnik.przywroc_autostart(k["id"])
            except Exception as e:  # noqa: BLE001
                bledy.append(f"{k['nazwa']}: {e}")
        messagebox.showinfo("Capsule", "Gotowe. Zeskanuj autostart ponownie, aby zobaczyć zmiany."
                            if not bledy else "Nie udało się:\n" + "\n".join(bledy))

    # --------------------------------------------------------------- procesy
    def skanuj_procesy(self):
        self._laduj(silnik.lista_procesow, self._po_procesach, "Skanuję procesy")

    def _po_procesach(self, lista):
        self.procesy_cache = lista
        self._wypelnij(self.d_proc, "procesy", lista, lambda w: (
            w["werdykt"], w["punkty"],
            f"{w['pid']} +{w['liczba'] - 1}" if w.get("liczba", 1) > 1 else w["pid"],
            w["nazwa"] + (f"  ×{w['liczba']}" if w.get("liczba", 1) > 1 else ""),
            w["sciezka"] or "—", w["powody"][0]))
        self._koniec(f"Procesy: {sum(w.get('liczba', 1) for w in lista)} działa, {self._licznik(lista)}.")

    def zakoncz_zaznaczone(self):
        iidy = zaznaczone(self.d_proc)
        if not iidy:
            messagebox.showinfo("Capsule", "Zaznacz kwadraciki ☐ przy procesach do zamknięcia.")
            return
        nazwy = "\n".join(f"• {self.dane['procesy'][i]['nazwa']} "
                          f"(procesów: {self.dane['procesy'][i].get('liczba', 1)})" for i in iidy[:12])
        if not messagebox.askyesno("Zakończ procesy", f"Zakończyć {len(iidy)} pozycji (wraz ze wszystkimi ich procesami)?\n\n{nazwy}\n\n"
                                   "Niezapisane dane w tych programach przepadną. Pliku to nie usuwa – "
                                   "możesz go potem zamknąć w kwarantannie."):
            return
        bledy = []
        for i in iidy:
            w = self.dane["procesy"][i]
            try:
                for pid in w.get("pidy", [w["pid"]]):
                    silnik.zakoncz_proces(pid, w["nazwa"])
                self.d_proc.delete(i)
                self.dane["procesy"].pop(i, None)
            except Exception as e:  # noqa: BLE001
                bledy.append(f"{w['nazwa']}: {e}")
        _po_zmianie(self.d_proc)
        if bledy:
            messagebox.showwarning("Procesy", "Nie udało się:\n" + "\n".join(bledy))

    # ------------------------------------------------------------ połączenia
    def skanuj_polaczenia(self):
        self._laduj(lambda: silnik.polaczenia_sieciowe(self.procesy_cache), self._po_polaczeniach,
                    "Sprawdzam połączenia")

    def _po_polaczeniach(self, lista):
        self._wypelnij(self.d_siec, "polaczenia", lista, lambda w: (
            w["werdykt"], w["punkty"], w["proces"], w["pid"], w["lokalny"], w["zdalny"], w["stan"]), pola=False)
        self._koniec(f"Połączenia: {len(lista)} pozycji, {self._licznik(lista)}.")

    # ----------------------------------------------------------------- wspólne
    def zbadaj(self, drzewo, klucz, pole):
        sel = drzewo.selection()
        if not sel:
            messagebox.showinfo("Capsule", "Zaznacz wiersz na liście.")
            return
        sciezka = self.dane[klucz][sel[0]].get(pole) or ""
        if sciezka and os.path.isfile(sciezka):
            self.app.analizuj_plik(sciezka)
        else:
            messagebox.showinfo("Capsule", "Nie znam ścieżki do pliku tej pozycji albo pliku już nie ma.")


# =========================================================================== USTAWIENIA
class StronaUstawienia(tk.Frame):
    """Praca w tle, harmonogram, integracje (VirusTotal, abuse.ch) i pułapka na ransomware."""

    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        u = app.ustawienia
        naglowek(self, "Ustawienia", "Praca w tle, skany zaplanowane, integracje i pułapka na ransomware")
        self.zakladki = ttk.Notebook(self)
        self.zakladki.pack(fill="both", expand=True)

        # ================================================ Ogólne
        og = tk.Frame(self.zakladki, bg=TLO)
        self.zakladki.add(og, text="Ogólne")
        self._sekcja(og, "> PRACA W TLE")
        self.v_tray = tk.BooleanVar(value=u["tray_zamykanie"])
        przelacznik(og, "Przycisk X w oknie chowa Capsule do zasobnika (przy zegarze) zamiast go wyłączać",
                    self.v_tray, lambda: self._zapisz("tray_zamykanie", self.v_tray.get())
                    ).pack(anchor="w", padx=10)
        self.l_tray = ttk.Label(og, style="Opis.TLabel", wraplength=900, justify="left")
        self.l_tray.pack(anchor="w", padx=34, pady=(0, 8))
        self.v_auto = tk.BooleanVar(value=dodatki.autostart_wlaczony())
        przelacznik(og, "Uruchamiaj Capsule razem z Windows (od razu w tle, w zasobniku)",
                    self.v_auto, self._zmien_autostart).pack(anchor="w", padx=10)
        ttk.Button(og, text="🖥 Utwórz skrót na pulpicie i w menu Start", command=self._skrot
                   ).pack(anchor="w", padx=10, pady=10)

        self._sekcja(og, "> SKAN ZAPLANOWANY")
        wiersz = tk.Frame(og, bg=TLO)
        wiersz.pack(anchor="w", padx=10)
        self.v_skan = tk.BooleanVar(value=u["skan_zaplanowany"])
        przelacznik(wiersz, "Skanuj automatycznie codziennie o godzinie:", self.v_skan,
                    self._zmien_skan).pack(side="left")
        self.v_godz = tk.StringVar(value=u["skan_godzina"])
        ttk.Entry(wiersz, textvariable=self.v_godz, width=7).pack(side="left", padx=8)
        ttk.Button(wiersz, text="Zapisz godzinę", command=self._zmien_skan).pack(side="left")
        ttk.Label(og, text="Skanuje foldery szybkiego skanu. Działa, gdy Capsule jest uruchomiony "
                           "(w tle wystarczy). Jeśli komputer był wyłączony o tej porze, skan wykona się "
                           "zaraz po starcie programu.", style="Opis.TLabel", wraplength=900,
                  justify="left").pack(anchor="w", padx=34, pady=(2, 0))

        # ================================================ Integracje
        ig = tk.Frame(self.zakladki, bg=TLO)
        self.zakladki.add(ig, text="Integracje")
        self._sekcja(ig, "> VIRUSTOTAL (opinia ponad 70 silników antywirusowych)")
        w1 = tk.Frame(ig, bg=TLO)
        w1.pack(anchor="w", padx=10)
        ttk.Label(w1, text="Klucz API:").pack(side="left")
        self.v_vt = tk.StringVar(value=u["vt_klucz"])
        ttk.Entry(w1, textvariable=self.v_vt, width=70, show="•").pack(side="left", padx=8)
        ttk.Button(w1, text="Zapisz", command=self._zapisz_vt).pack(side="left")
        ttk.Button(w1, text="🌐 Weź darmowy klucz", command=lambda: webbrowser.open(
            "https://www.virustotal.com/gui/join-us")).pack(side="left", padx=8)
        self.v_vt_straz = tk.BooleanVar(value=u["vt_straznik"])
        przelacznik(ig, "Strażnik sprawdza podejrzane pliki także w VirusTotal", self.v_vt_straz,
                    self._zmien_vt_straznik).pack(anchor="w", padx=10, pady=(6, 0))
        ttk.Label(ig, text="Do VirusTotal trafia WYŁĄCZNIE skrót pliku (SHA-256), nigdy sam plik. "
                           "Darmowy klucz: 4 zapytania na minutę, 500 dziennie. Capsule trzyma klucz "
                           "w pliku ustawienia.json na tym komputerze.", style="Opis.TLabel",
                  wraplength=900, justify="left").pack(anchor="w", padx=34, pady=(2, 8))

        self._sekcja(ig, "> AKTUALIZACJA SYGNATUR (abuse.ch: MalwareBazaar + URLhaus)")
        w2 = tk.Frame(ig, bg=TLO)
        w2.pack(anchor="w", padx=10)
        ttk.Label(w2, text="Auth-Key:").pack(side="left")
        self.v_ab = tk.StringVar(value=u["abusech_klucz"])
        ttk.Entry(w2, textvariable=self.v_ab, width=70, show="•").pack(side="left", padx=8)
        ttk.Button(w2, text="Zapisz", command=self._zapisz_ab).pack(side="left")
        ttk.Button(w2, text="🌐 Weź darmowy klucz", command=lambda: webbrowser.open(
            "https://auth.abuse.ch/")).pack(side="left", padx=8)
        w3 = tk.Frame(ig, bg=TLO)
        w3.pack(anchor="w", padx=10, pady=(6, 0))
        ttk.Button(w3, text="⟳ Aktualizuj sygnatury teraz", style="Akcent.TButton",
                   command=self.app.aktualizuj_sygnatury).pack(side="left")
        self.v_ab_auto = tk.BooleanVar(value=u["aktualizuj_auto"])
        przelacznik(w3, "Aktualizuj automatycznie raz na dobę", self.v_ab_auto,
                    lambda: self._zapisz("aktualizuj_auto", self.v_ab_auto.get())).pack(side="left", padx=14)
        self.l_akt = ttk.Label(ig, text="", style="Opis.TLabel", wraplength=900, justify="left")
        self.l_akt.pack(anchor="w", padx=34, pady=(4, 0))
        ttk.Label(ig, text="Pobiera listy najświeższych próbek malware (hashe z ostatnich ~48 godzin) i "
                           "groźnych adresów URL. Dzięki temu Capsule rozpozna je po skrócie albo po "
                           "adresie w pliku. Formaty list są za logowaniem abuse.ch, więc jeśli coś "
                           "się nie pobierze, komunikat błędu pojawi się powyżej.",
                  style="Opis.TLabel", wraplength=900, justify="left").pack(anchor="w", padx=34, pady=(2, 0))

        # ================================================ Pułapka na ransomware
        rn = tk.Frame(self.zakladki, bg=TLO)
        self.zakladki.add(rn, text="Pułapka na ransomware")
        self._sekcja(rn, "> UKRYTE PLIKI-WABIKI")
        self.v_wab = tk.BooleanVar(value=u["wabiki"])
        przelacznik(rn, "Włącz pułapkę (w folderach powstaną ukryte pliki „!_capsule_wabik.*”)",
                    self.v_wab, self._zmien_wabiki).pack(anchor="w", padx=10)
        self.l_wab = ttk.Label(rn, text="", style="Opis.TLabel", wraplength=900, justify="left")
        self.l_wab.pack(anchor="w", padx=34, pady=(2, 4))
        w4 = tk.Frame(rn, bg=TLO)
        w4.pack(anchor="w", padx=10)
        ttk.Button(w4, text="➕ Dodaj folder…", command=self._dodaj_folder_wabikow).pack(side="left")
        ttk.Button(w4, text="↺ Domyślne", command=self._domyslne_wabiki).pack(side="left", padx=8)
        ttk.Button(w4, text="🗑 Usuń wszystkie wabiki z dysku", command=self._usun_wabiki).pack(side="left")
        self.v_wab_kill = tk.BooleanVar(value=u["wabiki_auto_zabij"])
        przelacznik(rn, "Przy alarmie automatycznie zamykaj proces, który najwięcej zapisywał na dysk "
                        "(ryzykowne: może to być zwykły program)", self.v_wab_kill,
                    lambda: self._zapisz("wabiki_auto_zabij", self.v_wab_kill.get())
                    ).pack(anchor="w", padx=10, pady=(8, 0))
        ttk.Label(rn, text="Ransomware szyfruje pliki po kolei. Gdy ruszy wabik (zmieni zawartość, usunie "
                           "go albo zmieni nazwę), Capsule alarmuje i pokazuje procesy, które w tej chwili "
                           "najwięcej zapisują na dysk. To sygnał ostrzegawczy, a nie ochrona: wykryje atak "
                           "dopiero po ruszeniu pierwszego wabika.", style="Opis.TLabel", wraplength=900,
                  justify="left").pack(anchor="w", padx=34, pady=(4, 6))
        self.l_alarm = ttk.Label(rn, text="Brak alarmów.", style="Opis.TLabel")
        self.l_alarm.pack(anchor="w", padx=10)
        ramka, self.d_sprawcy = tabela(rn, ("PID", "Proces", "Ścieżka", "Zapisano (MB)"),
                                       (80, 200, 520, 120), wysokosc=4, pola_wyboru=True)
        ramka.pack(fill="x", padx=10, pady=(4, 6))
        self.sprawcy = {}
        ttk.Button(rn, text="■ Zakończ zaznaczone procesy", style="Akcent.TButton",
                   command=self._zakoncz_sprawcow).pack(anchor="w", padx=10)

    # ------------------------------------------------------------------ pomocnicze
    def _sekcja(self, rodzic, tekst):
        ttk.Label(rodzic, text=tekst, font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(14, 6))

    def _zapisz(self, klucz, wartosc):
        self.app.ustawienia[klucz] = wartosc
        self.app.zapisz_ustawienia()

    def odswiez(self):
        self.v_auto.set(dodatki.autostart_wlaczony())
        if self.app.zasobnik:
            self.l_tray.config(text="Zasobnik działa: ikona Capsule jest przy zegarze. Minimalizacja też "
                                    "chowa program do zasobnika.")
        else:
            self.l_tray.config(text="Zasobnik niedostępny – brakuje pakietów pystray i Pillow "
                                    "(uruchom zainstaluj.bat). Program działa, ale zostaje na pasku zadań.")
        akt = self.app.ustawienia["aktualizacja_ostatnia"]
        if akt:
            self.l_akt.config(text=f"Ostatnia aktualizacja: {akt}")
        self.odswiez_wabiki()

    # ------------------------------------------------------------------ ogólne
    def _zmien_autostart(self):
        try:
            dodatki.ustaw_autostart(self.v_auto.get())
        except OSError as e:
            self.v_auto.set(not self.v_auto.get())
            messagebox.showerror("Capsule", str(e))

    def _skrot(self):
        try:
            sciezki = dodatki.utworz_skroty()
            messagebox.showinfo("Capsule", "Utworzono skróty:\n" + "\n".join(sciezki))
        except OSError as e:
            messagebox.showerror("Capsule", str(e))

    def _zmien_skan(self):
        godz = self.v_godz.get().strip()
        if not dodatki.poprawna_godzina(godz):
            messagebox.showwarning("Capsule", "Podaj godzinę w formacie GG:MM, np. 18:00.")
            return
        if len(godz.split(":")[0]) == 1:
            godz = "0" + godz
            self.v_godz.set(godz)
        self._zapisz("skan_godzina", godz)
        self._zapisz("skan_zaplanowany", self.v_skan.get())

    # ------------------------------------------------------------------ integracje
    def _zapisz_vt(self):
        self._zapisz("vt_klucz", self.v_vt.get().strip())
        self.app.zastosuj_opcje_straznika()
        messagebox.showinfo("Capsule", "Klucz VirusTotal zapisany.")

    def _zmien_vt_straznik(self):
        if self.v_vt_straz.get() and not self.app.ustawienia["vt_klucz"]:
            messagebox.showinfo("Capsule", "Najpierw wpisz i zapisz klucz API VirusTotal.")
            self.v_vt_straz.set(False)
            return
        self._zapisz("vt_straznik", self.v_vt_straz.get())
        self.app.zastosuj_opcje_straznika()

    def _zapisz_ab(self):
        self._zapisz("abusech_klucz", self.v_ab.get().strip())
        messagebox.showinfo("Capsule", "Auth-Key zapisany.")

    def po_aktualizacji(self, wynik):
        if wynik["bledy"]:
            self.l_akt.config(text="Aktualizacja nie do końca się udała: " + " | ".join(wynik["bledy"]))
        else:
            self.l_akt.config(text=f"Zaktualizowano {_dt_teraz()}: hashy {wynik['hashe']}, "
                                   f"adresów {wynik['adresy']}.")

    # ------------------------------------------------------------------ pułapka na ransomware
    def odswiez_wabiki(self):
        s = self.app.straz_wabikow
        foldery = self.app.ustawienia["wabiki_foldery"] or dodatki.foldery_wabikow_domyslne()
        stan = (f"Aktywnych wabików: {s.liczba()}. " if s and s.dziala else "Pułapka wyłączona. ")
        self.v_wab.set(bool(s and s.dziala))
        self.l_wab.config(text=stan + "Foldery: " + ("; ".join(foldery) or "brak") +
                          ("" if self.app.ustawienia["wabiki_foldery"] else "   [domyślne]"))

    def _zmien_wabiki(self):
        if not self.app.ustaw_wabiki(self.v_wab.get()):
            self.v_wab.set(False)

    def _dodaj_folder_wabikow(self):
        folder = filedialog.askdirectory(title="Folder, w którym ukryć wabiki")
        if not folder:
            return
        lista = list(self.app.ustawienia["wabiki_foldery"] or dodatki.foldery_wabikow_domyslne())
        folder = os.path.normpath(folder)
        if folder not in lista:
            lista.append(folder)
        self._zapisz("wabiki_foldery", lista)
        self._po_zmianie_folderow()

    def _domyslne_wabiki(self):
        self._zapisz("wabiki_foldery", [])
        self._po_zmianie_folderow()

    def _po_zmianie_folderow(self):
        if self.app.straz_wabikow:       # restart pułapki, żeby objęła nową listę
            self.app.ustaw_wabiki(False)
            self.app.ustaw_wabiki(True, cicho=True)
        self.odswiez_wabiki()

    def _usun_wabiki(self):
        if not messagebox.askyesno("Capsule", "Wyłączyć pułapkę i usunąć wszystkie pliki-wabiki z dysku?"):
            return
        self.app.ustaw_wabiki(False)
        n = dodatki.usun_wabiki()
        self.odswiez_wabiki()
        messagebox.showinfo("Capsule", f"Usunięto wabiki: {n}.")

    def pokaz_alarm_wabika(self, dane):
        self.l_alarm.config(text=f"⛔ ALARM {dane['kiedy']}: zmienione wabiki: {len(dane['wabiki'])}. "
                                 "Podejrzane procesy (najwięcej zapisujące na dysk) poniżej.",
                            foreground=KOLOR_WERDYKTU["ZŁOŚLIWY"])
        self.d_sprawcy.delete(*self.d_sprawcy.get_children())
        self.sprawcy = {}
        for s in dane.get("sprawcy") or []:
            iid = wstaw_wiersz(self.d_sprawcy, (s["pid"], s["nazwa"], s["sciezka"] or "—",
                                                s["zapisano_mb"]), tags=("PODEJRZANY",))
            self.sprawcy[iid] = s
        _po_zmianie(self.d_sprawcy)

    def _zakoncz_sprawcow(self):
        iidy = zaznaczone(self.d_sprawcy)
        if not iidy:
            messagebox.showinfo("Capsule", "Zaznacz kwadraciki ☐ przy procesach do zamknięcia.")
            return
        if not messagebox.askyesno("Capsule", f"Zakończyć {len(iidy)} proces(ów)? Niezapisane dane przepadną."):
            return
        bledy = []
        for i in iidy:
            s = self.sprawcy[i]
            try:
                silnik.zakoncz_proces(s["pid"], s["nazwa"])
                self.d_sprawcy.delete(i)
            except Exception as e:  # noqa: BLE001
                bledy.append(f"{s['nazwa']}: {e}")
        _po_zmianie(self.d_sprawcy)
        if bledy:
            messagebox.showwarning("Capsule", "Nie udało się:\n" + "\n".join(bledy))


# =========================================================================== SKANER
class StronaSkaner(tk.Frame):
    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        self.wyniki = {}
        self.przerwij = False
        self.trwa = False
        self.zaplanowany = False
        naglowek(self, "Skaner", "Przeszukuje foldery i wyłapuje podejrzane pliki")

        pasek = tk.Frame(self, bg=TLO)
        pasek.pack(fill="x")
        self.b_szybki = ttk.Button(pasek, text="⚡ Szybki skan", style="Akcent.TButton",
                                   command=self.szybki)
        self.b_szybki.pack(side="left")
        self.b_folder = ttk.Button(pasek, text="📁 Wybierz folder…", command=self.wybierz_folder)
        self.b_folder.pack(side="left", padx=8)
        self.b_stop = ttk.Button(pasek, text="■ Zatrzymaj", command=self.zatrzymaj, state="disabled")
        self.b_stop.pack(side="left")

        self.postep = ttk.Progressbar(self, mode="indeterminate")
        self.postep.pack(fill="x", pady=(14, 4))
        self.status = ttk.Label(self, text="Gotowy.", style="Opis.TLabel")
        self.status.pack(anchor="w", pady=(0, 10))

        wybor = tk.Frame(self, bg=TLO)
        wybor.pack(fill="x", pady=(0, 6))
        ttk.Button(wybor, text="☑ Zaznacz wszystkie",
                   command=lambda: ustaw_wszystkie(self.drzewo, True)).pack(side="left")
        ttk.Button(wybor, text="☐ Odznacz wszystkie",
                   command=lambda: ustaw_wszystkie(self.drzewo, False)).pack(side="left", padx=8)
        ttk.Button(wybor, text="☑ Tylko złośliwe", command=self.zaznacz_zlosliwe).pack(side="left")
        self.l_zazn = ttk.Label(wybor, text="", style="Opis.TLabel")
        self.l_zazn.pack(side="right")

        ramka, self.drzewo = tabela(self, ("Werdykt", "Punkty", "Nazwa", "Typ", "Ścieżka"),
                                    (100, 70, 200, 200, 400), pola_wyboru=True,
                                    po_zmianie=self._licz_zaznaczone)
        ramka.pack(fill="both", expand=True)
        self.drzewo.bind("<Double-1>", lambda e: self.do_laboratorium())

        dol = tk.Frame(self, bg=TLO)
        dol.pack(fill="x", pady=(10, 0))
        ttk.Button(dol, text="🔬 Otwórz w laboratorium", command=self.do_laboratorium).pack(side="left")
        ttk.Button(dol, text="📦 Zaznaczone do kwarantanny", style="Akcent.TButton",
                   command=self.zaznaczone_do_kwarantanny).pack(side="left", padx=8)
        ttk.Label(dol, text="Kliknij kwadracik ☐ (albo spację), żeby zaznaczyć plik.",
                  style="Opis.TLabel").pack(side="right")

    def szybki(self):
        foldery = silnik.foldery_szybkiego_skanu()
        if not foldery:
            messagebox.showinfo("Capsule", "Nie znaleziono typowych folderów (Pobrane, Pulpit, Temp).")
            return
        self.start(foldery)

    def wybierz_folder(self):
        folder = filedialog.askdirectory(title="Wybierz folder (lub cały dysk) do skanowania")
        if folder:
            self.start([folder])

    def zatrzymaj(self):
        self.przerwij = True

    def start(self, foldery, zaplanowany=False):
        if self.trwa:
            return
        self.zaplanowany = zaplanowany
        self.trwa, self.przerwij = True, False
        self.wyniki.clear()
        self.drzewo.delete(*self.drzewo.get_children())
        _po_zmianie(self.drzewo)
        self.b_szybki.config(state="disabled")
        self.b_folder.config(state="disabled")
        self.b_stop.config(state="normal")
        self.postep.start(12)
        self.status.config(text="Skanowanie: " + "; ".join(foldery))
        licznik = {"n": 0}

        def postep(sciezka, n):
            licznik["n"] = n
            if n % 25 == 0:
                self.app.kolejka.put((self._status, (f"Sprawdzono {n} plików… {sciezka[-90:]}",)))

        def praca():
            for w in silnik.skanuj(foldery, postep=postep, stop=lambda: self.przerwij):
                self.app.kolejka.put((self._dodaj, (w,)))
            self.app.kolejka.put((self._koniec, (licznik["n"],)))

        threading.Thread(target=praca, daemon=True).start()

    def _status(self, tekst):
        self.status.config(text=tekst)

    def _dodaj(self, w):
        # złośliwe pliki są od razu zaznaczone, podejrzane – nie (decydujesz sam)
        iid = wstaw_wiersz(self.drzewo, (w["werdykt"], w["punkty"], w["nazwa"], w["typ"],
                                         w["sciezka"]), tags=(w["werdykt"],),
                           zaznaczony=w["werdykt"] == "ZŁOŚLIWY")
        self.wyniki[iid] = w
        _po_zmianie(self.drzewo)

    def _licz_zaznaczone(self):
        self.l_zazn.config(text=f"zaznaczono: {len(zaznaczone(self.drzewo))} z {len(self.wyniki)}")

    def zaznacz_zlosliwe(self):
        ustaw_wszystkie(self.drzewo, False)
        ustaw_wszystkie(self.drzewo, True, lambda i: self.wyniki[i]["werdykt"] == "ZŁOŚLIWY")

    def _koniec(self, n):
        self.trwa = False
        self.postep.stop()
        self.b_szybki.config(state="normal")
        self.b_folder.config(state="normal")
        self.b_stop.config(state="disabled")
        przerwano = " (przerwano)" if self.przerwij else ""
        self.status.config(text=f"Zakończono{przerwano}: sprawdzono {n} plików, "
                                f"podejrzanych: {len(self.wyniki)}.")
        self.app.po_skanie(len(self.wyniki), self.zaplanowany)

    def _zaznaczony(self):
        sel = self.drzewo.selection()
        if not sel:
            messagebox.showinfo("Capsule", "Zaznacz plik na liście.")
            return None
        return sel

    def do_laboratorium(self):
        sel = self._zaznaczony()
        if sel:
            self.app.analizuj_plik(self.wyniki[sel[0]]["sciezka"])

    def _do_kwarantanny(self, iidy):
        if not iidy:
            return
        if not messagebox.askyesno("Kwarantanna", f"Zamknąć w kwarantannie {len(iidy)} plik(ów)?\n"
                                   "Oryginały zostaną usunięte z obecnego miejsca."):
            return
        bledy = []
        for iid in iidy:
            w = self.wyniki.get(iid)
            try:
                silnik.do_kwarantanny(w["sciezka"], w)
                self.drzewo.delete(iid)
                self.wyniki.pop(iid, None)
            except Exception as e:  # noqa: BLE001
                bledy.append(f"{w['nazwa']}: {e}")
        _po_zmianie(self.drzewo)
        if bledy:
            messagebox.showwarning("Kwarantanna", "Nie udało się:\n" + "\n".join(bledy))
        else:
            messagebox.showinfo("Kwarantanna", "Gotowe – pliki są zamknięte w pojemniku.")

    def zaznaczone_do_kwarantanny(self):
        iidy = zaznaczone(self.drzewo)
        if not iidy:
            messagebox.showinfo("Capsule", "Zaznacz kwadraciki ☐ przy plikach, które chcesz zamknąć.")
            return
        self._do_kwarantanny(iidy)


# =========================================================================== KWARANTANNA
class StronaKwarantanna(tk.Frame):
    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        naglowek(self, "Kwarantanna",
                 "Zaszyfrowane pojemniki – zamknięte pliki nie mogą się uruchomić")
        wybor = tk.Frame(self, bg=TLO)
        wybor.pack(fill="x", pady=(0, 6))
        ttk.Button(wybor, text="☑ Zaznacz wszystkie",
                   command=lambda: ustaw_wszystkie(self.drzewo, True)).pack(side="left")
        ttk.Button(wybor, text="☐ Odznacz wszystkie",
                   command=lambda: ustaw_wszystkie(self.drzewo, False)).pack(side="left", padx=8)
        self.l_zazn = ttk.Label(wybor, text="", style="Opis.TLabel")
        self.l_zazn.pack(side="right")
        ramka, self.drzewo = tabela(self, ("Data", "Nazwa", "Werdykt", "Punkty", "Skąd (oryginalna ścieżka)"),
                                    (150, 200, 100, 70, 420), pola_wyboru=True,
                                    po_zmianie=lambda: self.l_zazn.config(
                                        text=f"zaznaczono: {len(zaznaczone(self.drzewo))}"))
        ramka.pack(fill="both", expand=True)
        self.drzewo.bind("<Double-1>", lambda e: self.otworz())
        dol = tk.Frame(self, bg=TLO)
        dol.pack(fill="x", pady=(10, 0))
        ttk.Button(dol, text="🔬 Otwórz pojemnik w laboratorium", style="Akcent.TButton",
                   command=self.otworz).pack(side="left")
        ttk.Button(dol, text="↩ Przywróć zaznaczone", command=self.przywroc).pack(side="left", padx=8)
        ttk.Button(dol, text="🗑 Usuń zaznaczone na stałe", command=self.usun).pack(side="left")
        ttk.Button(dol, text="⟳ Odśwież", command=self.odswiez).pack(side="right")
        ttk.Button(dol, text="📂 Pokaż folder", command=lambda: otworz_systemowo(
            os.path.join(silnik.katalog_danych(), "kwarantanna"))).pack(side="right", padx=8)

    def odswiez(self):
        self.drzewo.delete(*self.drzewo.get_children())
        for m in silnik.lista_kwarantanny():
            wstaw_wiersz(self.drzewo, (m["data_kwarantanny"], m["nazwa"], m.get("werdykt"),
                                       m.get("punkty"), m["oryginalna_sciezka"]),
                         tags=(m.get("werdykt") or "",), iid=m["id"])
        _po_zmianie(self.drzewo)

    def _cele(self):
        """Pozycje z kwadracikiem ☑; jeśli żadnej – podświetlony wiersz."""
        cele = zaznaczone(self.drzewo) or list(self.drzewo.selection())
        if not cele:
            messagebox.showinfo("Capsule", "Zaznacz kwadraciki ☐ przy pozycjach na liście.")
        return cele

    def otworz(self):
        sel = list(self.drzewo.selection()) or zaznaczone(self.drzewo)
        if not sel:
            messagebox.showinfo("Capsule", "Kliknij pozycję na liście.")
            return
        self.app.analizuj_z_kwarantanny(sel[0])

    def przywroc(self):
        cele = self._cele()
        if cele and messagebox.askyesno(
                "Przywróć", f"Przywrócić {len(cele)} plik(ów) na dysk?\nRób to tylko, jeśli masz "
                            "pewność, że to fałszywy alarm."):
            wyniki, bledy = [], []
            for ident in cele:
                try:
                    wyniki.append(silnik.przywroc(ident))
                except Exception as e:  # noqa: BLE001
                    bledy.append(f"{ident}: {e}")
            if wyniki:
                messagebox.showinfo("Przywrócono", "Zapisano:\n" + "\n".join(wyniki))
            if bledy:
                messagebox.showerror("Błąd", "\n".join(bledy))
            self.odswiez()

    def usun(self):
        cele = self._cele()
        if cele and messagebox.askyesno(
                "Usuń", f"Usunąć {len(cele)} plik(ów) na zawsze? Tej operacji nie da się cofnąć."):
            for ident in cele:
                silnik.usun_z_kwarantanny(ident)
            self.odswiez()


# =========================================================================== LABORATORIUM
class StronaLaboratorium(tk.Frame):
    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        self.wynik = None
        self.sciezka = None
        naglowek(self, "Laboratorium", "Rozkładanie pliku na czynniki pierwsze – bez uruchamiania go")

        pasek = tk.Frame(self, bg=TLO)
        pasek.pack(fill="x")
        ttk.Button(pasek, text="📂 Otwórz plik…", style="Akcent.TButton",
                   command=self.app.analizuj_plik).pack(side="left")
        self.b_raport = ttk.Button(pasek, text="📄 Zapisz raport", command=self.raport, state="disabled")
        self.b_raport.pack(side="left", padx=8)
        self.b_kwar = ttk.Button(pasek, text="📦 Do kwarantanny", command=self.do_kwarantanny,
                                 state="disabled")
        self.b_kwar.pack(side="left")
        self.b_vt = ttk.Button(pasek, text="🌐 VirusTotal", command=self.virustotal,
                               state="disabled")
        self.b_vt.pack(side="left", padx=8)
        self.b_def = ttk.Button(pasek, text="🛡 Zapytaj Defendera", command=self.defender,
                                state="disabled")
        self.b_def.pack(side="left")
        ttk.Button(pasek, text="🔄 Wyczyść", command=self.wyczysc).pack(side="right")

        self.baner = baner(self, 13)
        ustaw_baner(self.baner, "> Wybierz plik, aby rozpocząć analizę_", ZIELONY_CIEMNY)
        self.baner.pack(fill="x", pady=12)

        self.zakladki = ttk.Notebook(self)
        self.zakladki.pack(fill="both", expand=True)

        r, self.t_podsum = pole_tekstowe(self.zakladki)
        self.zakladki.add(r, text="W skrócie")
        r, self.d_poch = tabela(self.zakladki, ("Cecha", "Wartość"), (220, 600))
        self.zakladki.add(r, text="Pochodzenie")
        r, self.d_zach = tabela(self.zakladki, ("Kategoria", "Co to znaczy", "Dowód", "Waga"),
                                (190, 420, 300, 60))
        self.zakladki.add(r, text="Zachowanie")
        r, self.t_strukt = pole_tekstowe(self.zakladki, mono=True)
        self.zakladki.add(r, text="Struktura")

        ramka_ciagi = tk.Frame(self.zakladki, bg=TLO)
        filtr = tk.Frame(ramka_ciagi, bg=TLO)
        filtr.pack(fill="x", pady=4)
        ttk.Label(filtr, text="Filtr:").pack(side="left")
        self.filtr = tk.StringVar()
        self.filtr.trace_add("write", lambda *a: self._pokaz_ciagi())
        ttk.Entry(filtr, textvariable=self.filtr, width=40).pack(side="left", padx=6)
        self.l_ciagi = ttk.Label(filtr, text="", style="Opis.TLabel")
        self.l_ciagi.pack(side="left")
        r, self.t_ciagi = pole_tekstowe(ramka_ciagi, mono=True)
        r.pack(fill="both", expand=True)
        self.zakladki.add(ramka_ciagi, text="Ciągi znaków")

        r, self.t_ioc = pole_tekstowe(self.zakladki, mono=True)
        self.zakladki.add(r, text="Wskaźniki (IOC)")
        r, self.t_hex = pole_tekstowe(self.zakladki, mono=True)
        self.zakladki.add(r, text="Hex")

    # ----------------------------------------------------------- uruchamianie analizy
    def _czekaj(self, opis):
        ustaw_baner(self.baner, f"⏳ Analizuję: {opis}…", ZIELONY_CIEMNY)
        for b in (self.b_raport, self.b_kwar, self.b_vt, self.b_def):
            b.config(state="disabled")

    def zbadaj_plik(self, sciezka):
        self.sciezka = sciezka
        self._czekaj(os.path.basename(sciezka))
        self.app.w_tle(silnik.analizuj_plik, sciezka, gotowe=self.pokaz_wynik, blad=self._blad)

    def zbadaj_kwarantanne(self, ident):
        self.sciezka = None
        self._czekaj("pojemnik " + ident)
        self.app.w_tle(silnik.analizuj_z_kwarantanny, ident, gotowe=self.pokaz_wynik, blad=self._blad)

    def wyczysc(self):
        """Czyści widok Laboratorium, żeby zacząć od zera."""
        self.wynik = None
        self.sciezka = None
        for b in (self.b_raport, self.b_kwar, self.b_vt, self.b_def):
            b.config(state="disabled")
        ustaw_baner(self.baner, "> Wybierz plik, aby rozpocząć analizę_", ZIELONY_CIEMNY)
        for d in (self.d_poch, self.d_zach):
            d.delete(*d.get_children())
        for tx in (self.t_podsum, self.t_strukt, self.t_ciagi, self.t_ioc, self.t_hex):
            ustaw_tekst(tx, "")
        self.l_ciagi.config(text="")

    def _blad(self, e):
        ustaw_baner(self.baner, f"Błąd analizy: {e}", KOLOR_WERDYKTU["ZŁOŚLIWY"])

    # ------------------------------------------------------------- prezentacja
    def pokaz_wynik(self, w):
        self.wynik = w
        zrodlo = "  (z kwarantanny)" if w.get("id_kwarantanny") else ""
        ustaw_baner(self.baner, f"{w['werdykt']}  ·  {w['punkty']}/100  ·  {w['nazwa']}{zrodlo}",
                    KOLOR_WERDYKTU.get(w["werdykt"], ZIELONY))
        self.b_raport.config(state="normal")
        self.b_vt.config(state="normal")
        na_dysku = bool(self.sciezka and os.path.exists(self.sciezka))
        self.b_kwar.config(state="normal" if na_dysku else "disabled")
        self.b_def.config(state="normal" if na_dysku else "disabled")   # Defender skanuje plik z dysku

        ustaw_tekst(self.t_podsum, "\n\n".join(w["podsumowanie"]))

        self.d_poch.delete(*self.d_poch.get_children())
        etykiety = {"sciezka": "Ścieżka", "oryginalna_sciezka": "Oryginalna ścieżka",
                    "data_kwarantanny": "W kwarantannie od", "strefa": "Strefa (Znak sieci)",
                    "pobrano_z": "Pobrano z adresu", "strona_odsylajaca": "Strona odsyłająca",
                    "utworzono": "Utworzono", "zmodyfikowano": "Zmodyfikowano",
                    "ostatni_dostep": "Ostatni dostęp", "uwaga_lokalizacja": "Lokalizacja"}
        poch = w.get("pochodzenie") or {}
        for k, e in etykiety.items():
            if poch.get(k):
                v = silnik.rozbroj(poch[k]) if k in ("pobrano_z", "strona_odsylajaca") else poch[k]
                self.d_poch.insert("", "end", values=(e, v))
        if poch.get("podpis"):
            self.d_poch.insert("", "end", values=("Podpis cyfrowy",
                                                  f"{poch['podpis']['status']}  {poch['podpis']['wystawca']}"))
        elif w.get("pe") and not w["pe"].get("ma_podpis"):
            self.d_poch.insert("", "end", values=("Podpis cyfrowy", "BRAK – nie wiadomo, kto stworzył program"))
        for k, v in (w.get("wersja") or {}).items():
            self.d_poch.insert("", "end", values=(k, v))
        if w.get("defender"):
            self.d_poch.insert("", "end", values=("Microsoft Defender", w["defender"]["opis"]))
        if w.get("vt"):
            self.d_poch.insert("", "end", values=("VirusTotal", w["vt"]["opis"]))
        if not os.name == "nt" and not poch.get("strefa"):
            self.d_poch.insert("", "end", values=("Uwaga", "Informacja „skąd pobrano” dostępna jest na Windows"))

        self.d_zach.delete(*self.d_zach.get_children())
        for z in sorted(w["znaleziska"], key=lambda z: -z["waga"]):
            tag = "ZŁOŚLIWY" if z["waga"] >= 30 else "PODEJRZANY" if z["waga"] >= 15 else ""
            self.d_zach.insert("", "end", tags=(tag,), values=(z["kategoria"], z["opis"], z["dowod"], z["waga"]))

        ustaw_tekst(self.t_strukt, self._tekst_struktury(w))
        self._pokaz_ciagi()
        ustaw_tekst(self.t_ioc, self._tekst_ioc(w))
        ustaw_tekst(self.t_hex, w.get("hex", ""))
        self.zakladki.select(0)

    def _tekst_struktury(self, w):
        linie = [f"Nazwa:     {w['nazwa']}", f"Typ:       {w['typ']}",
                 f"Rozmiar:   {silnik.rozmiar_czytelny(w['rozmiar'])} ({w['rozmiar']} B)",
                 f"Entropia:  {w['entropia']} / 8   (powyżej ~7.2 = skompresowany lub zaszyfrowany)", ""]
        linie += [f"{k.upper():<7}    {v}" for k, v in w["hashe"].items()]
        pe = w.get("pe")
        if pe and "blad" not in pe:
            linie += ["", "── PROGRAM WINDOWS (PE) " + "─" * 40,
                      f"Architektura:     {pe['architektura']}",
                      f"Rodzaj:           {'biblioteka DLL' if pe['dll'] else 'program ' + pe['podsystem']}",
                      f"Data kompilacji:  {pe['data_kompilacji']}",
                      f"Punkt wejścia:    {pe['punkt_wejscia']}",
                      f".NET:             {'tak' if pe['dotnet'] else 'nie'}",
                      f"Podpis cyfrowy:   {'jest' if pe['ma_podpis'] else 'brak'}",
                      f"Dane na końcu:    {silnik.rozmiar_czytelny(pe['nadmiar_bajtow'])}",
                      "", "SEKCJE  (X = wykonywalna, W = zapisywalna)",
                      f"  {'nazwa':<10}{'rozmiar':>12}{'entropia':>10}  prawa"]
            for s in pe["sekcje"]:
                linie.append(f"  {s['nazwa']:<10}{silnik.rozmiar_czytelny(s['rsize']):>12}"
                             f"{s['entropia']:>10}  {'X' if s['wykonywalna'] else '-'}"
                             f"{'W' if s['zapisywalna'] else '-'}")
            podejrzane = {f for _, (_, _, l) in silnik.API_PODEJRZANE.items() for f in l}
            linie += ["", "IMPORTOWANE FUNKCJE  (★ = podejrzana)"]
            for dll, funkcje in pe["importy"].items():
                linie.append(f"  {dll}  ({len(funkcje)})")
                for f in funkcje:
                    linie.append(f"      {'★' if f in podejrzane else ' '} {f}")
        elif pe:
            linie += ["", pe["blad"]]
        if w.get("zawartosc_archiwum"):
            linie += ["", "── ZAWARTOŚĆ ARCHIWUM / DOKUMENTU " + "─" * 30]
            linie += ["  " + n for n in w["zawartosc_archiwum"]]
        return "\n".join(linie)

    def _tekst_ioc(self, w):
        ioc = w.get("ioc") or {}
        linie = ["Wskaźniki naruszenia (IOC) – adresy i ślady, które można zablokować",
                 "w zaporze lub zgłosić. Adresy są „rozbrojone” (hxxp, [.]).", ""]
        for k, n in (("adresy_url", "ADRESY URL"), ("adresy_ip", "ADRESY IP"),
                     ("emaile", "E-MAILE"), ("klucze_rejestru", "KLUCZE REJESTRU")):
            linie.append(f"── {n} ({len(ioc.get(k, []))})")
            for x in ioc.get(k, []):
                linie.append("  " + (silnik.rozbroj(x) if k in ("adresy_url", "adresy_ip") else x))
            linie.append("")
        return "\n".join(linie)

    def _pokaz_ciagi(self):
        if not self.wynik:
            return
        f = self.filtr.get().lower()
        ciagi = [c for c in self.wynik.get("ciagi", []) if f in c.lower()]
        self.l_ciagi.config(text=f"{len(ciagi)} z {len(self.wynik.get('ciagi', []))}")
        ustaw_tekst(self.t_ciagi, "\n".join(ciagi[:5000]))

    # ------------------------------------------------------------------ akcje
    def raport(self):
        if not self.wynik:
            return
        sciezka = silnik.zapisz_raport(self.wynik)
        if messagebox.askyesno("Raport zapisany", f"Zapisano:\n{sciezka}\n\nOtworzyć w przeglądarce?"):
            otworz_systemowo(sciezka)

    def do_kwarantanny(self):
        if not (self.sciezka and self.wynik):
            return
        if messagebox.askyesno("Kwarantanna", f"Zamknąć „{self.wynik['nazwa']}” w kwarantannie?\n"
                                              "Oryginał zostanie usunięty z obecnego miejsca."):
            try:
                meta = silnik.do_kwarantanny(self.sciezka, self.wynik)
                self.wynik["id_kwarantanny"] = meta["id"]
                self.sciezka = None
                self.b_kwar.config(state="disabled")
                messagebox.showinfo("Kwarantanna", "Plik zamknięty w pojemniku.")
            except Exception as e:  # noqa: BLE001
                messagebox.showerror("Błąd", str(e))

    def defender(self):
        """Pyta Microsoft Defendera o ten plik i dopisuje jego werdykt do wyniku."""
        if not (self.sciezka and self.wynik):
            return
        self.wynik["sciezka"] = self.sciezka
        ustaw_baner(self.baner, "⏳ Microsoft Defender sprawdza plik (może to potrwać chwilę)…",
                    ZIELONY_CIEMNY)
        self.b_def.config(state="disabled")
        self.app.w_tle(silnik.dolacz_defendera, self.wynik, gotowe=self._po_defenderze,
                       blad=self._blad)

    def _po_defenderze(self, w):
        self.pokaz_wynik(w)
        if w["defender"]["status"] in ("brak", "blad"):
            messagebox.showinfo("Microsoft Defender", w["defender"]["opis"])

    def virustotal(self):
        if not self.wynik:
            return
        klucz = self.app.ustawienia["vt_klucz"]
        if not klucz:
            webbrowser.open("https://www.virustotal.com/gui/file/" + self.wynik["hashe"]["sha256"])
            messagebox.showinfo("VirusTotal", "Otworzyłem stronę VirusTotal w przeglądarce.\n\nZ kluczem API "
                                "(Ustawienia → Integracje) Capsule zapyta VirusTotal sam i dopisze wynik "
                                "do oceny. Wysyłany jest tylko skrót pliku (hash), nigdy sam plik.")
            return
        ustaw_baner(self.baner, "⏳ Pytam VirusTotal o skrót pliku…", ZIELONY_CIEMNY)
        self.b_vt.config(state="disabled")
        self.app.w_tle(silnik.dolacz_vt, self.wynik, klucz, gotowe=self._po_vt, blad=self._blad)

    def _po_vt(self, w):
        self.pokaz_wynik(w)
        if w["vt"]["status"] in ("klucz", "limit", "blad"):
            messagebox.showinfo("VirusTotal", w["vt"]["opis"])


# =========================================================================== RAPORTY
class StronaRaporty(tk.Frame):
    def __init__(self, rodzic, app: Capsule):
        super().__init__(rodzic, bg=TLO)
        self.app = app
        naglowek(self, "Raporty", "Zapisane raporty z analiz – czytelne dla każdego, do wysłania lub wydruku")
        ramka, self.drzewo = tabela(self, ("Data", "Plik raportu"), (170, 700))
        ramka.pack(fill="both", expand=True)
        self.drzewo.bind("<Double-1>", lambda e: self.otworz())
        dol = tk.Frame(self, bg=TLO)
        dol.pack(fill="x", pady=(10, 0))
        ttk.Button(dol, text="🌐 Otwórz w przeglądarce", style="Akcent.TButton",
                   command=self.otworz).pack(side="left")
        ttk.Button(dol, text="🗑 Usuń", command=self.usun).pack(side="left", padx=8)
        ttk.Button(dol, text="📂 Pokaż folder", command=lambda: otworz_systemowo(
            os.path.join(silnik.katalog_danych(), "raporty"))).pack(side="right")

    def odswiez(self):
        import datetime as dt
        self.drzewo.delete(*self.drzewo.get_children())
        for p in silnik.lista_raportow():
            kiedy = dt.datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")
            self.drzewo.insert("", "end", iid=p, values=(kiedy, os.path.basename(p)))

    def otworz(self):
        sel = self.drzewo.selection()
        if sel:
            otworz_systemowo(sel[0])

    def usun(self):
        sel = self.drzewo.selection()
        if sel and messagebox.askyesno("Usuń", "Usunąć zaznaczony raport?"):
            os.remove(sel[0])
            self.odswiez()


# ===========================================================================
def instaluj():
    """--instaluj: skrót na pulpicie i w menu Start (uruchamiane przez zainstaluj.bat)."""
    root = tk.Tk()
    root.withdraw()
    try:
        dodatki.utworz_skroty()
        messagebox.showinfo("Capsule", "Gotowe!\n\nSkrót „Capsule” czeka na pulpicie i w menu Start.\n"
                            "Włączenie startu razem z Windows: Ustawienia → Uruchamiaj z Windows.")
    except OSError as e:
        messagebox.showerror("Capsule", f"Nie udało się utworzyć skrótu:\n{e}")
    root.destroy()


if __name__ == "__main__":
    argumenty = sys.argv[1:]
    if "--instaluj" in argumenty:
        instaluj()
        sys.exit(0)
    plik = next((a for a in argumenty if not a.startswith("--") and os.path.isfile(a)), None)
    instancja = dodatki.JednaInstancja()
    if not instancja.zajmij():                     # inna kopia już działa (np. w zasobniku)
        instancja.obudz_dzialajaca(plik)
        sys.exit(0)
    app = Capsule(ukryty="--ukryty" in argumenty)
    app.instancja = instancja
    instancja.nasluchuj(lambda sc: app.kolejka.put((app.pokaz_okno, (sc,))))
    if plik:
        app.after(300, lambda: app.analizuj_plik(plik))
    app.mainloop()
