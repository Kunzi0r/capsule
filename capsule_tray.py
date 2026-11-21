# -*- coding: utf-8 -*-
"""
Capsule – ikona w zasobniku systemowym (przy zegarze).

Wymaga pakietów pystray i Pillow (zainstaluje je zainstaluj.bat). Bez nich program
działa normalnie, tylko nie chowa się do zasobnika.

Wywołania zwrotne (callbacki) są uruchamiane w WĄTKU zasobnika, więc okno Tk
musi je przekazywać do swojej kolejki zdarzeń (robi to capsule.py).
"""

from __future__ import annotations


def dostepny() -> bool:
    try:
        import pystray  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except Exception:
        return False


class Zasobnik:
    def __init__(self, tytul: str, otworz, przelacz_straznika, szybki_skan, zamknij,
                 straznik_dziala):
        """Wszystkie argumenty poza `tytul` to funkcje bezargumentowe."""
        import pystray
        import capsule_ikona
        self._pystray = pystray
        self._ok = capsule_ikona.rysuj(64)
        self._alarm = capsule_ikona.rysuj(64, alarm=True)
        self._tytul = tytul
        menu = pystray.Menu(
            pystray.MenuItem("Otwórz Capsule", lambda i, m: otworz(), default=True),
            pystray.MenuItem("Strażnik włączony", lambda i, m: przelacz_straznika(),
                             checked=lambda m: bool(straznik_dziala())),
            pystray.MenuItem("Szybki skan", lambda i, m: szybki_skan()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Zamknij Capsule", lambda i, m: zamknij()),
        )
        self.ikona = pystray.Icon("Capsule", self._ok, tytul, menu)
        self._dziala = False

    def start(self):
        if not self._dziala:
            self.ikona.run_detached()
            self._dziala = True

    def stop(self):
        if self._dziala:
            try:
                self.ikona.stop()
            except Exception:
                pass
            self._dziala = False

    def ustaw_alarm(self, alarm: bool):
        try:
            self.ikona.icon = self._alarm if alarm else self._ok
            self.ikona.title = self._tytul + (" – WYKRYTO ZAGROŻENIE" if alarm else "")
        except Exception:
            pass

    def powiadom(self, tytul: str, tekst: str):
        try:
            self.ikona.notify(tekst, tytul)
        except Exception:
            pass

    def odswiez_menu(self):
        try:
            self.ikona.update_menu()
        except Exception:
            pass
