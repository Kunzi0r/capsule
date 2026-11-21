# -*- coding: utf-8 -*-
"""
Capsule – ikona programu (rysowana kodem, bez plików graficznych).

Czarna kafelka z zieloną kapsułą (pigułką) ustawioną po przekątnej.
Wariant „alarm” ma czerwoną drugą połówkę (używany w zasobniku przy wykryciu).
Pillow jest potrzebny tylko do narysowania ikony. Gotowy plik capsule.ico
leży obok programu, więc samo okno i skróty działają także bez Pillow.
"""

from __future__ import annotations

TLO = (3, 6, 3, 255)
RAMKA = (15, 90, 42, 255)
ZIELONY = (51, 255, 102, 255)
ZIELONY_CIEMNY = (31, 158, 68, 255)
POLOWA_PUSTA = (10, 30, 16, 255)
CZERWONY = (255, 77, 77, 255)
BLASK = (190, 255, 205, 255)


def rysuj(rozmiar: int = 256, alarm: bool = False):
    """Zwraca obraz PIL.Image RGBA o podanym rozmiarze."""
    from PIL import Image, ImageDraw, ImageFilter

    ss = 4                                   # supersampling = gładkie krawędzie
    n = rozmiar * ss
    obraz = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(obraz)
    promien = int(n * 0.22)
    d.rounded_rectangle((0, 0, n - 1, n - 1), radius=promien, fill=TLO)
    grub = max(ss * 2, int(n * 0.025))
    d.rounded_rectangle((grub // 2, grub // 2, n - 1 - grub // 2, n - 1 - grub // 2),
                        radius=promien - grub // 2, outline=RAMKA, width=grub)

    # kapsuła narysowana poziomo na osobnej warstwie, potem obrócona o 45°
    warstwa = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    w = ImageDraw.Draw(warstwa)
    dl, szer = int(n * 0.64), int(n * 0.27)
    x0, y0 = (n - dl) // 2, (n - szer) // 2
    x1, y1 = x0 + dl, y0 + szer
    r = szer // 2
    srodek = (x0 + x1) // 2
    kolor_prawej = CZERWONY if alarm else ZIELONY_CIEMNY

    # lewa połowa: pełna zieleń
    w.rounded_rectangle((x0, y0, x1, y1), radius=r, fill=ZIELONY)
    # prawa połowa: przycięta do prawej strony (maska)
    prawa = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    p = ImageDraw.Draw(prawa)
    p.rounded_rectangle((x0, y0, x1, y1), radius=r, fill=(CZERWONY if alarm else POLOWA_PUSTA))
    maska = Image.new("L", (n, n), 0)
    ImageDraw.Draw(maska).rectangle((srodek, 0, n, n), fill=255)
    warstwa.paste(prawa, (0, 0), maska)
    # obrys całej kapsuły i linia podziału
    gr = max(ss * 2, int(n * 0.022))
    w.rounded_rectangle((x0, y0, x1, y1), radius=r, outline=ZIELONY if not alarm else CZERWONY, width=gr)
    w.line((srodek, y0, srodek, y1), fill=ZIELONY, width=gr)
    # odblask na lewej połowie
    w.rounded_rectangle((x0 + r // 2, y0 + int(szer * 0.16), srodek - gr * 2, y0 + int(szer * 0.30)),
                        radius=int(szer * 0.07), fill=BLASK)
    # kropki na prawej połowie (w stylu terminala)
    for i in range(3):
        cx = srodek + int(dl * 0.12) + i * int(dl * 0.1)
        w.ellipse((cx - gr, (y0 + y1) // 2 - gr, cx + gr, (y0 + y1) // 2 + gr),
                  fill=kolor_prawej if not alarm else (255, 200, 200, 255))

    warstwa = warstwa.rotate(45, resample=Image.BICUBIC)
    # lekka poświata wokół kapsuły
    poswiata = warstwa.filter(ImageFilter.GaussianBlur(n * 0.018))
    obraz = Image.alpha_composite(obraz, poswiata)
    obraz = Image.alpha_composite(obraz, warstwa)
    # przytnij do zaokrąglonego kwadratu (poświata nie wychodzi poza kafelkę)
    maska_kafla = Image.new("L", (n, n), 0)
    ImageDraw.Draw(maska_kafla).rounded_rectangle((0, 0, n - 1, n - 1), radius=promien, fill=255)
    wynik = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    wynik.paste(obraz, (0, 0), maska_kafla)
    return wynik.resize((rozmiar, rozmiar), Image.LANCZOS)


def zapisz_ico(sciezka: str):
    """Zapisuje wielorozmiarowy plik .ico (16–256 px)."""
    rysuj(256).save(sciezka, format="ICO",
                    sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    import os
    zapisz_ico(os.path.join(os.path.dirname(os.path.abspath(__file__)), "capsule.ico"))
    print("Zapisano capsule.ico")
