# Capsule – skaner, kwarantanna i laboratorium złośliwych plików

Aplikacja na komputer z pulpitem, która:
1. **skanuje** foldery i wyłapuje podejrzane pliki,
2. **zamyka je w kwarantannie** (zaszyfrowany „pojemnik”, z którego plik nie może się uruchomić),
3. **otwiera pojemnik w laboratorium** i rozkłada plik na czynniki pierwsze: skąd się wziął i co miał robić,
4. **tworzy raporty HTML** zrozumiałe dla zwykłego człowieka,
5. **pilnuje folderów na bieżąco (Strażnik)** i pokazuje powiadomienie, gdy pojawi się groźny plik,
6. **współpracuje z Microsoft Defenderem**: pyta go o werdykt i tłumaczy jego wykrycia po ludzku,
7. **audytuje system (Windows)**: autostart, działające procesy i połączenia sieciowe, każde z oceną ryzyka.

> Program **nigdy nie uruchamia** badanych plików. Robi wyłącznie analizę statyczną, czyli czyta bajty pliku.

## Instalacja i uruchomienie (Windows)

1. Zainstaluj Pythona 3.10 lub nowszego z https://www.python.org (zaznacz „Add Python to PATH”).
2. **Wypakuj cały folder `Capsule` w stałe miejsce** (np. `C:\Capsule`). Skróty i autostart wskazują na ten folder, więc nie przenoś go później.
3. Kliknij dwukrotnie **`zainstaluj.bat`**. Doinstaluje pakiety `pystray` i `pillow` (ikona w zasobniku) i utworzy skrót **Capsule** na pulpicie oraz w menu Start.
4. Uruchamiaj Capsule skrótem z pulpitu (albo `uruchom.bat`).
5. W **Ustawieniach** zaznacz „Uruchamiaj Capsule razem z Windows”, jeśli ma startować sam i pracować w tle.

Bez `pystray` i `pillow` program też działa (analiza, Strażnik, skany), tylko nie chowa się do zasobnika.
Możesz od razu otworzyć konkretny plik: `python capsule.py C:\ścieżka\do\pliku.exe`.
Opcjonalnie: `pip install yara-python`, a potem wrzuć reguły `.yar` do `%LOCALAPPDATA%\Capsule\reguly_yara`.

## Praca w tle (nowość w 0.4)

- **Ikona w zasobniku** (przy zegarze): kliknięcie otwiera okno, prawy przycisk daje menu (Otwórz, Strażnik włączony, Szybki skan, Zamknij Capsule). Ikona robi się **czerwona**, gdy coś wykryto.
- **X i minimalizacja chowają okno do zasobnika**, a Strażnik, skany zaplanowane i pułapka na ransomware pracują dalej. Przy pierwszym schowaniu pojawia się powiadomienie z wyjaśnieniem. Pełne wyłączenie: prawy przycisk na ikonie → *Zamknij Capsule*. Zachowanie X można zmienić w Ustawieniach.
- **Powiadomienia przy schowanym oknie** przychodzą z zasobnika jako powiadomienia Windows. Przy otwartym oknie pokazują się jako okienko w rogu.
- **Tylko jedna kopia**: ponowne uruchomienie skrótu nie startuje drugiej, tylko wyciąga okno pierwszej z zasobnika.
- **Start z Windows**: `capsule.py --ukryty` startuje od razu w zasobniku (tak robi wpis autostartu).

Wygląd: czarne tło i zielona czcionka w stylu terminala. Zagrożenia nadal są wyróżnione kolorem (czerwony = złośliwy, bursztynowy = podejrzany).

Kwadracik przełączasz kliknięciem albo spacją (działa też na kilku podświetlonych wierszach naraz). Kwadracik w nagłówku zaznacza lub odznacza wszystko.

## Zakładki

| Zakładka | Co robi |
|---|---|
| **Pulpit** | Stan ochrony, liczniki, szybkie akcje i historia zdarzeń |
| **Ochrona** | Przełącznik **Strażnika**, opcje (auto-kwarantanna, Defender, powiadomienia), lista obserwowanych folderów, tabela wykryć z kwadracikami oraz zakładka **Microsoft Defender** (stan, świeżość sygnatur, historia wykryć wyjaśniona zwykłym językiem) |
| **System** | Trzy zakładki: **Autostart** (rejestr, folder Autostart, zadania harmonogramu, usługi), **Procesy** (z oceną i zamykaniem) oraz **Połączenia** (kto łączy się z internetem i jakie porty są otwarte na świat) |
| **Ustawienia** | Praca w tle (zasobnik, start z Windows, skrót), skan zaplanowany, integracje (VirusTotal, abuse.ch) i pułapka na ransomware |
| **Skaner** | Szybki skan (Pobrane, Pulpit, Temp, Autostart) albo dowolny folder. Przy każdym pliku jest kwadracik ☐/☑: złośliwe są zaznaczone od razu, podejrzane zaznaczasz sam. Są też przyciski *Zaznacz/Odznacz wszystkie* i *Tylko złośliwe* |
| **Kwarantanna** | Lista pojemników z kwadracikami: zaznaczone można przywrócić albo usunąć na stałe, a dwuklik otwiera pojemnik w laboratorium |
| **Laboratorium** | Przycisk *Zapytaj Defendera* i analiza pliku: *W skrócie*, *Pochodzenie*, *Zachowanie*, *Struktura* (sekcje, importy), *Ciągi znaków*, *IOC*, *Hex* |
| **Raporty** | Zapisane raporty HTML do otwarcia w przeglądarce |

## Strażnik (nowość w 0.2)

Strażnik co ok. 2 sekundy porównuje listę plików w obserwowanych folderach (domyślnie Pobrane, Pulpit, Temp i Autostart, razem z podfolderami do 2 poziomów).
- Plik jest analizowany dopiero, gdy **przestanie się zmieniać**, więc pobieranie w przeglądarce nie jest ruszane w trakcie (`.crdownload`, `.part`, `.tmp` są pomijane).
- To, co leżało w folderach przy włączeniu Strażnika, uznaje za tło i nie alarmuje.
- Przy wykryciu pojawia się **okienko w rogu ekranu**. Kliknięcie otwiera plik (albo pojemnik) w laboratorium.
- Podejrzane i złośliwe pliki są dodatkowo sprawdzane w **Microsoft Defenderze** (jego wykrycie dodaje 40 punktów do oceny).
- Opcja **auto-kwarantanna** zamyka złośliwe pliki w pojemniku od razu. Domyślnie jest wyłączona, więc to ty decydujesz kwadracikami.
- Stan Strażnika i opcje są zapamiętywane w `ustawienia.json`. Jeśli zamkniesz program z włączonym Strażnikiem, włączy się sam przy następnym uruchomieniu.

**Ważne:** Strażnik działa, dopóki Capsule jest uruchomiony (też schowany w zasobniku). Zauważa plik po zapisaniu go na dysk i **nie blokuje jego uruchomienia**. Blokowanie przed startem wymaga sterownika systemowego, którego nie da się zrobić w Pythonie. Dlatego Capsule ma działać **obok** Defendera, a nie zamiast niego.

## Skan zaplanowany

*Ustawienia → Ogólne*: codzienny szybki skan o wybranej godzinie. Działa, gdy Capsule jest uruchomiony (w tle wystarczy; włącz start z Windows). Jeśli komputer był wyłączony o tej porze, skan wykona się zaraz po starcie programu. Po skanie, który coś znalazł, przychodzi powiadomienie.

## VirusTotal (nowość w 0.4)

Wpisz darmowy klucz API w *Ustawienia → Integracje* (konto na virustotal.com). Wtedy przycisk **VirusTotal** w Laboratorium pyta o opinię ponad 70 silników i dopisuje ją do oceny (5 lub więcej wykryć = podejrzany, 10 lub więcej = złośliwy). Opcja *Strażnik sprawdza podejrzane pliki także w VirusTotal* robi to automatycznie.
**Do VirusTotal idzie wyłącznie skrót SHA-256, nigdy plik.** Darmowy limit to 4 zapytania na minutę i 500 dziennie. Bez klucza przycisk otwiera stronę pliku w przeglądarce.

## Aktualizacja sygnatur (nowość w 0.4)

*Ustawienia → Integracje* → Auth-Key z auth.abuse.ch (darmowy) → *Aktualizuj sygnatury teraz* albo raz na dobę automatycznie. Pobiera najświeższe hashe z MalwareBazaar (ostatnie ~48 godzin) i groźne adresy z URLhaus. Plik zawierający adres z listy dostaje +45 punktów, a znany hash jest rozpoznawany jako zagrożenie. **Uwaga:** dokumentacja eksportów abuse.ch jest za logowaniem, więc parsery są tolerancyjne i nie zostały sprawdzone na prawdziwych danych. Jeśli aktualizacja zgłosi błąd, komunikat pojawi się w Ustawieniach.

## Pułapka na ransomware (nowość w 0.4)

*Ustawienia → Pułapka na ransomware*: w folderach Dokumenty, Pulpit i Obrazy (albo własnych) powstają ukryte pliki `!_capsule_wabik.*`. Ransomware szyfruje pliki po kolei, a „!” sortuje się na początku. Gdy wabik zostanie zmieniony, usunięty albo przemianowany, Capsule alarmuje i pokazuje procesy, które w tej chwili najwięcej zapisywały na dysk (z kwadracikami i przyciskiem *Zakończ zaznaczone*). Opcja automatycznego zamykania podejrzanego procesu jest domyślnie wyłączona, bo może trafić w zwykły program.
To **sygnał ostrzegawczy, nie ochrona**: wykryje atak dopiero po ruszeniu pierwszego wabika, a pliki zaszyfrowane wcześniej nie wrócą. Prawdziwą obroną są kopie zapasowe. Sama zmiana daty wabika (np. przez backup) nie wywołuje alarmu, tylko zmiana zawartości. *Usuń wszystkie wabiki z dysku* sprząta po pułapce.

## System: autostart, procesy, połączenia (nowość w 0.3, tylko Windows)

Wszystkie trzy zakładki są domyślnie tylko do odczytu. Kliknij *Skanuj*, a Capsule oceni każdą pozycję.

**Jak oceniana jest pozycja:** program z **ważnym podpisem cyfrowym** jest uznawany za wiarygodny w każdym katalogu (oceniamy tylko jego polecenie i udawanie procesu systemowego, a nie importowane funkcje). Bez podpisu liczy się lokalizacja (Temp, Pobrane, AppData, ProgramData są podejrzane), brak pliku, udawanie procesu systemowego (np. `svchost.exe` poza `System32`), podejrzane polecenia (`-enc`, `IEX`, `-WindowStyle Hidden`, `mshta`…) oraz ta sama analiza statyczna co w Laboratorium. Progi werdyktu są takie same jak wszędzie.

- **Autostart:** *Wyłącz zaznaczone* jest **odwracalne**. Wpis rejestru albo plik z folderu Autostart jest kopiowany do `%LOCALAPPDATA%\Capsule\autostart_kopia.json`, a zadanie harmonogramu tylko wyłączane. *Przywróć wyłączone* cofa zmiany. Wpisy w HKLM wymagają uruchomienia Capsule jako administrator. Usług nie wyłączamy (tylko je pokazujemy).
- **Procesy:** *Zakończ zaznaczone* używa `taskkill`. Capsule odmawia zamknięcia krytycznych procesów Windows i samego siebie. Przed zamknięciem zawsze pyta o potwierdzenie.
- **Połączenia:** pokazuje ruch wychodzący do internetu i programy nasłuchujące na wszystkich adresach. Ruch w sieci lokalnej jest pomijany. Podnosi ocenę, gdy łączy się podejrzany program albo użyty jest port typowy dla backdoorów (4444, 1337, 31337, 6667, Tor…). Nie sprawdza reputacji adresów IP.

Wiele procesów tego samego programu (np. 20× `opera.exe`) jest pokazane jako jeden wiersz z liczbą `×N`. *Zakończ zaznaczone* zamyka wtedy wszystkie.

Pierwsze skanowanie procesów może potrwać kilkanaście sekund, bo sprawdzane są podpisy. Kolejne są szybsze (ocena jest zapamiętywana).

## Współpraca z Defenderem (tylko Windows)

- *Zapytaj Defendera* w laboratorium uruchamia `MpCmdRun.exe -Scan -ScanType 3 -File … -DisableRemediation`, czyli Defender ocenia plik, ale **niczego nie usuwa** w ramach tego zapytania.
- Zakładka *Microsoft Defender* w Ochronie czyta stan (`Get-MpComputerStatus`) i historię wykryć (`Get-MpThreatDetection`).
- Na innych systemach te funkcje pokazują komunikat, że Defender jest niedostępny.

## Co wykrywa laboratorium

- **Pochodzenie**: adres, z którego plik został pobrany, i strefę „Znaku sieci” (Windows zapisuje je w ukrytym strumieniu `Zone.Identifier`), daty utworzenia, podejrzane lokalizacje (Temp, AppData, Autostart), podpis cyfrowy (weryfikowany przez Windows), producenta i oryginalną nazwę programu.
- **Zachowanie programów .exe/.dll** (na podstawie importowanych funkcji): wstrzykiwanie kodu, keylogger, kradzież haseł, pobieranie plików, autostart, usługi, wykrywanie debuggera, zrzuty ekranu.
- **Pakowanie i ukrywanie**: entropię, UPX, sekcje zapisywalne i wykonywalne naraz, ukryte importy, dane doklejone na końcu.
- **Skrypty** (PowerShell, VBS, BAT, JS): zakodowane polecenia, `IEX`, pobieranie, usuwanie kopii zapasowych, wyłączanie Defendera, zadania harmonogramu, nadużywanie narzędzi systemowych (certutil, mshta, bitsadmin).
- **Dokumenty**: makra Office (także uruchamiane automatycznie), JavaScript i akcje w PDF, programy schowane w archiwach ZIP.
- **Sztuczki z nazwą**: `faktura.pdf.exe`, znak RLO, program udający inny typ pliku.
- **IOC**: adresy URL i IP, e-maile, klucze rejestru (zawsze „rozbrojone”, np. `hxxp://evil[.]com`).

Werdykt to punkty od 0 do 100: **CZYSTY** (<30), **PODEJRZANY** (30–69), **ZŁOŚLIWY** (≥70 albo znana sygnatura).

## Własne sygnatury i reguły

Program trzyma dane w `%LOCALAPPDATA%\Capsule\`:
- `znane_hashe.json`: dopisz `"sha256": "nazwa zagrożenia"`,
- `reguly.json`: proste reguły tekstowe (`ciagi`, `min`, `waga`),
- `kwarantanna\`, `raporty\`, `stan.json`.

## Jak bezpiecznie przetestować

Użyj pliku **EICAR**. To oficjalny, całkowicie nieszkodliwy plik testowy dla antywirusów (do pobrania z eicar.org).
Uwaga: Windows Defender też go wykryje i może go usunąć pierwszy. Na czas testu możesz dodać folder testowy do wyjątków Defendera.

## Ograniczenia prototypu

- Wzorce tekstowe (skrypty, makra, polecenia) są szukane w pierwszych 30 MB pliku w Laboratorium i w pierwszych 12 MB podczas skanowania. Struktura programu (PE: importy, sekcje, podpis) jest analizowana w całości. Dzięki temu skan dużych plików nie zamraża okna.

- To nie zastępuje antywirusa. Strażnik reaguje po fakcie (nie blokuje uruchomienia), a heurystyki mogą się mylić w obie strony.
- Strażnik, Defender i zakładkę System sprawdzono na prawdziwym Windows. Zasobnik, skrót, autostart, VirusTotal, aktualizacje sygnatur i pułapka na ransomware (0.4) przetestowano tylko na atrapach i danych przykładowych. Jeśli coś nie działa albo wygląda źle, wyślij zrzut ekranu.
- Kwarantanna szyfruje plik prostym kluczem XOR. Wystarcza to, żeby plik nie dał się uruchomić ani wykryć,
  ale nie jest to szyfrowanie „na wojnę”.
- Analiza dynamiczna (uruchamianie w odizolowanej maszynie wirtualnej) celowo nie jest dołączona.
