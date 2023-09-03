# SoTLoader, Injector DLL pentru jocul Sea of Thieves

Acesta este un simplu injector DLL pentru jocul **Sea of Thieves** care a fost creat dintr-un mesaj pe `UnknownCheats`. Injectorul se bazează pe metoda `CreateRemoteThread` și folosește funcția `LoadLibrary` pentru a încărca DLL-ul în procesul de joc (Jocul nu are anti-cheat).

Acest software este destinat a fi utilizat numai în scopuri educaționale. Nu sunt responsabil pentru orice daune/bane-uri cauzate de acesta.

### Avertizare
Acest software este oferit "așa cum este", fără nici un fel de garanție. Autorul nu este răspunzător pentru orice daune cauzate de acest software.

## Locație
Acest injector detectează automat limba utilizatorului și va afișa șirurile de caractere în următoarele limbi:
- English
- Español
- Русский (gracias a exzyyy)
- Română (mulțumită lui Ryukagu08)

Nu ezitați să contribuiți cu mai multe limbi.

## Instrucțiuni de utilizare
1. Descărcați cea mai recentă versiune de pe [pagina de versiuni](https://github.com/holasoyender/SoTLoader/releases)
2. Extrageți fișierul zip
3. Mutați fișierul sau fișierele DLL pe care doriți să le injectați în folderul `libs` (creați-l dacă nu există).
4. Rulați executabilul, dacă mutați mai mult de un fișier DLL în dosar, veți fi întrebat pe care doriți să îl injectați.

## Descărcați DLL
Dacă doriți să descărcați DLL, rulați din nou executabilul și veți fi întrebat dacă doriți să descărcați DLL.

## Cum se compilează
1. Clonați depozitul
2. Deschideți fișierul de soluție cu Visual Studio 2022 sau o versiune mai recentă.
3. Compilați proiectul pentru `Release x64`.

## Credite
Copyright (C) 2023 holasoyender, under the [GPL-3.0 License](../LICENSE)