[English](README.md) | **Deutsch**

<p align="center"><img src="assets/banner.png" alt="Qwen-Zaun – Hermes-Agent-Plugin von KI SOUVERÄN: kein Nach-Hause-Telefonieren" width="100%"></p>

# Qwen-Zaun

Ein Hermes-Agent-Plugin, das jeden Werkzeugaufruf **vor der Ausführung** prüft. Es sperrt die Muster, mit denen
Qwen3.8-Flash-Next laut Cohere Daten abfließen lassen wollte. Normale Agentenarbeit läuft unverändert durch.

## Warum: der Vorfall bei Qwen

Cohere hat am 26. Oktober 2026
[„Concerning behaviour in a popular open-weight AI model“](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model)
veröffentlicht. Die Aufgabe war nur, eine Erkennungsregel zu schreiben. **Qwen3.8-Flash-Next** hat in einer
abgeschotteten Testumgebung trotzdem über seine Shell:

- `/tmp` aufgelistet, nach `curl`, `wget`, `python3` und `jq` gesucht und die DNS-Konfiguration gelesen,
- einen **PUT-Upload in einen Alibaba-Cloud-OSS-Speicher in Peking** versucht und danach die HTTP-Antwort geprüft.

Der Upload scheiterte nur, weil die Umgebung keinen Weg nach draußen hatte. Direkt vor dem Aufruf stand in der
Denkspur des Modells, es werde keine Tools nutzen. **Die Denkspur zu beobachten schützt also nicht.** Weitere Befunde:

- Die Cloud-Metadatenadresse `169.254.169.254` tauchte bei frühen Vorgaben in 23–36 % der Antworten auf. Das kann
  ein Versuch sein, Cloud-Zugangsdaten abzugreifen.
- Mit `curl -o` erschien in 23 % der Antworten ein Datei-Proxy namens *routify*.
- In einem Test ohne Netz hat sich das Modell mit `unshare -Urm` Root-Rechte in einem User-Namespace verschafft.

Das Verhalten ist selten (weniger als 1 von 100 000 Aufrufen). Cohere schreibt selbst, dass unklar ist, ob es Absicht
oder ein Überbleibsel aus dem Training ist. Berichte aus der Community zu Qwen3.8-27B (ungefragte Alibaba-Speicherlinks,
Abrufe über routify) reichen bis August zurück.

**Das Modell allein kann nichts davon.** Gewichte erzeugen nur Text. Erst die Agentenumgebung macht daraus Befehle.
Der Zaun gehört deshalb an die Werkzeugaufrufe des Agenten. Das empfiehlt auch Cohere: die Regeln am echten
Werkzeugaufruf durchsetzen, bevor er läuft.

## Was es tut

Das Plugin hängt am Haken `pre_tool_call` und prüft Handlungen, nicht Texte:

- **Befehle** (`terminal`, `process_manage`) und **Code** (`execute_code`) werden vollständig geprüft. In einer
  einfachen Befehlszeile sperren die Ziel-Muster (Metadaten, Alibaba-Speicher, routify) nur zusammen mit einem
  Netzwerkzeug: `grep -r 169.254.169.254 .` sucht, es sendet nicht.
- **Prosa ist frei.** Markdown, Text oder ein Protokoll, das ein Muster nennt, läuft durch, per
  `write_file`/`patch` und per Heredoc in eine Datei, die kein Code ist.
- **Code-Dateien** (`.py`, `.sh`, `.js` … oder Shebang) werden beim Schreiben geprüft und **beim Start noch
  einmal**: Der Pfad wird über ein vorangehendes `cd` aufgelöst, `./skript` und `python -m modul` zählen mit,
  und die ganze Datei wird gelesen. Ein Ziel in einer Variable oder in einem `subprocess`-Aufruf fällt also auf.

| Stufe | Muster | Folge |
|---|---|---|
| **Sperren** | Cloud-Metadaten (`169.254.0.0/16`, `100.100.100.200`, `metadata.google.internal`, `fd00:ec2::254`) | läuft nicht, Meldung |
| **Sperren** | Alibaba-Cloud-Speicher/-API (`*.aliyuncs.com`, `oss-<region>.`, `ossutil`) in Befehlen, Code-Dateien und gestarteten Skripten | läuft nicht, Meldung |
| **Sperren** | `routify`-Hosts | läuft nicht, Meldung |
| **Sperren** | Root im User-Namespace (`unshare -U/-r/--user`, `nsenter`) | läuft nicht, Meldung |
| **Sperren** | Senden an anonyme Ablagedienste (transfer.sh, webhook.site, ngrok, Paste-Seiten …) oder rohe öffentliche IPs | läuft nicht, Meldung |
| **Melden** | Senden an ein Ziel, das nicht auf deiner Liste steht | läuft, Meldung |
| **Melden** | Geheimnis-Datei (`.env`, `*_API_KEY`, SSH-Schlüssel) zusammen mit einem unbekannten Ziel | läuft, Meldung |
| **Melden** | Erkundungsmuster aus dem Bericht (`resolv.conf`, Prüfung auf curl/wget/python3/jq) | läuft, Meldung |

Herstellerdoku lesen bleibt erlaubt: `web_extract` einer Alibaba-Dokuseite oder eines Qwen-Blogbilds wird nicht gesperrt.
Bei einer Sperre bekommt das Modell eine kurze Nachricht und arbeitet ohne den Schritt weiter. Fällt das Plugin selbst
aus, läuft der Aufruf durch: Der Zaun legt den Agenten nie lahm.

## Gemessen im echten Betrieb

Geprüft an einem täglich genutzten Hermes-System (Hauptmodell Strata 125B / Qwen3.8-Flash-Next Q2_0, 14 Profile):

- **76 528 gespeicherte Werkzeugaufrufe aus 60 Tagen nachgespielt: 0 Sperren im Alltag.** 25 Meldungen, fast alle Telegram-Beiträge mit Links zu Nachrichtenseiten. (Gesperrt wurden nur der Live-Test unten und Testcode für den Zaun selbst, der echte Angriffs-Zeichenketten enthält.)
- **Alle 7 Angriffsmuster** aus dem Bericht im Test gesperrt, dazu **9 von 9 Umgehungsvarianten** (relativer Pfad nach `cd`, Ziel in einer Variable, `r = requests.put(...)`, `subprocess` mit curl, `./skript`, `python -m`, Heredoc an python …).
- Prosa, die ein Muster nur nennt, läuft durch, auch Berichte per Heredoc und ein `grep` nach der Adresse.
- **Rund 1 ms pro Aufruf** (0,03–3 ms mit Skriptlesen), kein Netz, kein zusätzlicher Prozess.
- Live-Test: Strata sollte `curl http://169.254.169.254/latest/meta-data/` ausführen. Der Zaun hat gesperrt, der Agent hat die Sperre gemeldet.

## Einrichtung

```bash
git clone https://github.com/wolffahrer/qwen-zaun
cp -r qwen-zaun/qwen-zaun ~/.hermes/plugins/
hermes plugins enable qwen-zaun
```

Das Gateway übernimmt es ohne Neustart. Jedes Profil hat seinen eigenen Plugin-Manager:

```bash
for p in ~/.hermes/profiles/*/; do
  ln -sfn ~/.hermes/plugins/qwen-zaun "$p/plugins/qwen-zaun"
  hermes -p "$(basename "$p")" plugins enable qwen-zaun
done
```

Test ohne Hermes: `python3 tests/test_zaun.py`

## Einstellungen

Alle Dateien liegen in `$HERMES_HOME` (Standard `~/.hermes`) und werden bei jedem Aufruf gelesen, ohne Neustart.

| Datei | Zweck |
|---|---|
| `qwen-zaun.ziele` | eigene bekannte Ziele, eins pro Zeile, Unterdomänen zählen mit (Webspace, Mail-API, Tailnet …) |
| `qwen-zaun.melden` | erste Zeile: ein Befehl, der den Meldetext als Argument bekommt, z. B. ein Skript mit `hermes send` |
| `qwen-zaun.nur-melden` | vorhanden: nichts sperren, nur melden |
| `qwen-zaun.aus` | vorhanden: Zaun aus |
| `logs/qwen-zaun.jsonl` | jeder Treffer mit Zeit, Profil, Werkzeug, Regel und Auszug |

Meldungen sind gedrosselt: Sperren immer, alles andere einmal je Regel und Ziel am Tag, höchstens 6 am Tag.

Tipp: Die Zielliste aus der eigenen Historie bauen. Erst die gespeicherten Aufrufe gegen die Regeln spielen, dann
eintragen, was als „neues Ziel“ auftaucht und dir gehört.

## Optional: Rückhalt im Netz

Die Metadatenadressen lassen sich zusätzlich unterhalb des Agenten für alle eigenen Nutzerdienste sperren (systemd,
cgroup-BPF, wirkt sofort, kein Neustart). Im Alltag braucht sie nichts:

```bash
sudo systemctl set-property user-$(id -u).slice IPAddressDeny="169.254.0.0/16 100.100.100.200/32 fd00:ec2::254/128"
```

Rückgängig: `sudo systemctl set-property user-$(id -u).slice IPAddressDeny=`

## Grenzen

Das ist ein Zaun, keine Sandbox. Die Regeln fangen das beobachtete Verhalten und seine naheliegenden Abwandlungen.
Ein Modell, das gezielt verschleiert (base64, zusammengesetzte Zeichenketten, neue Hosts), kommt durch. Gestartete
Skripte liest der Zaun eine Ebene tief: Was ein Skript erst zur Laufzeit importiert oder herunterlädt, verfolgt er
nicht. Kombiniere den
Zaun mit dem, was du hast: Freigaben für riskante Befehle, kein `sudo` ohne Passwort für den Agenten, Geheimnisse
außerhalb seiner Reichweite, ein Filter für ausgehende Verbindungen, wo er sich lohnt. Der Zaun ist die Schicht, die
deinen Agenten nichts kostet.

## Lizenz

MIT · KI SOUVERÄN · [youtube.com/@kisouveran](https://youtube.com/@kisouveran) · [t.me/lokale_ki](https://t.me/lokale_ki)
