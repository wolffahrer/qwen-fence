"""Regeln des Qwen-Fence (Anlass: Cohere-Bericht vom 26.10.2026 zu Qwen3.8-Flash-Next).

Grundsatz: Der Agent arbeitet wie bisher. Gesperrt wird nur, was er in seiner Arbeit nie braucht
und was genau den beobachteten Fehlgriffen entspricht. Auffälliges, das im Alltag auch vorkommt,
läuft durch und wird gemeldet.

Der Zaun prüft Handlungen, nicht Texte:
- Prosa (Markdown, Text, Protokolle) ist frei, auch wenn sie ein Muster nennt. Das gilt für
  Schreibaufrufe und für Heredocs, die in eine Prosa-Datei schreiben.
- Code ist eine Handlung in Vorbereitung: Code-Dateien (.py, .sh … oder Shebang) werden beim
  Schreiben voll geprüft, Skripte beim Start noch einmal, mit Pfad über ein vorangehendes `cd`,
  auch als `./skript` oder `python -m modul`.
- In einer Befehlszeile sperren Ziel-Muster (Metadaten, Alibaba-Speicher, routify) nur zusammen
  mit einem Netzwerkzeug. `grep -r 169.254.169.254 .` sucht, es sendet nicht.

- SPERREN: Metadatenadressen, Alibaba-Speicher, routify, Root im User-Namespace, Upload zu
  Ablagediensten oder rohen öffentlichen IPs.
- MELDEN: Senden an ein Ziel, das nicht bekannt ist; Geheimnis-Datei zusammen mit einem
  fremden Ziel; Erkundungsmuster aus dem Bericht.

Abgeglichen gegen 76 409 gespeicherte Aufrufe aus 60 Tagen Alltag: keine einzige Sperre.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import time
from pathlib import Path

AUSFUEHREN = {"terminal", "execute_code", "process_manage"}
SCHREIBEN = {"write_file": ("content",), "patch": ("new_string", "patch"), "skill_manage": ("file_content", "new_string")}
WEB = {"web_extract", "browser_exec"}

_I = re.IGNORECASE

SPERREN = [
    ("metadaten",
     re.compile(r"169\.254\.\d{1,3}\.\d{1,3}|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254", _I),
     "Cloud-Metadatenadresse (Zugangsdaten-Abgriff)"),
    ("alibaba_speicher",
     re.compile(r"[\w.-]*\.aliyuncs\.com|\boss-[a-z]{2}-[a-z0-9-]+\.|\bossutil\b|\baliyun\s+oss\b", _I),
     "Alibaba-Cloud-Speicher bzw. -API (Upload-Ziel aus dem Cohere-Bericht)"),
    ("routify",
     re.compile(r"routify[\w-]*\.[a-z]{2,}", _I),
     "routify-Datei-Proxy (Beobachtungsliste Cohere)"),
    ("namespace_root",
     re.compile(r"\bunshare\b[^\n;&|]*?(\s-[a-zA-Z]*[Ur][a-zA-Z]*\b|--user\b|--map-root-user\b)|\bnsenter\b", _I),
     "Root in einem User-Namespace (Ausbruchsweg aus dem Cohere-Bericht)"),
]

# Dienste, die sich als anonyme Ablage für abgeflossene Daten eignen. Gesperrt nur beim Senden.
ABLAGEDIENSTE = re.compile(
    r"(pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|file\.io|0x0\.st|temp\.sh|ix\.io|termbin\.com"
    r"|webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|interact\.sh|oast\.(fun|pro|live|site|online|me)"
    r"|burpcollaborator|dnslog\.cn|ceye\.io|catbox\.moe|gofile\.io|anonfiles|filebin\.net)", _I)

_GEHEIM = re.compile(r"\.hermes/\.env\b|/\.ssh/id_|secrets?/[\w.-]*(token|key)|_API_KEY\b|BOT_TOKEN\b", _I)
_NETZ = re.compile(r"\b(curl|wget|nc|ncat|socat|scp|rsync|ftp|lftp|ssh)\b|https?://|requests\.(get|post|put)|urlopen|httpx\.", _I)
# Ziel-Muster in einer Befehlszeile zählen nur zusammen mit einem dieser Netzwerkzeuge.
_NETZ_WEIT = re.compile(
    _NETZ.pattern + r"|\b(pycurl|socket|urllib|http\.client|aiohttp|oss2|ossutil|boto3|fetch|Invoke-WebRequest|iwr|telnet)\b",
    _I)
_ZIEL_SPERREN = {"metadaten", "alibaba_speicher", "routify"}
_UPLOAD = re.compile(
    r"\bcurl\b[^\n]*?(\s-T\s|--upload-file|-X\s*['\"]?(PUT|POST)|\s--data(-binary|-raw|-urlencode)?[\s=]|\s-d\s|\s-F\s|--form)"
    r"|\bwget\b[^\n]*--(post-data|post-file|method=(PUT|POST))"
    r"|requests\.(put|post)\(|httpx\.(put|post)\(|\b(scp|rsync)\b[^\n]*\s[\w.-]+@?[\w.-]+:",
    _I)
_HOST = re.compile(r"(?:https?|ftps?|sftp)://(?:[^@/\s'\"]+@)?([A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])", _I)
_ERKUNDUNG = re.compile(r"cat\s+/etc/resolv\.conf|\b(which|command -v)\s+(curl|wget)\b[^\n]*\b(wget|curl|python3|jq)\b", _I)

# Ziele, an die gesendet werden darf, ohne dass eine Meldung kommt. Unterdomänen zählen mit.
# Eigene Ziele (Webspace, Mail-API, Tailnet …) gehören in ~/.hermes/qwen-fence.ziele, eins pro Zeile.
STANDARD_ZIELE = {
    "api.telegram.org", "t.me", "github.com", "githubusercontent.com", "huggingface.co",
    "openrouter.ai", "api.anthropic.com", "api.openai.com", "googleapis.com", "x.ai",
    "wikipedia.org", "wikimedia.org", "openstreetmap.org", "duckduckgo.com", "youtube.com", "youtu.be",
}
ZIELE_DATEI = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / "qwen-fence.ziele"
_ziele_stand: tuple[float, set[str]] = (-1.0, set())


def bekannte_ziele() -> set[str]:
    """Standard plus eigene Datei; die Datei wird nur neu gelesen, wenn sie sich geändert hat."""
    global _ziele_stand
    try:
        mtime = ZIELE_DATEI.stat().st_mtime
    except OSError:
        return STANDARD_ZIELE
    if mtime != _ziele_stand[0]:
        eigene = set()
        for zeile in ZIELE_DATEI.read_text(encoding="utf-8").splitlines():
            zeile = zeile.split("#", 1)[0].strip().lower()
            if zeile:
                eigene.add(zeile)
        _ziele_stand = (mtime, eigene)
    return STANDARD_ZIELE | _ziele_stand[1]


CODE_ENDUNGEN = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php", ".ps1", ".lua"}
_PFAD_SCHLUESSEL = ("path", "file_path", "target", "filename")
_INTERPRETER = re.compile(r"^(python[\d.]*|bash|sh|zsh|dash|node|ruby|perl|php|source|\.)$")
_VORSATZ = {"sudo", "timeout", "nohup", "exec", "env", "nice", "time", "stdbuf", "xargs"}
_HEREDOC = re.compile(r"([^\n]*)<<-?\s*(['\"]?)(\w+)\2[^\n]*\n(.*?)\n[ \t]*\3[ \t]*(?=\n|$)", re.S)
_ZIEL_DATEI = re.compile(r">{1,2}\s*['\"]?([^\s'\";&|]+)")
_MAX_SKRIPT = 200_000


def _ist_code(pfad: str, inhalt: str = "") -> bool:
    return Path(pfad or "").suffix.lower() in CODE_ENDUNGEN or inhalt.lstrip().startswith("#!")


def _prosa_heredocs_entfernen(befehl: str) -> str:
    """Heredoc-Körper, die per cat/tee in eine Prosa-Datei gehen, sind Daten. An einen Interpreter
    (python3 <<EOF, bash <<EOF) oder in eine Code-Datei bleiben sie stehen."""
    def ersetzen(m: re.Match) -> str:
        kopf, koerper = m.group(1), m.group(4)
        ziel = _ZIEL_DATEI.search(kopf)
        wort = (kopf.split() or [""])[0]
        if ziel and not _ist_code(ziel.group(1)) and not _INTERPRETER.match(os.path.basename(wort)):
            return kopf + "<<" + m.group(3) + "\n" + m.group(3)
        return m.group(0)
    return _HEREDOC.sub(ersetzen, befehl)


def _datei_lesen(pfad: Path) -> str:
    try:
        if not pfad.is_file() or pfad.stat().st_size > _MAX_SKRIPT:
            return ""
        roh = pfad.read_bytes()
    except OSError:
        return ""
    if b"\0" in roh[:1024]:
        return ""  # Binärdatei
    return roh.decode("utf-8", errors="replace")


def _pfad(wort: str, cwd: Path) -> Path:
    wort = os.path.expandvars(os.path.expanduser(wort))
    p = Path(wort)
    return p if p.is_absolute() else cwd / p


def _gestartete_skripte(befehl: str, cwd: Path) -> str:
    """Inhalt aller Skripte, die der Befehl startet. Ein Skript auf der Platte ist noch keine
    Handlung, sein Start schon. Der Pfad wird über vorangehende `cd` aufgelöst."""
    inhalt = []
    for teil in re.split(r"&&|\|\||[;|\n]", befehl):
        try:
            woerter = shlex.split(teil, comments=True)
        except ValueError:
            woerter = teil.split()
        while woerter and (re.match(r"^\w+=", woerter[0]) or woerter[0] in _VORSATZ
                           or (woerter[0].lstrip("-").isdigit())):
            woerter = woerter[1:]
        if not woerter:
            continue
        kopf, rest = woerter[0], woerter[1:]
        if kopf == "cd":
            cwd = _pfad(rest[0], cwd) if rest else Path.home()
            continue
        if _INTERPRETER.match(os.path.basename(kopf)):
            for i, w in enumerate(rest):
                if w == "-m" and i + 1 < len(rest):
                    modul = rest[i + 1].replace(".", "/")
                    for kandidat in (cwd / (modul + ".py"), cwd / modul / "__main__.py"):
                        inhalt.append(_datei_lesen(kandidat))
                    break
                if w in ("-c", "-e"):
                    break  # Code steht schon in der Befehlszeile
                if not w.startswith("-"):
                    inhalt.append(_datei_lesen(_pfad(w, cwd)))
                    break
        elif "/" in kopf:
            inhalt.append(_datei_lesen(_pfad(kopf, cwd)))
    return "\n".join(t for t in inhalt if t)


def _teile(tool: str, args: dict) -> tuple[str, str, str]:
    """(befehl, code, skripte)
    befehl  = Befehlszeile ohne Prosa-Heredocs
    code    = Code im Aufruf selbst (execute_code, geschriebene Code-Datei), streng geprüft
    skripte = Inhalt gestarteter Skripte, streng geprüft, aber nur für Sperren (sonst meldet
              jedes eigene Skript, das einen Token liest und Seiten abruft, bei jedem Start)"""
    if tool in AUSFUEHREN:
        befehl = " ".join(str(v) for k, v in args.items() if k in ("command", "cmd", "input") and v)
        code = " ".join(str(v) for k, v in args.items() if k in ("code", "script") and v)
        befehl = _prosa_heredocs_entfernen(befehl)
        cwd = Path(os.path.expanduser(str(args.get("workdir") or args.get("cwd") or os.getcwd())))
        return befehl, code, _gestartete_skripte(befehl, cwd)
    if tool in SCHREIBEN:
        pfad = next((str(args[k]) for k in _PFAD_SCHLUESSEL if args.get(k)), "")
        inhalt = " ".join(str(args.get(k) or "") for k in SCHREIBEN[tool])
        return "", (inhalt if _ist_code(pfad, inhalt) else ""), ""  # Prosa ist frei
    if tool in WEB:
        return " ".join(str(v) for v in args.values() if isinstance(v, (str, list))), "", ""
    return "", "", ""


def _text(tool: str, args: dict) -> str:
    """Der Aufruf selbst, wie der Zaun ihn sieht (für Protokollauszug und Auswertung)."""
    befehl, code, _ = _teile(tool, args)
    return "\n".join(t for t in (befehl, code) if t)


def _hosts(text: str) -> set[str]:
    return {h.lower().strip("[]").rstrip(".") for h in _HOST.findall(text)}


def _ip(h: str):
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        return None


def _lokal(h: str) -> bool:
    if h in ("localhost",):
        return True
    ip = _ip(h)
    # 100.64/10 = Tailnet (CGNAT), privat = LAN/WSL
    return bool(ip and (ip.is_loopback or ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")))


def _bekannt(h: str) -> bool:
    return _lokal(h) or any(h == b or h.endswith("." + b) for b in bekannte_ziele())


# --- Selbstschutz ----------------------------------------------------------------------------
# Der Agent darf den Zaun nicht per Werkzeug abschalten oder umschreiben: keine Schalter setzen,
# keine Plugin- oder Einstellungsdateien ändern, kein `plugins disable`. Lesen bleibt erlaubt
# (Protokoll, Regeln). Schalten geht nur aus der eigenen Shell des Betreibers. Diese Regel gilt
# auch im Modus „nur melden“.
PLUGIN_NAME = "qwen-fence"
_HERMES_HOME = ZIELE_DATEI.parent
_PLUGIN_DIR = Path(__file__).resolve().parent
_AENDERND = re.compile(
    r"\b(rm|rmdir|mv|cp|ln|touch|tee|truncate|chmod|chown|chattr|install|rsync|unlink|shred|dd|patch)\b"
    r"|\bsed\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*i|\bperl\s+-[a-zA-Z]*i"
    r"|\bopen\([^)]*['\"][wax+]|write_text|write_bytes|os\.(remove|unlink|rename|replace|symlink|chmod)|shutil\."
    r"|\.(unlink|rename|replace|touch|symlink_to|rmdir)\(",
    _I)
_ABSCHALTEN = re.compile(
    rf"plugins\s+(disable|remove|rm|uninstall|update)\b[^\n;&|]*{PLUGIN_NAME}|HERMES_SAFE_MODE|HERMES_PLUGINS_DISABLE", _I)
_SELBSTSCHUTZ_GRUND = "Selbstschutz: Der Zaun wird nur vom Betreiber geschaltet, nicht per Werkzeug"


_schutz_stand: tuple[float, re.Pattern | None] = (0.0, None)


def _geschuetzt() -> re.Pattern:
    """Pfade und Namen, die der Agent nicht ändern darf (das Protokoll gehört nicht dazu).
    Wird höchstens alle 30 s neu aufgebaut: Symlink-Ziele auflösen kostet unter WSL spürbar Zeit."""
    global _schutz_stand
    jetzt = time.monotonic()
    if _schutz_stand[1] is not None and jetzt - _schutz_stand[0] < 30:
        return _schutz_stand[1]
    teile = [rf"{PLUGIN_NAME}\.(aus|nur-melden|ziele|melden)\b", rf"plugins/{PLUGIN_NAME}\b", re.escape(str(_PLUGIN_DIR))]
    if PLUGIN_NAME in _PLUGIN_DIR.parent.name:
        teile.append(re.escape(str(_PLUGIN_DIR.parent)))  # z. B. /srv/ai/tools/qwen-fence
    for name in ("ziele", "melden"):
        try:
            ziel = (_HERMES_HOME / f"{PLUGIN_NAME}.{name}").resolve(strict=True)
            teile.append(re.escape(str(ziel)))
        except OSError:
            pass
    muster = re.compile("|".join(teile), _I)
    _schutz_stand = (jetzt, muster)
    return muster


def _selbstschutz(tool: str, args: dict, befehl: str, streng: str) -> bool:
    schutz = _geschuetzt()
    if tool in AUSFUEHREN:
        for teil in re.split(r"&&|\|\||[;\n]", befehl):
            if _ABSCHALTEN.search(teil):
                return True
            if any(schutz.search(ziel) for ziel in _ZIEL_DATEI.findall(teil)):
                return True  # Umleitung in eine geschützte Datei
            zielt = schutz.search(teil) or ("config.yaml" in teil and PLUGIN_NAME in teil)
            if zielt and _AENDERND.search(teil):
                return True
        return bool(streng and schutz.search(streng) and _AENDERND.search(streng))
    if tool in SCHREIBEN:
        pfad = next((str(args[k]) for k in _PFAD_SCHLUESSEL if args.get(k)), "")
        if not pfad:
            return False
        echt = str(Path(os.path.expanduser(pfad)).resolve())
        if schutz.search(pfad) or schutz.search(echt):
            return True
        if Path(pfad).name == "config.yaml":
            alt = str(args.get("old_string") or "")
            neu = " ".join(str(args.get(k) or "") for k in SCHREIBEN[tool])
            if tool == "write_file":
                try:
                    alt = Path(echt).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    alt = ""
            if PLUGIN_NAME in alt and PLUGIN_NAME not in neu:
                return True  # das Plugin würde aus der Konfiguration verschwinden
    return False


def pruefen(tool: str, args) -> tuple[str, str, str] | None:
    """Liefert (stufe, regel, grund) oder None. stufe = 'sperren' | 'melden'."""
    if not isinstance(args, dict):
        return None
    befehl, code, skripte = _teile(tool, args)
    text = "\n".join(t for t in (befehl, code) if t)
    streng = "\n".join(t for t in (code, skripte) if t)
    if _selbstschutz(tool, args, befehl, streng):
        return ("sperren", "selbstschutz", _SELBSTSCHUTZ_GRUND)
    if not (text or streng) or len(text) + len(streng) > 1024 * 1024:
        return None

    befehl_netz = tool in WEB or bool(_NETZ_WEIT.search(befehl))
    for name, muster, grund in SPERREN:
        if tool in WEB and name in ("alibaba_speicher", "namespace_root"):
            continue  # Dokuseiten und Blogbilder lesen bleibt erlaubt
        if streng and muster.search(streng):
            return ("sperren", name, grund)
        if befehl and muster.search(befehl) and (befehl_netz or name not in _ZIEL_SPERREN):
            return ("sperren", name, grund)

    if tool not in AUSFUEHREN and tool not in SCHREIBEN:
        return None

    for teil in (text, skripte):
        if teil and (_UPLOAD.search(teil) or (_GEHEIM.search(teil) and _NETZ.search(teil))):
            if ABLAGEDIENSTE.search(teil):
                return ("sperren", "ablagedienst", "Senden an einen anonymen Ablagedienst")
            roh = sorted(h for h in _hosts(teil) if _ip(h) and not _lokal(h))
            if roh:
                return ("sperren", "rohe_ip", "Senden an rohe öffentliche IP: " + ", ".join(roh)[:120])

    hosts = _hosts(text)
    sendet = bool(_UPLOAD.search(text))
    geheim = bool(_GEHEIM.search(text) and _NETZ.search(text))

    if tool in AUSFUEHREN:
        neu = sorted(h for h in hosts if not _bekannt(h))
        if sendet and neu:
            return ("melden", "upload_neues_ziel", "Senden an neues Ziel: " + ", ".join(neu)[:200])
        if geheim and neu:
            return ("melden", "geheimnis_neues_ziel", "Geheimnis-Datei mit neuem Ziel: " + ", ".join(neu)[:200])
        if _ERKUNDUNG.search(text):
            return ("melden", "netz_erkundung", "Erkundungsmuster wie im Cohere-Bericht")
    return None
