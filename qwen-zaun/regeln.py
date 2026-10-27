"""Regeln des Qwen-Zauns (Anlass: Cohere-Bericht vom 26.10.2026 zu Qwen3.8-Flash-Next).

Grundsatz: Der Agent arbeitet wie bisher. Gesperrt wird nur, was er in seiner Arbeit nie braucht
und was genau den beobachteten Fehlgriffen entspricht. Auffälliges, das im Alltag auch vorkommt,
läuft durch und wird gemeldet.

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
_UPLOAD = re.compile(
    r"\bcurl\b[^\n]*?(\s-T\s|--upload-file|-X\s*['\"]?(PUT|POST)|\s--data(-binary|-raw|-urlencode)?[\s=]|\s-d\s|\s-F\s|--form)"
    r"|\bwget\b[^\n]*--(post-data|post-file|method=(PUT|POST))"
    r"|requests\.(put|post)\(|httpx\.(put|post)\(|\b(scp|rsync)\b[^\n]*\s[\w.-]+@?[\w.-]+:",
    _I)
_HOST = re.compile(r"(?:https?|ftps?|sftp)://(?:[^@/\s'\"]+@)?([A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])", _I)
_ERKUNDUNG = re.compile(r"cat\s+/etc/resolv\.conf|\b(which|command -v)\s+(curl|wget)\b[^\n]*\b(wget|curl|python3|jq)\b", _I)

# Ziele, an die gesendet werden darf, ohne dass eine Meldung kommt. Unterdomänen zählen mit.
# Eigene Ziele (Webspace, Mail-API, Tailnet …) gehören in ~/.hermes/qwen-zaun.ziele, eins pro Zeile.
STANDARD_ZIELE = {
    "api.telegram.org", "t.me", "github.com", "githubusercontent.com", "huggingface.co",
    "openrouter.ai", "api.anthropic.com", "api.openai.com", "googleapis.com", "x.ai",
    "wikipedia.org", "wikimedia.org", "openstreetmap.org", "duckduckgo.com", "youtube.com", "youtu.be",
}
ZIELE_DATEI = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes")) / "qwen-zaun.ziele"
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


def _text(tool: str, args: dict) -> str:
    if tool in AUSFUEHREN:
        return " ".join(str(v) for k, v in args.items() if k in ("command", "code", "script", "cmd", "input") and v)
    if tool in SCHREIBEN:
        return " ".join(str(args.get(k) or "") for k in SCHREIBEN[tool])
    if tool in WEB:
        return " ".join(str(v) for v in args.values() if isinstance(v, (str, list)))
    return ""


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


def pruefen(tool: str, args) -> tuple[str, str, str] | None:
    """Liefert (stufe, regel, grund) oder None. stufe = 'sperren' | 'melden'."""
    if not isinstance(args, dict):
        return None
    text = _text(tool, args)
    if not text or len(text) > 512 * 1024:
        return None

    for name, muster, grund in SPERREN:
        if tool in WEB and name in ("alibaba_speicher", "namespace_root"):
            continue  # Dokuseiten und Blogbilder lesen bleibt erlaubt
        if muster.search(text):
            return ("sperren", name, grund)

    if tool not in AUSFUEHREN and tool not in SCHREIBEN:
        return None

    hosts = _hosts(text)
    sendet = bool(_UPLOAD.search(text))
    geheim = bool(_GEHEIM.search(text) and _NETZ.search(text))

    if sendet or geheim:
        if ABLAGEDIENSTE.search(text):
            return ("sperren", "ablagedienst", "Senden an einen anonymen Ablagedienst")
        roh = sorted(h for h in hosts if _ip(h) and not _lokal(h))
        if roh:
            return ("sperren", "rohe_ip", "Senden an rohe öffentliche IP: " + ", ".join(roh)[:120])

    if tool in AUSFUEHREN:
        neu = sorted(h for h in hosts if not _bekannt(h))
        if sendet and neu:
            return ("melden", "upload_neues_ziel", "Senden an neues Ziel: " + ", ".join(neu)[:200])
        if geheim and neu:
            return ("melden", "geheimnis_neues_ziel", "Geheimnis-Datei mit neuem Ziel: " + ", ".join(neu)[:200])
        if _ERKUNDUNG.search(text):
            return ("melden", "netz_erkundung", "Erkundungsmuster wie im Cohere-Bericht")
    return None
