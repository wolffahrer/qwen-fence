"""Qwen-Fence: prüft jeden Werkzeugaufruf, bevor er läuft (Anlass: Cohere-Bericht 26.10.2026).

Sperrt nur, was der Agent in seiner Arbeit nie braucht (siehe regeln.py), meldet Auffälliges und
lässt alles andere unverändert durch. Kosten: ein paar Regex pro Aufruf, unter 1 ms.

Schalter (ohne Neustart, wird bei jedem Aufruf gelesen):
  ~/.hermes/qwen-fence.aus           Zaun ganz aus
  ~/.hermes/qwen-fence.nur-melden    nichts sperren, nur melden
  ~/.hermes/qwen-fence.ziele         eigene bekannte Ziele, eins pro Zeile
  ~/.hermes/qwen-fence.melden        Meldebefehl (erste Zeile), bekommt den Text als Argument,
                                    z. B. ein Skript, das per `hermes send` an Telegram schickt
Protokoll: ~/.hermes/logs/qwen-fence.jsonl
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Optional

from . import regeln

logger = logging.getLogger(__name__)

_BASIS = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
_LOG = _BASIS / "logs" / "qwen-fence.jsonl"
_STAND = _BASIS / "logs" / "qwen-fence.stand.json"
_MELDEN: str | None = None  # None = aus qwen-fence.melden lesen; Tests setzen es direkt
_MELDUNGEN_PRO_TAG = 6
_sperre = threading.Lock()


def _schalter(name: str) -> bool:
    return (_BASIS / name).exists()


def _protokoll(eintrag: dict) -> None:
    try:
        _LOG.parent.mkdir(parents=True, exist_ok=True)
        with _sperre, _LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(eintrag, ensure_ascii=False) + "\n")
    except OSError as err:
        logger.warning("qwen-fence: Protokoll nicht schreibbar: %s", err)


def _darf_melden(schluessel: str, sofort: bool) -> bool:
    """Sperren werden immer gemeldet; Auffälliges höchstens einmal je Regel+Ziel und Tag, max. 6 am Tag."""
    if sofort:
        return True
    tag = time.strftime("%Y-%m-%d")
    with _sperre:
        try:
            stand = json.loads(_STAND.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stand = {}
        if stand.get("tag") != tag:
            stand = {"tag": tag, "anzahl": 0, "gesehen": []}
        if schluessel in stand["gesehen"] or stand["anzahl"] >= _MELDUNGEN_PRO_TAG:
            return False
        stand["gesehen"].append(schluessel)
        stand["anzahl"] += 1
        try:
            _STAND.write_text(json.dumps(stand), encoding="utf-8")
        except OSError:
            pass
        return True


def _meldebefehl() -> str | None:
    if _MELDEN is not None:
        return _MELDEN
    try:
        zeile = (_BASIS / "qwen-fence.melden").read_text(encoding="utf-8").strip().splitlines()[0].strip()
    except (OSError, IndexError):
        return None
    return zeile or None


def _melden(text: str) -> None:
    befehl = _meldebefehl()
    if not befehl:
        return  # kein Meldeweg eingerichtet: nur Protokoll
    # Eigener Prozess, nicht abwarten: der Werkzeugaufruf darf nie auf die Meldung warten.
    try:
        subprocess.Popen([befehl, text], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as err:
        logger.warning("qwen-fence: Meldung nicht abgesetzt: %s", err)


def _auszug(tool: str, args: Any) -> str:
    try:
        text = regeln._text(tool, args) if isinstance(args, dict) else str(args)
    except Exception:
        text = ""
    return " ".join(text.split())[:300]


def _on_pre_tool_call(tool_name: str = "", args: Any = None, task_id: str = "", **kw: Any) -> Optional[dict]:
    try:
        if _schalter("qwen-fence.aus"):
            return None
        treffer = regeln.pruefen(tool_name, args)
        if not treffer:
            return None
        stufe, regel, grund = treffer
        nur_melden = _schalter("qwen-fence.nur-melden")
        gesperrt = stufe == "sperren" and not nur_melden
        profil = os.environ.get("HERMES_PROFILE") or Path(os.environ.get("HERMES_HOME", str(_BASIS))).name
        auszug = _auszug(tool_name, args)
        _protokoll({"zeit": time.strftime("%Y-%m-%dT%H:%M:%S"), "profil": profil, "werkzeug": tool_name,
                    "stufe": stufe, "regel": regel, "gesperrt": gesperrt, "grund": grund,
                    "sitzung": kw.get("session_id") or task_id, "auszug": auszug})
        if _darf_melden(f"{regel}|{grund}", sofort=gesperrt):
            kopf = "🛑 Qwen-Fence hat gesperrt" if gesperrt else "⚠️ Qwen-Fence meldet"
            _melden(f"{kopf} ({profil}, {tool_name})\nRegel: {regel} – {grund}\nBefehl: {auszug[:240]}")
        if not gesperrt:
            return None
        return {"action": "block",
                "message": (f"Qwen-Fence: Aufruf nicht ausgeführt ({grund}). Diese Aktion ist für die Aufgabe nicht "
                            "nötig und auf diesem System gesperrt. Der Betreiber ist informiert. Arbeite ohne diesen "
                            "Schritt weiter.")}
    except Exception as err:  # Der Zaun darf den Agenten nie lahmlegen.
        logger.warning("qwen-fence: Prüfung fehlgeschlagen, Aufruf durchgelassen: %s", err)
        return None


def register(ctx) -> None:
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
