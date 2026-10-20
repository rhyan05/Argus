"""VirusTotal — consulta de reputação por hash SHA-256, com cache SQLite e rate limit."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path

from scanner.models import Finding

VT_API = "https://www.virustotal.com/api/v3/files/{sha256}"
RATE_INTERVAL = 15.0  # free tier ~4 req/min
NO_REPUTATION = "sem-reputacao"  # 404 do VT — veredito neutro, não é finding


class VTCache:
    """Cache local dos vereditos para não reconsultar hashes repetidos (SQLite stdlib)."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS vt (sha256 TEXT PRIMARY KEY, verdict TEXT, severity TEXT)"
        )
        # cache criado por versão anterior (sem a coluna severity) — migra in-place
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(vt)")}
        if "severity" not in cols:
            self._conn.execute("ALTER TABLE vt ADD COLUMN severity TEXT")
        self._conn.commit()

    def get(self, sha256: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT verdict, severity FROM vt WHERE sha256=?", (sha256,)
        ).fetchone()
        if not row:
            return None
        verdict, severity = row
        if verdict == NO_REPUTATION:
            return None  # 404 cacheado não é finding — o arquivo segue sem veredito
        return Finding("virustotal", verdict, severity or "info")

    def put(self, sha256: str, verdict: str, severity: str = "info") -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO vt (sha256, verdict, severity) VALUES (?,?,?)",
            (sha256, verdict, severity),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "VTCache":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class RateLimit:
    """Pausa entre requisições."""

    def __init__(self, interval: float = RATE_INTERVAL):
        self.interval = interval
        self._last = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        delta = now - self._last
        if delta < self.interval:
            time.sleep(self.interval - delta)
        self._last = time.monotonic()


def build_client(cfg: dict | None = None) -> tuple[VTCache, RateLimit, str] | None:
    """Retorna (cache, limiter, api_key) se VT_API_KEY existir no ambiente; senão None (engine desligada)."""
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None
    vt_cfg = (cfg or {}).get("vt", {})
    cache_path = Path(os.environ.get("VT_CACHE", vt_cfg.get("cache", ".quar/vt-cache.db")))
    limiter = RateLimit(float(vt_cfg.get("rate_interval", RATE_INTERVAL)))
    return VTCache(cache_path), limiter, key


def check_vt(sha256: str, cache: VTCache, limiter: RateLimit, api_key: str) -> Finding | None:
    """GET /files/{hash}. Retorna Finding ou None (limpo/404/erro)."""
    cached = cache.get(sha256)
    if cached:
        return cached

    req = urllib.request.Request(
        VT_API.format(sha256=sha256), headers={"x-apikey": api_key}
    )
    try:
        limiter.wait()
        with urllib.request.urlopen(req, timeout=15) as resp:
            stats = json.load(resp)["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            cache.put(sha256, NO_REPUTATION, "info")
            return None
        return None  # 429/limite
    except (urllib.error.URLError, OSError, ValueError):
        return None

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious:
        verdict = f"malicious:{malicious}"
        sev = "malware"
    elif suspicious:
        verdict = f"suspicious:{suspicious}"
        sev = "suspicious"
    else:
        verdict = "reputacao-limpa"
        sev = "info"
    cache.put(sha256, verdict, sev)
    return Finding("virustotal", verdict, sev)
