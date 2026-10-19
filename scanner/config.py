"""Configuração centralizada via config.toml (tomllib — stdlib, sem dependência).

Precedência: config.toml no cwd > ~/.config/scanner.toml > defaults.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

DEFAULTS: dict = {
    "exclude": [],  # nomes de arquivo/diretório a ignorar
    "max_file_size": 100 * 1024 * 1024,  # bytes; acima disso é pulado (registrado)
    "clamd": {"host": "127.0.0.1", "port": 3310},
    "vt": {"enabled": True, "rate_interval": 15.0, "cache": ".quar/vt-cache.db"},
    "quarantine": {"dir": ".quar"},
    "rules_dir": "rules",
}


def _merge(base: dict, user: dict) -> dict:
    out = {k: dict(v) if isinstance(v, dict) else v for k, v in base.items()}
    for k, v in user.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def load(path: str | Path | None = None) -> dict:
    if path is not None:
        candidates = [Path(path)]
    else:
        candidates = [Path("config.toml"), Path.home() / ".config/scanner.toml"]
    for cand in candidates:
        if cand.exists():
            # utf-8-sig: tolera o BOM que o PowerShell 5.1 grava via Out-File -Encoding utf8
            with open(cand, "r", encoding="utf-8-sig") as f:
                return _merge(DEFAULTS, tomllib.loads(f.read()))
    return {k: dict(v) if isinstance(v, dict) else v for k, v in DEFAULTS.items()}
