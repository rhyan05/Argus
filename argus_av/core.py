"""Núcleo: hashing, travessia de arquivos e orquestração da varredura.

As engines vivem em `argus_av.engines`; aqui fica só o fluxo que as combina e o
relatório por arquivo.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from argus_av.engines import (
    analyze_archive,
    analyze_builtin,
    analyze_clamd,
    analyze_docs,
    analyze_pe,
    analyze_yara,
)
from argus_av.models import (
    ACTIONABLE,
    RAN,
    SKIP_UNAVAILABLE,
    EngineResult,
    EngineRun,
    Finding,
    Result,
)
from argus_av.vt import check_vt

CHUNK = 1024 * 1024  # 1 MiB — tamanho de bloco para hashing/streaming


def hashes(data: bytes) -> tuple[str, str, str]:
    """SHA-256, SHA-1 e MD5 de um buffer em memória."""
    return (
        hashlib.sha256(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.md5(data).hexdigest(),
    )


def hash_file(path) -> tuple[str, str, str]:
    """SHA-256, SHA-1 e MD5 lendo o arquivo em blocos — memória constante."""
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest()


def scan_file(
    path: Path,
    use_clamd: bool = True,
    extra_rules: str = "",
    clamd_host: str = "127.0.0.1",
    clamd_port: int = 3310,
    vt: tuple | None = None,
    quarantine_dir: Path | None = None,
    rules_dir: str | None = None,
    vt_only_suspicious: bool = False,
) -> Result:
    sha256, sha1, md5 = hash_file(path)
    findings: list[Finding] = []
    runs: list[EngineRun] = []

    def record(engine: str, res: EngineResult) -> None:
        findings.extend(res.findings)
        runs.append(EngineRun(engine, res.status, res.reason))

    record("builtin", analyze_builtin(path=path))
    record("yara", analyze_yara(extra_rules=extra_rules, rules_dir=rules_dir, path=path))
    if use_clamd:
        try:
            record("clamav", analyze_clamd(clamd_host, clamd_port, path=path))
        except (ConnectionError, OSError, RuntimeError) as e:
            # clamd ausente/fora — isolamento de erros: não derruba o pipeline
            runs.append(EngineRun("clamav", SKIP_UNAVAILABLE, type(e).__name__))

    record("pe", analyze_pe(path))
    record("doc", analyze_docs(path))
    record("archive", analyze_archive(path))

    # `vt_only_suspicious` evita gastar o rate limit (~15 s/req) em arquivos já limpos.
    if vt is not None and (
        not vt_only_suspicious or any(f.severity in ACTIONABLE for f in findings)
    ):
        cache, limiter, api_key = vt
        vt_finding, vt_reason = check_vt(sha256, cache, limiter, api_key)
        if vt_finding:
            findings.append(vt_finding)
        runs.append(
            EngineRun("virustotal", RAN if not vt_reason else SKIP_UNAVAILABLE, vt_reason)
        )

    if quarantine_dir is not None and any(f.severity == "malware" for f in findings):
        from argus_av.quarantine import quarantine_file

        quarantine_file(path, quarantine_dir)

    return Result(str(path), sha256, sha1, md5, findings, runs)


def iter_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = [p for p in root.rglob("*") if p.is_file()]
    files.sort(key=str)
    return files


def _excluded(path: Path, root: Path, exclude: set[str]) -> bool:
    """Casar em qualquer componente do caminho relativo, não só no basename.

    `exclude = ["node_modules"]` tem que matar o diretório inteiro, não só um arquivo
    chamado node_modules (README promete "nomes de arquivo/diretório").
    """
    if not exclude:
        return False
    if os.name == "nt":
        exclude = {name.casefold() for name in exclude}

        def key(name: str) -> str:
            return name.casefold()
    else:

        def key(name: str) -> str:
            return name

    if root.is_file():
        return key(path.name) in exclude
    return any(key(part) in exclude for part in path.relative_to(root).parts)


def human_size(n: int) -> str:
    """Tamanho legível (ex.: 104857600 -> '100 MB')."""
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}"
        value /= 1024
    return f"{value:.0f} TB"


def parse_size(text: str) -> int:
    """Converte '100m', '1g', '512k' ou bytes crus em inteiro. '0' = ilimitado."""
    t = text.strip().lower()
    if not t:
        raise ValueError("tamanho vazio")
    mult = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    if t[-1] in mult:
        return int(float(t[:-1]) * mult[t[-1]])
    return int(t)


def scan(
    root: Path,
    progress=None,
    use_clamd: bool = True,
    extra_rules: str = "",
    clamd_host: str = "127.0.0.1",
    clamd_port: int = 3310,
    vt: tuple | None = None,
    quarantine_dir: Path | None = None,
    rules_dir: str | None = None,
    exclude: list[str] | None = None,
    max_file_size: int | None = None,
    vt_only_suspicious: bool = False,
) -> list[Result]:
    exclude = set(exclude or [])
    files = [p for p in iter_files(root) if not _excluded(p, root, exclude)]
    results: list[Result] = []
    try:
        for i, path in enumerate(files, 1):
            if progress:
                progress(i, len(files), str(path))
            try:
                size = path.stat().st_size
            except OSError as e:
                results.append(Result(str(path), skip_reason=f"ilegivel ({type(e).__name__})"))
                continue
            if max_file_size and size > max_file_size:
                # visível no relatório, não silencioso
                results.append(
                    Result(
                        str(path),
                        skip_reason=f"maior que o limite ({human_size(max_file_size)})",
                    )
                )
                continue
            try:
                results.append(
                    scan_file(
                        path,
                        use_clamd,
                        extra_rules,
                        clamd_host,
                        clamd_port,
                        vt,
                        quarantine_dir,
                        rules_dir,
                        vt_only_suspicious,
                    )
                )
            except OSError as e:
                # arquivo travado/removido/sem permissão no meio da varredura — registra e
                # segue, em vez de abortar a varredura do diretório inteiro
                results.append(
                    Result(str(path), skip_reason=f"ilegivel ({type(e).__name__})")
                )
    finally:
        # o cache é compartilhado por todos os scan_file — fecha uma vez, no fim
        if vt is not None:
            vt[0].close()
    return results
