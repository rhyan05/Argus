"""Núcleo: hashing, engines e loop de varredura.

Engines são funções `analyze_*(path, data=None) -> EngineResult` — nenhuma classe abstrata
necessária com poucas engines.
Com `data=None` a engine lê o arquivo pelo `path` (mmap/streaming); `data` existe para
conteúdo em memória que não pode ir a disco (fixtures EICAR dos testes).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path

from scanner.engines import analyze_archive, analyze_docs, analyze_pe
from scanner.models import (
    ACTIONABLE,
    RAN,
    SKIP_NA,
    SKIP_UNAVAILABLE,
    EngineResult,
    EngineRun,
    Finding,
    Result,
)
from scanner.vt import check_vt

try:  # módulo yara-python, quando há wheel/compilador
    import yara  # type: ignore
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


def _find_yara_cli() -> str | None:
    """Localiza o binário YARA: `YARA_PATH`, PATH, ou pacote instalado via winget.

    winget instala em %LOCALAPPDATA%\\Microsoft\\WinGet\\Packages e adiciona ao PATH
    só em shells novos — o fallback evita exigir restart.
    """
    override = os.environ.get("YARA_PATH")
    if override and Path(override).is_file():
        return override
    for name in ("yara", "yara64"):
        found = shutil.which(name)
        if found:
            return found
    root = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages"
    if root.is_dir():
        for candidate in sorted(root.glob("*/yara64.exe")) + sorted(root.glob("*/yara.exe")):
            return str(candidate)
    return None


YARA_CLI = _find_yara_cli()  # binário CLI, quando o módulo Python não compila

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_RULE = """
rule eicar_test {
    meta:
        description = "EICAR test signature (builtin)"
        author = "scanner"
    strings:
        $eicar = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
"""

CHUNK = 1024 * 1024  # 1 MiB — tamanho de bloco para hashing/streaming
YARA_TIMEOUT = 300  # s — teto para uma varredura do binário yara não pendurar o scan


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


def _eicar_in_file(path) -> bool:
    """Varre o arquivo em blocos procurando o EICAR, com sobreposição para o caso de a
    assinatura cair na fronteira entre dois blocos."""
    overlap = len(EICAR) - 1
    tail = b""
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            if EICAR in tail + chunk:
                return True
            tail = (tail + chunk)[-overlap:]
    return False


def analyze_clamd(
    data: bytes = b"", host: str = "127.0.0.1", port: int = 3310, path=None
) -> EngineResult:
    """Varre via INSTREAM do clamd. Lança ConnectionError se o daemon não estiver no ar.

    Com `path`, envia o arquivo em blocos direto do disco — sem carregar em memória.
    """
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(b"zINSTREAM\0")
        if path is not None:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(64 * 1024), b""):
                    sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
        else:
            for i in range(0, len(data), 64 * 1024):
                chunk = data[i : i + 64 * 1024]
                sock.sendall(len(chunk).to_bytes(4, "big") + chunk)
        sock.sendall(b"\0\0\0\0")
        reply = b""
        while not reply.endswith(b"\0"):
            reply += sock.recv(4096)
    text = reply[:-1].decode(errors="replace").strip()
    if text.endswith("FOUND"):
        sig = text.replace("stream: ", "").rsplit(" FOUND", 1)[0]
        return EngineResult([Finding("clamav", sig)])
    if text.endswith("ERROR"):
        raise RuntimeError(f"clamd error: {text}")
    return EngineResult()


@lru_cache(maxsize=8)
def _rules_source(extra_rules: str, rules_dir: str | None) -> str:
    """Fontes YARA = EICAR embutida + extras do usuário (string ou diretório).

    O lru_cache evita reler o rules_dir a cada arquivo; maxsize=8 porque fontes de
    regra podem ter MBs e há pouquíssimas combinações.
    """
    sources = EICAR_RULE + extra_rules
    if rules_dir:
        for f in sorted(Path(rules_dir).glob("*.yar")):
            sources += "\n" + f.read_text(encoding="utf-8", errors="replace")
    return sources


@lru_cache(maxsize=8)
def _compiled_rules(extra_rules: str, rules_dir: str | None):
    """Compila as fontes uma vez por combinação (extra_rules, rules_dir) — módulo Python."""
    return yara.compile(source=_rules_source(extra_rules, rules_dir))


_CLI_RULES_DIR = tempfile.TemporaryDirectory(prefix="scanner-yara-")


@lru_cache(maxsize=8)
def _cli_rules_file(extra_rules: str, rules_dir: str | None) -> str:
    """Grava as fontes num .yar temporário reutilizado pelo CLI na varredura inteira."""
    target = Path(_CLI_RULES_DIR.name) / f"rules-{abs(hash((extra_rules, rules_dir)))}.yar"
    target.write_text(_rules_source(extra_rules, rules_dir), encoding="utf-8")
    return str(target)


def _analyze_yara_cli(
    data: bytes, extra_rules: str, rules_dir: str | None, path: Path | None
) -> list[Finding]:
    """Match via binário `yara`. Só precisa de arquivo — usa `path` (mmap) ou grava `data`."""
    rules_file = _cli_rules_file(extra_rules, rules_dir)
    tmp: str | None = None
    try:
        if path is not None:
            target = str(path)
        else:
            fd, tmp = tempfile.mkstemp(prefix="scanner-scan-")
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            target = tmp
        proc = subprocess.run(
            [YARA_CLI, rules_file, target],
            capture_output=True,
            text=True,
            timeout=YARA_TIMEOUT,
        )
        if proc.returncode != 0:
            return []  # regra inválida ou arquivo ilegível — engine isolada, não derruba o scan
        # saída: uma linha "<nome_da_regra> <caminho>" por match; nome não tem espaços
        return [
            Finding("yara", line.split(maxsplit=1)[0])
            for line in proc.stdout.splitlines()
            if line.strip()
        ]
    except (OSError, subprocess.TimeoutExpired):
        return []  # binário ausente ou varredura travada — não pendura o scan
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def analyze_yara(
    data: bytes = b"",
    extra_rules: str = "",
    rules_dir: str | None = None,
    path: Path | None = None,
) -> EngineResult:
    """Match das regras EICAR embutida + extras do usuário (string ou diretório).

    Prefere o módulo Python (se compilado); senão usa o binário CLI. Quando `path` é
    passado, ambas as rotas leem o arquivo por mmap — sem carregar tudo em memória.
    """
    if HAS_YARA:
        rules = _compiled_rules(extra_rules, rules_dir)
        matches = rules.match(filepath=str(path)) if path is not None else rules.match(data=data)
        return EngineResult([Finding("yara", m.rule) for m in matches])
    if YARA_CLI:
        return EngineResult(_analyze_yara_cli(data, extra_rules, rules_dir, path))
    return EngineResult(status=SKIP_UNAVAILABLE, reason="yara ausente")


def analyze_builtin(data: bytes | None = None, path=None) -> EngineResult:
    """Matcher assinatura por substring — cobre o EICAR sem depender do yara.

    Fica como rede de segurança caso nem o módulo nem o CLI do yara existam.
    """
    if data is not None:
        hit = EICAR in data
    elif path is not None:
        try:
            hit = _eicar_in_file(path)
        except OSError:
            return EngineResult(status=SKIP_UNAVAILABLE, reason="ilegivel")
    else:
        return EngineResult(status=SKIP_NA, reason="sem fonte")
    return EngineResult([Finding("builtin", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE")] if hit else [])


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
            record("clamav", analyze_clamd(host=clamd_host, port=clamd_port, path=path))
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
        vt_finding = check_vt(sha256, cache, limiter, api_key)
        if vt_finding:
            findings.append(vt_finding)
        runs.append(EngineRun("virustotal", RAN))

    if quarantine_dir is not None and any(f.severity == "malware" for f in findings):
        from scanner.quarantine import quarantine_file

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
    if root.is_file():
        return path.name in exclude
    return any(part in exclude for part in path.relative_to(root).parts)


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
    files = iter_files(root)
    results: list[Result] = []
    try:
        for i, path in enumerate(files, 1):
            if _excluded(path, root, exclude):
                continue
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
            if progress:
                progress(i, len(files), str(path))
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
