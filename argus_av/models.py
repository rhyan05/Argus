"""Tipos compartilhados do scanner."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "suspicious", "malware")
ACTIONABLE = ("suspicious", "malware")  # severidades que marcam o arquivo como sujo

RAN = "ran"
SKIP_UNAVAILABLE = "indisponivel"  # dependência/serviço ausente
SKIP_NA = "nao-aplicavel"        # tipo de arquivo não bate com a engine

# Só `indisponivel` conta como "deveria ter rodado"; `nao-aplicavel` não.
COUNTED_SKIPS = (SKIP_UNAVAILABLE,)


@dataclass
class Finding:
    engine: str
    signature: str
    severity: str = "malware"


@dataclass
class EngineResult:
    """Retorno de uma engine: achados + se rodou ou por que pulou."""

    findings: list[Finding] = field(default_factory=list)
    status: str = RAN
    reason: str = ""


@dataclass
class EngineRun:
    """Registro do que aconteceu com uma engine num arquivo (para o relatório x/y)."""

    engine: str
    status: str = RAN
    reason: str = ""

    @property
    def ran(self) -> bool:
        return self.status == RAN

    @property
    def counted(self) -> bool:
        return self.ran or self.status in COUNTED_SKIPS


@dataclass
class Result:
    path: str
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    findings: list[Finding] = field(default_factory=list)
    engine_runs: list[EngineRun] = field(default_factory=list)
    skip_reason: str = ""  # preenchido quando o arquivo inteiro foi pulado

    @property
    def clean(self) -> bool:
        """True = nenhum achado acionável. `info` é observação, não sujeira (ex.: assinatura
        digital presente, reputação limpa) — contá-la como DETECTED gera alarme falso."""
        return not any(f.severity in ACTIONABLE for f in self.findings)

    @property
    def skipped(self) -> bool:
        return bool(self.skip_reason)

    @property
    def engines_ran(self) -> int:
        return sum(1 for e in self.engine_runs if e.ran)

    @property
    def engines_total(self) -> int:
        return sum(1 for e in self.engine_runs if e.counted)
