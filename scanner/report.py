"""Formatadores de resultado: console (rich), JSON, CSV e HTML."""

from __future__ import annotations

import csv
import io
import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.models import ACTIONABLE, COUNTED_SKIPS, SKIP_NA, Result

console = Console()


def _status(r: Result) -> str:
    if r.skipped:
        return "SKIPPED"
    if not any(f.severity in ACTIONABLE for f in r.findings):
        return "OK" if r.findings else "CLEAN"
    return "MALWARE" if any(f.severity == "malware" for f in r.findings) else "DETECTED"


def _engines_label(r: Result) -> str:
    if r.skipped or not r.engine_runs:
        return "-"
    return f"{r.engines_ran}/{r.engines_total}"


def _entries(results: list[Result]):
    """Classificação comum aos formatadores: (result, status, engines, findings)."""
    for r in results:
        status = _status(r)
        if r.skipped:
            yield r, status, "-", []
        elif not r.findings:
            yield r, status, _engines_label(r), []
        else:
            yield r, status, _engines_label(r), r.findings


def _run_marks(r: Result) -> str:
    """Marcas por engine: + rodou, - pulou (tamanho/indisponível), . não se aplica.

    ASCII puro (+ - .) porque o console do Windows em cp1252 quebra caracteres como '·'.
    """
    marks = []
    for e in r.engine_runs:
        if e.ran:
            marks.append(f"+ {e.engine}")
        elif e.status == SKIP_NA:
            marks.append(f". {e.engine}")
        else:
            detail = f" ({e.reason})" if e.reason else ""
            marks.append(f"- {e.engine}{detail}")
    return "  ".join(marks)


def to_dict(r: Result) -> dict:
    return {
        "path": r.path,
        "sha256": r.sha256,
        "sha1": r.sha1,
        "md5": r.md5,
        "clean": r.clean,
        "skipped": r.skipped,
        "skip_reason": r.skip_reason,
        "engines": {
            "ran": r.engines_ran,
            "total": r.engines_total,
            "runs": [
                {"engine": e.engine, "status": e.status, "reason": e.reason}
                for e in r.engine_runs
            ],
        },
        "findings": [
            {"engine": f.engine, "signature": f.signature, "severity": f.severity}
            for f in r.findings
        ],
    }


def to_json(results: list[Result]) -> str:
    return json.dumps([to_dict(r) for r in results], indent=2, ensure_ascii=False)


def to_csv(results: list[Result]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        ["path", "sha256", "sha1", "md5", "status", "severity", "engine", "signature", "engines", "skip_reason"]
    )
    for r, status, engines, findings in _entries(results):
        if r.skipped:
            writer.writerow([r.path, "", "", "", status, "", "", "", engines, r.skip_reason])
            continue
        if not findings:
            writer.writerow([r.path, r.sha256, r.sha1, r.md5, status, "", "", "", engines, ""])
            continue
        for f in findings:
            writer.writerow(
                [r.path, r.sha256, r.sha1, r.md5, status, f.severity, f.engine, f.signature, engines, ""]
            )
    return buf.getvalue()


_SEV_STYLE = {"info": "blue", "suspicious": "yellow", "malware": "red"}
_STATUS_STYLE = {
    "CLEAN": "green",
    "OK": "blue",
    "DETECTED": "yellow",
    "MALWARE": "red",
    "SKIPPED": "yellow",
}


def to_console(results: list[Result]) -> None:
    table = Table(title="Resultado da varredura")
    table.add_column("Arquivo", overflow="fold")
    table.add_column("Status")
    table.add_column("Engines")
    table.add_column("Detalhe", overflow="fold")
    for r, st, engines, findings in _entries(results):
        status = f"[{_STATUS_STYLE[st]}]{st}[/{_STATUS_STYLE[st]}]"
        if r.skipped:
            table.add_row(r.path, status, engines, f"[yellow]{r.skip_reason}[/yellow]")
        elif not findings:
            table.add_row(r.path, status, engines, "-")
        else:
            detail = "\n".join(
                f"[{_SEV_STYLE.get(f.severity, 'white')}]{f.engine}: {f.signature} ({f.severity})[/]"
                for f in findings
            )
            table.add_row(r.path, status, engines, detail)
    console.print(table)

    # bloco de detalhe por engine — só quando alguma que devia rodar não rodou
    partial = [r for r in results if any(e.status in COUNTED_SKIPS for e in r.engine_runs)]
    if partial:
        detail = Table(title="Engines por arquivo  (+ rodou  - pulou  . nao se aplica)")
        detail.add_column("Arquivo", overflow="fold")
        detail.add_column("Engines")
        detail.add_column("Execucao", overflow="fold")
        for r in partial:
            detail.add_row(r.path, _engines_label(r), _run_marks(r))
        console.print(detail)

    total = len(results)
    skipped = sum(1 for r in results if r.skipped)
    sus = sum(1 for r in results if not r.skipped and any(f.severity in ACTIONABLE for f in r.findings))
    info = sum(
        1
        for r in results
        if not r.skipped and r.findings and not any(f.severity in ACTIONABLE for f in r.findings)
    )
    parts = []
    if sus:
        parts.append(f"[red]{sus} arquivo(s) suspeito(s)[/red]")
    if info:
        parts.append(f"[blue]{info} arquivo(s) com observações[/blue]")
    if skipped:
        parts.append(f"[yellow]{skipped} arquivo(s) pulado(s)[/yellow]")
    status = " - ".join(parts) if parts else "[green]NENHUM problema encontrado[/green]"
    console.print(Panel(f"{total} arquivo(s) varridos - {status}", title="Resumo"))


def to_html(results: list[Result]) -> str:
    rows = []
    for r, st, engines, findings in _entries(results):
        cls = st.lower()
        if r.skipped:
            rows.append(
                f"<tr><td>{_esc(r.path)}</td><td class='{cls}'>SKIPPED</td><td>{engines}</td>"
                f"<td>{_esc(r.skip_reason)}</td></tr>"
            )
        elif not findings:
            rows.append(
                f"<tr><td>{_esc(r.path)}</td><td class='clean'>CLEAN</td>"
                f"<td>{engines}</td><td>-</td></tr>"
            )
        else:
            detail = "<br>".join(
                f"{_esc(f.engine)}: {_esc(f.signature)} ({_esc(f.severity)})" for f in findings
            )
            rows.append(
                f"<tr><td>{_esc(r.path)}</td><td class='{cls}'>{st}</td>"
                f"<td>{engines}</td><td>{detail}</td></tr>"
            )
    table = "\n".join(rows)
    return f"""<!doctype html>
<html lang="pt"><head><meta charset="utf-8"><title>Resultado da varredura</title>
<style>
  body {{ font-family: sans-serif; margin: 2em; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
  .clean {{ color: green; font-weight: bold; }}
  .ok {{ color: blue; }}
  .info {{ color: blue; }}
  .suspicious, .detected {{ color: orange; }}
  .malware {{ color: red; font-weight: bold; }}
  .skipped {{ color: #b58900; font-weight: bold; }}
</style></head>
<body><h1>Resultado da varredura — {len(results)} arquivo(s)</h1>
<table><thead><tr><th>Arquivo</th><th>Status</th><th>Engines</th><th>Detalhe</th></tr></thead>
<tbody>
{table}
</tbody></table></body></html>
"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(results: list[Result], fmt: str) -> str:
    if fmt == "json":
        return to_json(results)
    if fmt == "csv":
        return to_csv(results)
    if fmt == "html":
        return to_html(results)
    to_console(results)
    return ""
