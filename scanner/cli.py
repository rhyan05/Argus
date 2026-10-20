"""Ponto de entrada CLI — argparse."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from scanner.core import scan
from scanner.report import render


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="verificador",
        description="Scanner antivírus/malware local.",
    )
    parser.add_argument("--config", help="Caminho do config.toml (default: ./config.toml).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Varrer arquivo ou diretório.")
    p_scan.add_argument("path", help="Arquivo ou diretório a varrer.")
    p_scan.add_argument(
        "--format",
        choices=["console", "json", "csv", "html"],
        default="console",
        help="Formato da saída (default: console).",
    )
    p_scan.add_argument("--rules", help="Arquivo .yar com regras YARA extras.")
    p_scan.add_argument("--rules-dir", help="Diretório com regras YARA (*.yar).")
    p_scan.add_argument(
        "--no-clamd",
        action="store_true",
        help="Não consultar o daemon clamd (se ausente/fora, já é ignorado).",
    )
    p_scan.add_argument(
        "--no-vt",
        action="store_true",
        help="Não consultar o VirusTotal (por padrão usa VT_API_KEY do ambiente).",
    )
    p_scan.add_argument(
        "--vt-only-suspicious",
        action="store_true",
        help="Consultar o VirusTotal só em arquivos já marcados como suspeitos/malware "
        "(evita o rate limit de ~15 s por arquivo limpo).",
    )
    p_scan.add_argument(
        "--max-file-size",
        metavar="TAM",
        help="Pular arquivos acima de TAM (ex.: 1g, 500m, 0 = ilimitado). Default: config.toml.",
    )
    p_scan.add_argument(
        "--quarantine",
        metavar="DIR",
        nargs="?",
        const="__config__",
        help="Mover arquivos maliciosos para DIR cifrados (default: config/quarantine.dir).",
    )

    sub.add_parser("status", help="Checagem de saúde das engines (clamd, yara, vt).")
    sub.add_parser("guia", help="Guia rápido: engines, uso e como configurar o VirusTotal.")
    p_upd = sub.add_parser("update-rules", help="Baixar regras YARA de uma URL.")
    p_upd.add_argument("url", help="URL do arquivo .yar.")
    p_upd.add_argument("-o", "--out", default="rules", help="Diretório de destino (default: rules/).")
    p_web = sub.add_parser("web", help="Servir o frontend local (upload + scan).")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=8080)
    p_web.add_argument("--open", action="store_true", help="Abrir janela nativa via pywebview (se instalado).")
    return parser.parse_args(argv)


def _cmd_scan(args, cfg) -> int:
    extra_rules = ""
    if args.rules:
        extra_rules = Path(args.rules).read_text(encoding="utf-8")
    rules_dir = args.rules_dir or cfg.get("rules_dir")

    root = Path(args.path)
    if not root.exists():
        print(f"ERRO: caminho não existe: {root}", file=sys.stderr)
        return 1

    vt = None
    if not args.no_vt and cfg["vt"].get("enabled", True):
        from scanner.vt import build_client

        vt = build_client(cfg)  # None se VT_API_KEY ausente — engine desligada silenciosamente

    if args.quarantine:
        qdir = args.quarantine if args.quarantine != "__config__" else cfg["quarantine"]["dir"]
        quarantine_dir = Path(qdir)
    else:
        quarantine_dir = None

    clamd_cfg = cfg["clamd"]

    from scanner.core import parse_size

    max_file_size = cfg.get("max_file_size")
    if args.max_file_size is not None:
        try:
            max_file_size = parse_size(args.max_file_size) or None  # 0 = ilimitado
        except ValueError:
            print(f"ERRO: --max-file-size inválido: {args.max_file_size}", file=sys.stderr)
            return 1

    # ponytail: rich.Progress em thread da console principal; scan sequencial —
    # paralelizar (ProcessPoolExecutor) quando varredura de dir grande medir lento.
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Varrendo...", total=None)
        results = scan(
            root,
            progress=lambda i, n, path: (
                progress.update(task, total=n, completed=i, description=f"Varrendo: {path}")
            ),
            use_clamd=not args.no_clamd,
            extra_rules=extra_rules,
            clamd_host=clamd_cfg["host"],
            clamd_port=clamd_cfg["port"],
            vt=vt,
            quarantine_dir=quarantine_dir,
            rules_dir=rules_dir,
            exclude=cfg.get("exclude"),
            max_file_size=max_file_size,
            vt_only_suspicious=args.vt_only_suspicious,
        )

    out = render(results, args.format)
    if out:
        print(out)
    return 0


def _engine_lines(cfg) -> list[str]:
    import os

    from scanner.core import HAS_YARA, YARA_CLI, analyze_clamd
    from scanner.engines import HAS_OLETOOLS, HAS_PEFILE, HAS_PY7ZR

    if HAS_YARA:
        yara_line = "[green]módulo Python[/green]"
    elif YARA_CLI:
        yara_line = f"[green]CLI[/green] ({YARA_CLI})"
    else:
        yara_line = "[yellow]ausente[/yellow]"

    lines = []
    lines.append(f"yara      : {yara_line}")
    lines.append(f"pefile    : {HAS_PEFILE}")
    lines.append(f"oletools  : {HAS_OLETOOLS}")
    lines.append(f"py7zr     : {HAS_PY7ZR}")
    lines.append(f"virustotal: {'[green]chave presente[/green]' if os.environ.get('VT_API_KEY') else '[yellow]sem VT_API_KEY[/yellow]'}")

    # PRD pede "checagem de integridade do serviço clamd" — Presence ping não basta:
    # connect + PING/PONG prova que o daemon responde de verdade.
    host, port = cfg["clamd"]["host"], cfg["clamd"]["port"]
    try:
        analyze_clamd(b"", host, port)
        lines.append(f"clamd     : [green]respondendo em {host}:{port}[/green]")
    except Exception as e:
        lines.append(f"clamd     : [yellow]sem resposta em {host}:{port} ({type(e).__name__})[/yellow]")
    return lines


def _cmd_status(cfg) -> int:
    from rich.console import Console
    from rich.panel import Panel

    Console().print(Panel("\n".join(_engine_lines(cfg)), title="Status das engines"))
    return 0


def _cmd_guia(cfg) -> int:
    import os

    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()
    console.print(Panel("\n".join(_engine_lines(cfg)), title="Engines disponíveis"))

    vt_status = (
        "chave presente — engine ativa"
        if os.environ.get("VT_API_KEY")
        else "sem chave — engine desligada (opcional)"
    )
    console.print(
        Markdown(
            f"""# Guia rápido

Scanner local de malware, focado no terminal. Varre arquivos e pastas e mostra o
veredito por arquivo, além de quais engines rodaram.

## Comandos básicos

| Comando | O que faz |
|---|---|
| `verificador scan <arquivo-ou-pasta>` | Varre e mostra o relatório |
| `verificador status` | Saúde das engines |
| `verificador web` | Interface local (arrastar e soltar) |
| `verificador update-rules <url>` | Baixa regras YARA |

**Dica:** em modo de desenvolvimento (sem instalar), troque `verificador` por `python -m scanner`.

## VirusTotal (opcional)

Status: **{vt_status}**

A engine consulta a reputação pelo **hash SHA-256** — o arquivo não é enviado.

1. Crie uma conta e pegue a chave grátis em https://www.virustotal.com/gui/my-apikey
2. Configure:
   - Windows (PowerShell): `setx VT_API_KEY "sua-chave"` (reabra o terminal)
   - Linux/macOS/WSL: `export VT_API_KEY="sua-chave"`
3. Confira com `verificador status` (deve mostrar "chave presente").

O plano grátis limita a ~4 requisições/min. Em pastas grandes use
`--vt-only-suspicious`; para desligar, use `--no-vt`.

## Próximo passo

    verificador scan .

Sem a chave do VirusTotal tudo funciona; apenas essa engine é pulada.
"""
        )
    )
    return 0


def _cmd_update_rules(args) -> int:
    import urllib.request

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    target = out / Path(args.url).name
    print(f"Baixando {args.url} -> {target} ...")
    try:
        with urllib.request.urlopen(args.url, timeout=30) as resp:
            target.write_bytes(resp.read())
    except Exception as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 1
    print(f"OK: {target} ({target.stat().st_size} bytes)")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.config and not Path(args.config).exists():
        print(f"ERRO: config não existe: {args.config}", file=sys.stderr)
        return 1
    from scanner.config import load

    cfg = load(args.config)

    if args.command == "scan":
        return _cmd_scan(args, cfg)
    if args.command == "status":
        return _cmd_status(cfg)
    if args.command == "guia":
        return _cmd_guia(cfg)
    if args.command == "update-rules":
        return _cmd_update_rules(args)
    if args.command == "web":
        from scanner.web import serve

        if args.open:
            try:
                import threading

                import webview  # type: ignore

                t = threading.Thread(target=serve, args=(args.host, args.port), daemon=True)
                t.start()
                webview.create_window("Verificador de Arquivo", f"http://{args.host}:{args.port}")
                webview.start()
                return 0
            except ImportError:
                print("pywebview não instalado — servindo no navegador.", file=sys.stderr)
        serve(args.host, args.port)
        return 0
    print(f"Comando não implementado: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
