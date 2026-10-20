"""Verificador de Arquivo — scanner antivírus/malware.

Uso: python -m scanner scan <caminho> [--format json|csv] [--rules arquivo.yar]
"""

from scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
