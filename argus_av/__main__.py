"""Argus — scanner antivírus/malware.

Uso: python -m argus_av scan <caminho> [--format json|csv] [--rules arquivo.yar]
"""

from argus_av.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
