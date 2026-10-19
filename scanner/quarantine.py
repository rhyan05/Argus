"""Quarentena — move e cifra (AES-256-CTR) arquivos confirmados maliciosos.

Layout: <quar>/key.key (chave) + <quar>/manifest.jsonl (uma linha JSON por entrada) + *.enc

A cifra é feita em blocos — não carrega o arquivo inteiro em memória. O manifest é
append-only (O(1) por arquivo), não reescrito a cada entrada.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK = 1024 * 1024
KEY_SIZE = 32  # AES-256
IV_SIZE = 16


def load_key(quar_dir: Path) -> bytes:
    """Chave simétrica da quarentena, criada na primeira vez."""
    key_path = quar_dir / "key.key"
    if not key_path.exists():
        key_path.write_bytes(os.urandom(KEY_SIZE))
        try:
            key_path.chmod(0o600)
        except OSError:
            pass  # chmod não aplicável em alguns FS — ponytail: garantir ACL no deploy
    return key_path.read_bytes()


def _append_manifest(quar_dir: Path, entry: dict) -> None:
    with open(quar_dir / "manifest.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def quarantine_file(orig: Path, quar_dir: Path) -> str:
    """Cifra `orig` em blocos para <quar>/<nome>.<id>.enc, registra no manifest e apaga o
    original. Devolve o caminho do arquivo cifrado."""
    quar_dir.mkdir(parents=True, exist_ok=True)
    key = load_key(quar_dir)
    iv = os.urandom(IV_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    target = quar_dir / f"{orig.name}.{uuid.uuid4().hex[:8]}.enc"

    size = 0
    with open(orig, "rb") as fin, open(target, "wb") as fout:
        fout.write(iv)
        for chunk in iter(lambda: fin.read(CHUNK), b""):
            size += len(chunk)
            fout.write(encryptor.update(chunk))
        fout.write(encryptor.finalize())

    _append_manifest(quar_dir, {"original": str(orig), "quarantined": str(target), "size": size})
    orig.unlink(missing_ok=True)
    return str(target)


def decrypt_to(quar_path: Path, out_path: Path, key: bytes) -> int:
    """Decifra um .enc de volta para `out_path` (restauração). Devolve o tamanho em claro."""
    with open(quar_path, "rb") as fin, open(out_path, "wb") as fout:
        iv = fin.read(IV_SIZE)
        decryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        n = 0
        for chunk in iter(lambda: fin.read(CHUNK), b""):
            n += len(chunk)
            fout.write(decryptor.update(chunk))
        fout.write(decryptor.finalize())
    return n
