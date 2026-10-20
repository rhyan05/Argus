"""Análise estática: PE/assinatura/packers, documentos OLE e compactados.

Engines seguem o contrato `analyze_*(path, data=None) -> EngineResult`. Com `data=None`
a engine lê o arquivo pelo `path` (mmap/streaming, sem carregar tudo); com `data` usa os
bytes em memória — necessário para os testes com EICAR, que não pode ir a disco.

Dependências são opcionais (isolamento de erros): engine ausente não derruba o scan —
retorna `status=indisponivel`.
"""

from __future__ import annotations

import io
import math
import zipfile
from collections import Counter

from scanner.models import (
    RAN,
    SKIP_NA,
    SKIP_UNAVAILABLE,
    EngineResult,
    Finding,
)

try:
    import pefile  # type: ignore
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from oletools.olevba import VBA_Parser  # type: ignore
    HAS_OLETOOLS = True
except ImportError:
    HAS_OLETOOLS = False

try:
    import py7zr  # type: ignore
    HAS_PY7ZR = True
except ImportError:
    HAS_PY7ZR = False

# Limites heurísticos
PACKER_ENTROPY = 6.5       # entropia de seção acima disso ~ conteúdo empacotado/cifrado
ENTROPY_MAX_SECTION = 64 * 1024 * 1024  # acima disso não calcula entropia (evita copiar seção)
SUSPECT_SECTIONS = {"UPX0", "UPX1", "UPX2", ".themida", ".vmp0", ".vmp1", ".nsp0", ".nsp1"}
ZIP_MAX_RATIO = 100        # razão compressão > isso => zip bomb
ZIP_MAX_TOTAL = 500 * 1024 * 1024  # tamanho descomprimido total estimado
ZIP_MAX_FILES = 10_000
DOC_EXTS = {"doc", "docm", "xls", "xlsm", "ppt", "pptm", "docx", "xlsx", "pptx"}


def _head(path, data: bytes | None, n: int) -> bytes:
    """Primeiros `n` bytes: de `data` em memória ou lidos do arquivo."""
    if data is not None:
        return data[:n]
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def shannon_entropy(data: bytes) -> float:
    """Entropia de Shannon (0–8 bits/byte). Alto = conteúdo cifrado/compactado/packed."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _extract_cert_info(pe) -> str | None:
    """Nome do emissor do certificado Authenticode, se presente."""
    try:
        sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        if sec.VirtualAddress and sec.Size > 8:
            offset = sec.VirtualAddress
            if offset < len(pe.__data__):
                cert = pe.__data__[offset : offset + sec.Size]
                if len(cert) > 8:
                    size = int.from_bytes(cert[0:4], "little")
                    data = cert[8 : min(8 + size, len(cert))]
                    try:
                        from cryptography.hazmat.primitives.serialization.pkcs12 import (
                            load_pkcs12,
                        )
                    except ImportError:
                        return "present"
                    idx = data.find(b"0\x82")  # início heurístico do DER
                    if idx < 0:
                        return "present"
                    try:
                        p12 = load_pkcs12(data[idx:], None)
                        cert_obj = p12.certificates[0] if p12.certificates else None
                    except Exception:
                        return "present"
                    if cert_obj:
                        for attr in cert_obj.subject:
                            if attr.oid._name == "commonName":
                                return str(attr.value)
                        return "present"
    except Exception:
        pass
    return None


def analyze_pe(path, data: bytes | None = None) -> EngineResult:
    """PE: seções W+X, ASLR/DEP, packers (entropia + nomes), assinatura digital."""
    if not HAS_PEFILE:
        return EngineResult(status=SKIP_UNAVAILABLE, reason="pefile ausente")
    if _head(path, data, 2) != b"MZ":
        return EngineResult(status=SKIP_NA, reason="nao-PE")
    findings: list[Finding] = []
    try:
        # com path, pefile faz mmap — não carrega o arquivo inteiro em memória
        pe = pefile.PE(data=data, fast_load=True) if data is not None else pefile.PE(name=str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            ]
        )

        issuer = _extract_cert_info(pe)
        if issuer:
            findings.append(Finding("pe", f"assinatura-digital ({issuer})", "info"))
        else:
            findings.append(Finding("pe", "sem-assinatura-digital", "suspicious"))

        dllchars = pe.OPTIONAL_HEADER.DllCharacteristics
        if not (dllchars & 0x0040):
            findings.append(Finding("pe", "ASLR-desabilitado", "suspicious"))
        if not (dllchars & 0x0100):
            findings.append(Finding("pe", "DEP-desabilitado", "suspicious"))

        for sec in pe.sections:
            name = sec.Name.rstrip(b"\0").decode(errors="replace").strip()
            flags = sec.Characteristics
            writable = bool(flags & 0x80000000)
            executable = bool(flags & 0x20000000)
            if writable and executable:
                findings.append(Finding("pe", f"secao-W+X:{name}", "suspicious"))
            # get_data() copia a seção; evita entropia em seção gigante
            if (sec.SizeOfRawData or 0) <= ENTROPY_MAX_SECTION:
                ent = shannon_entropy(sec.get_data())
                if ent > PACKER_ENTROPY:
                    findings.append(
                        Finding("pe", f"packer-entropia-alta:{name}:{ent:.2f}", "suspicious")
                    )
            if name.upper() in SUSPECT_SECTIONS:
                findings.append(Finding("pe", f"packer-detectado:{name}", "malware"))
    except Exception:
        return EngineResult(findings, status=RAN)  # PE malformado — mantém o que já achou
    return EngineResult(findings)


def analyze_docs(path, data: bytes | None = None) -> EngineResult:
    """Macros OLE (Word/Excel/PPT) via oletools."""
    if not HAS_OLETOOLS:
        return EngineResult(status=SKIP_UNAVAILABLE, reason="oletools ausente")
    ext = str(path).lower().rsplit(".", 1)[-1] if "." in str(path) else ""
    if ext not in DOC_EXTS:
        return EngineResult(status=SKIP_NA, reason="nao-documento")
    findings: list[Finding] = []
    try:
        # oletools aceita data=None e lê o próprio arquivo pelo path
        parser = VBA_Parser(str(path), data=data)
        try:
            if parser.detect_vba_macros():
                for (_, _, _, vba_name, _) in parser.extract_macros():
                    lower = vba_name.lower()
                    if any(k in lower for k in ("auto_", "workbook_open", "document_open")):
                        findings.append(Finding("doc", f"macro-autoexec:{vba_name}", "malware"))
                    else:
                        findings.append(Finding("doc", f"macro-vba:{vba_name}", "suspicious"))
        finally:
            parser.close()
    except Exception:
        pass
    return EngineResult(findings)


def analyze_archive(path, data: bytes | None = None) -> EngineResult:
    """Heurística de Zip Bomb e volume: razão de compressão, total estimado, nº de entradas."""
    head = _head(path, data, 6)
    findings: list[Finding] = []
    if head[:4] == b"PK\x03\x04":
        try:
            # ZipFile lê só o índice central — não carrega o conteúdo
            source = io.BytesIO(data) if data is not None else str(path)
            with zipfile.ZipFile(source) as zf:
                total, packed, count = 0, 0, 0
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    count += 1
                    total += info.file_size
                    packed += info.compress_size
            # razão global: somar a razão por entrada infla um zip normal de N arquivos
            ratio = total / packed if packed else 0.0
            if count > ZIP_MAX_FILES:
                findings.append(Finding("archive", f"zip-muitos-arquivos:{count}", "suspicious"))
            if total > ZIP_MAX_TOTAL:
                findings.append(Finding("archive", f"zip-volume-grande:{total}", "suspicious"))
            if ratio > ZIP_MAX_RATIO:
                findings.append(Finding("archive", f"zip-ratio-alto:{ratio:.0f}x", "suspicious"))
        except Exception:
            pass
        return EngineResult(findings)
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        if not HAS_PY7ZR:
            return EngineResult(status=SKIP_UNAVAILABLE, reason="py7zr ausente")
        try:
            source = io.BytesIO(data) if data is not None else str(path)
            with py7zr.SevenZipFile(source, mode="r") as zf:
                info = zf.list()
                total = sum(getattr(f, "uncompressed", 0) or 0 for f in info)
                if total > ZIP_MAX_TOTAL:
                    findings.append(Finding("archive", f"7z-volume-grande:{total}", "suspicious"))
        except Exception:
            pass
        return EngineResult(findings)
    return EngineResult(status=SKIP_NA, reason="nao-compactado")
