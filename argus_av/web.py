"""Servidor HTTP local: página de upload e endpoint de scan."""

from __future__ import annotations

import json
import re
import tempfile
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from argus_av.core import scan_file

PAGE = """<!doctype html>
<html lang="pt"><head><meta charset="utf-8"><title>Argus</title>
<style>
  body {{ font-family: sans-serif; margin: 2em; }}
  #drop {{ border: 2px dashed #888; padding: 3em; text-align: center; border-radius: 8px; }}
  #drop.hover {{ border-color: #2a6; background: #efe; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
  th, td {{ border: 1px solid #ccc; padding: 6px; text-align: left; }}
  .malware {{ color: red; font-weight: bold; }} .suspicious {{ color: orange; }}
  .info {{ color: blue; }} .clean {{ color: green; }}
</style></head>
<body>
<h1>Argus</h1>
<div id="drop"><strong>Arraste arquivos aqui</strong> ou <label><input type="file" id="files" multiple>selecione</label></div>
<div id="out"></div>
<script>
const drop = document.getElementById('drop'), filesEl = document.getElementById('files');
const out = document.getElementById('out');
function scanFiles(list) {{
  for (const f of list) {{
    const fd = new FormData();
    fd.append('file', f);
    const row = document.createElement('div'); row.textContent = `Scan ${f.name}...`; out.prepend(row);
    fetch('/scan', {{ method: 'POST', body: fd }})
      .then(r => r.json())
      .then(res => {{
          // textContent p/ o nome (evita XSS via filename) e status derivado da severidade
          const label = document.createElement('b');
          label.textContent = f.name;
          row.textContent = '';
          row.appendChild(label);
          row.appendChild(document.createTextNode(': '));
          const actionable = res.findings.filter(x => x.severity !== 'info');
          if (!res.findings.length) {{
            row.innerHTML += '<span class="clean">CLEAN</span>';
          }} else if (!actionable.length) {{
            row.innerHTML += '<span class="info">OK (apenas observações)</span>';
          }} else {{
            actionable.forEach(x => {{
              const s = document.createElement('span');
              s.className = x.severity;
              s.textContent = x.severity === 'malware' ? 'MALWARE' : 'DETECTED';
              s.textContent += ` — ${{x.engine}}: ${{x.signature}}`;
              row.appendChild(document.createTextNode(' '));
              row.appendChild(s);
            }});
          }}
          // quantas engines rodaram e quais ficaram de fora
          const eng = res.engines || {{ ran: 0, total: 0, runs: [] }};
          const badge = document.createElement('span');
          badge.className = (eng.ran < eng.total) ? 'info' : 'clean';
          badge.textContent = ` [engines ${{eng.ran}}/${{eng.total}}]`;
          row.appendChild(badge);
          const skipped = eng.runs.filter(e => e.status !== 'ran' && e.status !== 'nao-aplicavel');
          if (skipped.length) {{
            const miss = document.createElement('span');
            miss.className = 'suspicious';
            miss.textContent = ' não rodou: ' +
              skipped.map(e => `${{e.engine}} (${{e.reason || e.status}})`).join(', ');
            row.appendChild(miss);
          }}
        }})
      .catch(e => {{ row.textContent = f.name + ' erro: ' + e; }});
  }}
}}
['dragover','dragenter'].forEach(e => drop.addEventListener(e, ev => {{ ev.preventDefault(); drop.classList.add('hover'); }}));
['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {{ ev.preventDefault(); drop.classList.remove('hover'); }}));
drop.addEventListener('drop', ev => scanFiles(ev.dataTransfer.files));
filesEl.addEventListener('change', () => scanFiles(filesEl.files));
</script>
</body></html>
"""

BOUNDARY_RE = re.compile(r"boundary=(?:\"([^\"]+)\"|([^;]+))")
MAX_UPLOAD = 100 * 1024 * 1024  # teto do upload: o corpo é lido inteiro na memória antes de ir a disco


def _read_part(boundary: bytes, data: bytes, name: bytes) -> tuple[str, bytes] | None:
    """Extrai (filename, conteúdo) do campo multipart `name` (parse caseiro, upload único)."""
    marker = b"--" + boundary
    for part in data.split(marker):
        head, _, body = part.partition(b"\r\n\r\n")
        if b'name="' + name + b'"' in head:
            filename = ""
            m = re.search(rb'filename="([^"]*)"', head)
            if m:
                filename = m.group(1).decode("utf-8", "replace")
            return filename, body[:-2]  # tira o \r\n final
    return None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: str | bytes, ctype: str = "text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE)
        else:
            self._send(404, "not found")

    def do_POST(self):
        if self.path != "/scan":
            self._send(404, "not found")
            return
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or 0)
        except ValueError:
            self._send(400, json.dumps({"error": "Content-Length invalido"}), "application/json")
            return
        if length <= 0:
            self._send(400, json.dumps({"error": "Content-Length ausente"}), "application/json")
            return
        if length > MAX_UPLOAD:
            # sem teto, o corpo do POST vira OOM (é lido inteiro antes de gravar no temporário)
            self._send(413, json.dumps({"error": "upload acima do limite"}), "application/json")
            return
        data = self.rfile.read(length)
        m = BOUNDARY_RE.search(self.headers.get("Content-Type", ""))
        if not m:
            self._send(400, json.dumps({"error": "multipart missing"}), "application/json")
            return
        boundary = (m.group(1) or m.group(2)).encode()
        part = _read_part(boundary, data, b"file")
        if not part:
            self._send(400, json.dumps({"error": "file field missing"}), "application/json")
            return
        filename, payload = part
        safe_name = Path(filename).name or ""  # normaliza travessia de caminho

        with tempfile.TemporaryDirectory() as tmp:
            name = uuid.uuid4().hex
            # preserva a extensão: analyze_docs decide o engine pela extensão do path
            p = Path(tmp) / (name + Path(safe_name).suffix)
            p.write_bytes(payload)
            res = scan_file(p, use_clamd=False)
            from argus_av.report import to_dict

            out = to_dict(res)
            out["path"] = safe_name or name
        self._send(200, json.dumps(out), "application/json")

    def log_message(self, fmt, *args):
        pass  # silencioso — logs no terminal já são ruído suficiente


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Serve o frontend. `pywebview` (janela nativa) é só: webview.create_window('...', url)"""
    print(f"Serve em http://{host}:{port}")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
