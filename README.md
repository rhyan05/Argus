# Verificador de Arquivo

Scanner antivírus/malware local, multiplataforma (PowerShell, cmd, WSL, macOS),
**CLI-first** com frontend local complementar.

## Instalação

Tutorial passo a passo. O scanner roda só com Python — as engines externas (ClamAV,
YARA, VirusTotal) são **opcionais** e, sem elas, são ignoradas silenciosamente no status.

### Pré-requisitos

- **Python 3.11 ou superior** (usa `tomllib` da stdlib). Confira:

  ```powershell
  python --version    # deve imprimir 3.11+ ; se "python" não existir, tente "py -3"
  ```

### Passo 1 — Obter o código

```powershell
git clone <url-do-repo> "Verificador de Arquivo"
cd "Verificador de Arquivo"
```

Sem Git? Baixe o ZIP e extraia — os passos seguintes são iguais.

### Passo 2 — Ambiente virtual (recomendado)

Isola as dependências do Python do sistema.

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> Se aparecer erro de execução de scripts, rode uma vez:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

**Linux / macOS / WSL:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Passo 3 — Instalar dependências

```powershell
pip install -e ".[dev]"          # instala o scanner + ruff/pytest (modo editável)
```

Só o essencial (sem ferramentas de dev): `pip install -r requirements.txt`.
O `-e .` também cria o atalho `scanner` no PATH do venv — a partir daí
`scanner scan ...` e `python -m scanner scan ...` são equivalentes.

### Passo 4 — Verificar a instalação

```powershell
python -m scanner status
```

Saída esperada: uma linha por engine. As que funcionam mostram o que foi encontrado
(`yara: CLI`, `pefile: True`); as indisponíveis mostram o motivo
(`virustotal: sem VT_API_KEY`, `clamd: sem resposta em 127.0.0.1:3310`). Se `pefile`,
`oletools` e `py7zr` estiverem `True`, a instalação base está funcional — o matcher
`builtin` cobre o EICAR sem depender de nenhuma engine externa.

### Passo 5 — Engines opcionais

#### ClamAV (`clamd`)

A engine mais forte. O scanner conversa com o daemon por socket TCP (INSTREAM).

**Windows:** baixe o instalador oficial em <https://www.clamav.net/downloads>, instale,
edite `clamd.conf` e descomente/defina:

```ini
TCPSocket 3310
TCPAddr 127.0.0.1
```

Depois rode `clamd.exe` (ou instale como serviço). Teste com `python -m scanner status`.

**Debian/Ubuntu:**

```bash
sudo apt update && sudo apt install -y clamav clamav-daemon
sudo systemctl enable --now clamav-daemon
```

**macOS (Homebrew):**

```bash
brew install clamav
# edite $(brew --prefix)/etc/clamav/clamd.conf e ative TCPSocket 3310
```

#### YARA

O módulo `yara-python` não tem wheel para Python 3.14 (exige compilador C). O scanner
prefere o módulo quando existe e, caso contrário, usa o binário `yara`/`yara64` do PATH
(ou o caminho em `YARA_PATH`).

```powershell
winget install VirusTotal.YARA        # Windows
```
```bash
sudo apt install -y yara              # Debian/Ubuntu
brew install yara                     # macOS
```

#### VirusTotal

Consulta reputação por **hash SHA-256** (não envia o arquivo). Pegue uma chave grátis em
<https://www.virustotal.com/gui/my-apikey> e exporte:

```powershell
setx VT_API_KEY "sua-chave"           # Windows (abra um novo terminal depois)
```
```bash
export VT_API_KEY="sua-chave"         # Linux/macOS/WSL
```

Sem a chave, a engine é ignorada. O plano grátis limita a ~15 s entre requisições —
para diretórios grandes, use `--vt-only-suspicious` (consulta só arquivos já suspeitos).

### Solução de problemas

| Sintoma | Causa provável | Solução |
|---|---|---|
| `'python' não é reconhecido` | Python fora do PATH | Reinstale marcando "Add to PATH", ou use `py -3` |
| `Activate.ps1 ... desabilitado` | política de execução do PowerShell | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `ModuleNotFoundError: scanner` | rodou fora da pasta/venv | Ative o venv e rode da raiz do projeto |
| engine `clamav` = `-` (ConnectionRefusedError) | `clamd` não está rodando | Inicie o `clamd` e confira `TCPSocket 3310` |
| engine `yara` = `-` | binário fora do PATH | Instale o YARA ou defina `YARA_PATH` |
| `status` mostra `virustotal: sem VT_API_KEY` | chave ausente | Exporte a chave e reabra o terminal |
| arquivos pulados como `SKIPPED` | acima de `max_file_size` (100 MB) | Use `--max-file-size 1g` ou `0` (ilimitado) |

## Uso rápido

```powershell
python -m scanner scan C:\pasta               # console com barra de progresso
python -m scanner scan C:\pasta --format json
python -m scanner scan C:\pasta --format csv
python -m scanner scan C:\pasta --format html
python -m scanner scan C:\pasta --quarantine  # move malware p/ .quar cifrado (AES-256)
python -m scanner scan C:\pasta --rules minhas.yar
python -m scanner scan C:\pasta --rules-dir rules   # carrega todos os *.yar
python -m scanner scan C:\pasta --max-file-size 1g   # inclui arquivos grandes (0 = ilimitado)
python -m scanner scan C:\pasta --vt-only-suspicious # VirusTotal só em suspeitos (poupa rate limit)
python -m scanner status                      # saúde das engines (inclui ping real no clamd)
python -m scanner web                         # frontend: http://127.0.0.1:8080
python -m scanner web --open                  # janela nativa (requer pywebview)
python -m scanner update-rules <url>          # baixa regras YARA p/ rules/
```

## Configuração (`config.toml`)

Procurado em `./config.toml`, depois `~/.config/scanner.toml`. Valores ausentes usam defaults.

```toml
exclude = ["cache.tmp", "thumbs.db", "node_modules"]  # casa com QUALQUER componente do caminho
max_file_size = 104857600       # bytes; acima disso é pulado (aparece como SKIPPED)

[clamd]
host = "127.0.0.1"
port = 3310

[vt]
enabled = true
rate_interval = 15.0            # segundos entre requisições (free tier)
cache = ".quar/vt-cache.db"

[quarantine]
dir = ".quar"

[rules_dir]
# caminho default de regras YARA — usável com --rules-dir
```

## Motores

| Engine | O que detecta |
|---|---|
| clamd | assinaturas ClamAV via streaming |
| yara | regras binárias/textuais (+ regras próprias/dir) |
| builtin | EICAR por substring (funciona sem yara) |
| pe | PE: seções W+X, ASLR/DEP ausentes, packers (entropia + UPX/Themida), assinatura digital |
| doc | macros OLE/VBA (oletools) |
| archive | zip bombs (razão/volume/contagem), 7z |
| virustotal | reputação por hash SHA-256 (com cache SQLite e rate limit) |

Cada finding carrega uma severidade: `info` (observação), `suspicious`, `malware`.
Só `suspicious`/`malware` marcam o arquivo como **não limpo** — `info` é observação
(assinatura digital presente, reputação limpa) e aparece como `OK`, não como `DETECTED`.

### Status por engine

O relatório mostra quantas engines rodaram em cada arquivo (`2/3`) e, quando alguma que
deveria rodar não rodou, um bloco com o motivo:

```
+ builtin  + yara  - clamav (ConnectionRefusedError)  . pe  . doc  . archive
```

`+` rodou · `-` pulou (arquivo grande demais para a engine, ou engine indisponível) ·
`.` não se aplica ao tipo do arquivo. O denominador conta só `+` e `-` — um `.txt` fica
`2/2`, um `.exe` grande pode ficar `4/5` com o `-` apontando qual engine e por quê.

## Arquivos grandes

O scan **não carrega o arquivo inteiro na memória**: o hashing é feito em blocos e cada
engine lê do próprio arquivo (`mmap` no YARA/PE, índice central no ZIP). Um arquivo de
1 GB é varrido com pico de memória de ~18 MB. O `max_file_size` (default 100 MB) é só um
teto de tempo/segurança — passe `--max-file-size 0` para não ter limite. Arquivos pulados
aparecem como `SKIPPED` no relatório, com o motivo.

## Testes e lint

```powershell
python -m unittest tests.test_scan   # suíte (unittest)
ruff check .                         # lint
```

Os testes não fazem requisições de rede. Fixtures EICAR são injetadas **em memória** —
nunca escritas em disco, pois o antivírus do host (Windows Defender) as apaga no meio do
write e quebraria a suíte.

## Limitações conhecidas

- ELF/Mach-O não analisados (depende do `lief`, sem wheel p/ Python 3.14).
- Scan é sequencial — paralelização planejada se dirs grandes ficarem lentos.
- O `clamd` tem limite próprio (`MaxFileSize`/`MaxScanSize`, ~25 MB por padrão no
  `clamd.conf`): acima disso ele recusa e o arquivo aparece com `- clamav` no status.
- Sem o módulo `yara-python`, o CLI do YARA é acionado por arquivo (recompila as regras
  e sobe um processo a cada item) — mais lento que o módulo numa varredura de diretório grande.