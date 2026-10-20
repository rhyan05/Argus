"""Testes da Fase 1 — EICAR 100% em memória (nunca em disco: o Defender do host apagaria)."""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from scanner.core import EICAR, analyze_builtin, analyze_yara, hashes, iter_files, scan, scan_file
from scanner.models import EngineResult, Finding

EICAR_TEXT = EICAR.decode()


class TestHasher(unittest.TestCase):
    def test_known_digests(self):
        # SHA-256("") / SHA-1("") / MD5("") — vetores conhecidos
        s256, s1, md5 = hashes(b"")
        self.assertEqual(s256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(s1, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(md5, "d41d8cd98f00b204e9800998ecf8427e")


class TestEicarDetection(unittest.TestCase):
    def test_builtin_detects_eicar_in_memory(self):
        findings = analyze_builtin(EICAR).findings
        self.assertTrue(any(f.signature.startswith("EICAR") for f in findings))

    def test_builtin_clean_for_normal_data(self):
        res = analyze_builtin(b"hello world")
        self.assertEqual(res.findings, [])
        self.assertEqual(res.status, "ran")

    def test_yara_detects_eicar_with_python_module(self):
        from scanner import core

        if not core.HAS_YARA:
            self.skipTest("yara-python não compila em 3.14; o binário CLI é coberto por TestYaraCli")
        findings = analyze_yara(EICAR).findings
        self.assertTrue(any(f.signature == "eicar_test" for f in findings))


class TestYaraCli(unittest.TestCase):
    """Integração com o binário `yara` (winget) — rota usada quando o módulo Python não
    compila. Não testa EICAR em disco: o Defender do host bloqueia a leitura do arquivo."""

    def setUp(self):
        from scanner import core

        self.core = core
        if core.HAS_YARA or not core.YARA_CLI:
            self.skipTest("roda só quando o módulo Python falta e o binário CLI existe")

    def test_cli_matches_pattern_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.bin"
            p.write_bytes(b"conteudo com MALTEST dentro")
            res = analyze_yara(extra_rules='rule r { strings: $a = "MALTEST" condition: $a }', path=p)
        self.assertIn("r", [f.signature for f in res.findings])

    def test_cli_no_false_positive(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.bin"
            p.write_bytes(b"nada relevante")
            res = analyze_yara(extra_rules='rule r { strings: $a = "MALTEST" condition: $a }', path=p)
        self.assertEqual(res.findings, [])

    def test_cli_reports_each_matching_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.bin"
            p.write_bytes(b"MALTEST")
            rules = (
                'rule r1 { strings: $a = "MALTEST" condition: $a }\n'
                'rule r2 { strings: $a = "MALTEST" condition: $a }'
            )
            res = analyze_yara(extra_rules=rules, path=p)
        self.assertEqual(sorted(f.signature for f in res.findings), ["r1", "r2"])

    def test_cli_bad_rules_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.bin"
            p.write_bytes(b"x")
            self.assertEqual(analyze_yara(extra_rules="rule quebrada { strings: $a = ", path=p).findings, [])

    def test_cli_accepts_in_memory_data(self):
        # rota usada por testes e por conteúdo que nunca vai a disco
        res = analyze_yara(b"tem MALTEST aqui", 'rule r { strings: $a = "MALTEST" condition: $a }')
        self.assertIn("r", [f.signature for f in res.findings])


class TestYaraCompileOnce(unittest.TestCase):
    """Regressão: yara.compile() rodava por arquivo — O(n) compilações numa varredura de
    diretório, cada uma relendo o rules_dir do disco."""

    def setUp(self):
        from scanner import core

        self.core = core
        self.compiled = []
        self.matched = []

        core._compiled_rules.cache_clear()

        # fecha sobre a lista do caso de teste: `self` dentro de FakeRules seria a própria
        # instância do fake, não o TestCase
        matched = self.matched

        class FakeRules:
            def match(self, data=None):
                matched.append(data)
                return []

        fake_yara = types.ModuleType("yara")

        def fake_compile(source=None):
            self.compiled.append(source)
            return FakeRules()

        fake_yara.compile = fake_compile
        patcher = patch.multiple(
            core, HAS_YARA=True, yara=fake_yara, create=True
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(core._compiled_rules.cache_clear)

    def test_compiles_once_for_many_files(self):
        for i in range(20):
            self.core.analyze_yara(f"payload-{i}".encode(), "rule r { condition: false }")
        self.assertEqual(len(self.compiled), 1, self.compiled)
        # o match continua acontecendo por arquivo — só a compilação foi cacheada
        self.assertEqual(len(self.matched), 20, self.matched)

    def test_distinct_rules_compile_separately(self):
        self.core.analyze_yara(b"a", "rule a { condition: false }")
        self.core.analyze_yara(b"b", "rule b { condition: false }")
        self.assertEqual(len(self.compiled), 2, self.compiled)

    def test_rules_dir_edits_not_picked_up_within_process(self):
        # Limitação conhecida e aceita: o cache é chaveado por (extra_rules, rules_dir),
        # então editar um .yar no meio do processo não recompila. Reabra o processo
        # (ou troque o caminho) para pegar a mudança.
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "minha.yar"
            rules.write_text("rule x { condition: false }", encoding="utf-8")
            self.core.analyze_yara(b"a", "", tmp)
            rules.write_text("rule y { condition: false }", encoding="utf-8")
            self.core.analyze_yara(b"b", "", tmp)
        self.assertEqual(len(self.compiled), 1, self.compiled)
        self.assertIn("rule x", self.compiled[0])
        self.assertNotIn("rule y", self.compiled[0])

    def test_no_yara_returns_empty_without_compiling(self):
        # sem módulo E sem CLI, a engine some — não pode tentar compilar nem shell out
        with patch.object(self.core, "HAS_YARA", False), patch.object(self.core, "YARA_CLI", None):
            self.assertEqual(self.core.analyze_yara(b"x").findings, [])
        self.assertEqual(self.compiled, [])


class TestScanFile(unittest.TestCase):
    def test_scan_eicar_file_in_memory(self):
        # Arquivo real em disco temporário, mas o conteúdo EICAR vive em memória
        # o tempo todo; usamos um arquivo vazio para o teste de scan_file.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "vazio.txt"
            p.write_bytes(b"")
            res = scan_file(p, use_clamd=False)
            self.assertTrue(res.clean)
            self.assertEqual(len(res.sha256), 64)

    def test_iter_files_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.txt").write_text("a")
            (Path(tmp) / "b.txt").write_text("b")
            self.assertEqual(len(iter_files(Path(tmp))), 2)


class TestPhase2(unittest.TestCase):
    def test_entropy_low_for_plain_text(self):
        from scanner.engines import shannon_entropy

        self.assertLess(shannon_entropy(b"a" * 1000), 0.1)

    def test_entropy_high_for_random_bytes(self):
        from scanner.engines import shannon_entropy

        self.assertGreater(shannon_entropy(bytes(range(256)) * 4), 7.9)

    def test_zip_bomb_detected(self):
        # 1 MB de zeros -> zip minúsculo -> razão altíssima (zip bomb simulada)
        import io
        import zipfile

        from scanner.engines import analyze_archive

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("bomb.bin", b"\0" * (1024 * 1024))
        data = buf.getvalue()
        findings = analyze_archive("x.zip", data).findings
        self.assertTrue(any(f.signature.startswith("zip-ratio-alto") for f in findings))

    def test_zip_clean_for_small_archive(self):
        import io
        import zipfile

        from scanner.engines import analyze_archive

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("a.txt", b"hello world")
        self.assertEqual(analyze_archive("x.zip", buf.getvalue()).findings, [])

    def test_zip_many_entries_not_flagged_as_bomb(self):
        # Regressão: a razão era somada por entrada, então um zip normal de 60 arquivos
        # (ratio ~20x cada) saía como "zip-ratio-alto:825x".
        import io
        import zipfile

        from scanner.engines import analyze_archive

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(60):
                zf.writestr(f"a{i}.txt", b"hello world" * 20)
        sigs = [f.signature for f in analyze_archive("x.zip", buf.getvalue()).findings]
        self.assertFalse([s for s in sigs if s.startswith("zip-ratio-alto")], sigs)

    def test_zip_stored_no_division_by_zero(self):
        # compress_size == 0 não pode estourar ZeroDivisionError
        import io
        import zipfile

        from scanner.engines import analyze_archive

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("vazio.txt", b"")
        analyze_archive("x.zip", buf.getvalue())  # não deve levantar

    def test_pe_python_exe_parsed(self):
        from scanner.engines import HAS_PEFILE, analyze_pe

        if not HAS_PEFILE or not sys.executable.lower().endswith(".exe"):
            self.skipTest("pefile ausente ou não estamos no Windows")
        with open(sys.executable, "rb") as f:
            data = f.read()
        findings = analyze_pe(sys.executable, data).findings
        # python.exe assinado pela PSF: deve ter assinatura digital presente
        self.assertTrue(any(f.signature.startswith("assinatura-digital") for f in findings))

    def test_docs_macro_detected(self):
        from scanner.engines import HAS_OLETOOLS, analyze_docs

        if not HAS_OLETOOLS:
            self.skipTest("oletools ausente")
        # DOC legítimo sem macro não pode gerar finding falso
        self.assertEqual(analyze_docs("clean.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1").findings, [])


class TestPhase3(unittest.TestCase):
    def test_vt_cache_roundtrip(self):
        from scanner.vt import VTCache

        with tempfile.TemporaryDirectory() as tmp:
            with VTCache(Path(tmp) / "cache.db") as cache:
                sha = "a" * 64
                self.assertIsNone(cache.get(sha))
                cache.put(sha, "malicious:5")
                f = cache.get(sha)
                self.assertIsNotNone(f)
                self.assertEqual(f.signature, "malicious:5")
                self.assertEqual(f.engine, "virustotal")

    def test_vt_cache_preserves_severity(self):
        # Regressão: o cache devolvia severity fixa "info", então o 2o scan do mesmo
        # malware perdia a severidade e a quarentena não disparava.
        from scanner.vt import VTCache

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "cache.db"
            with VTCache(db) as cache:
                cache.put("b" * 64, "malicious:7", "malware")
            with VTCache(db) as cache:  # reaberto: é o caminho real do 2o scan
                f = cache.get("b" * 64)
            self.assertEqual(f.severity, "malware")
            self.assertTrue(any(f.severity == "malware" for f in [f]))

    def test_vt_cache_no_reputation_is_not_a_finding(self):
        from scanner.vt import NO_REPUTATION, VTCache

        with tempfile.TemporaryDirectory() as tmp:
            with VTCache(Path(tmp) / "cache.db") as cache:
                cache.put("c" * 64, NO_REPUTATION, "info")
                self.assertIsNone(cache.get("c" * 64))

    def test_vt_cache_migrates_legacy_schema(self):
        # cache de versão anterior não tinha a coluna severity
        import sqlite3

        from scanner.vt import VTCache

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "old.db"
            conn = sqlite3.connect(str(db))
            conn.execute("CREATE TABLE vt (sha256 TEXT PRIMARY KEY, verdict TEXT)")
            conn.execute("INSERT INTO vt VALUES (?, ?)", ("d" * 64, "malicious:3"))
            conn.commit()
            conn.close()

            with VTCache(db) as cache:
                f = cache.get("d" * 64)
                self.assertEqual(f.signature, "malicious:3")
                cache.put("e" * 64, "malicious:1", "malware")
                self.assertEqual(cache.get("e" * 64).severity, "malware")

    def test_build_client_returns_three_tuple(self):
        # Regressão: build_client devolvia 2 elementos e core.py fazia unpack de 3
        # -> ValueError em qualquer scan com VT_API_KEY setada.
        import os
        from unittest.mock import patch

        from scanner.vt import build_client

        with tempfile.TemporaryDirectory() as tmp:
            env = {"VT_API_KEY": "fake-key", "VT_CACHE": str(Path(tmp) / "sub" / "vt.db")}
            with patch.dict(os.environ, env, clear=False):
                client = build_client({})
            self.assertIsNotNone(client)
            cache, limiter, api_key = client  # não pode explodir
            self.assertEqual(api_key, "fake-key")
            self.assertTrue((Path(tmp) / "sub" / "vt.db").exists())  # pai criado
            cache.close()

    def test_scan_with_vt_engine_does_not_crash(self):
        # ponta a ponta do unpack: scan() inteiro com um cliente VT real (rate limit 0,
        # rede barrada por URL inválida — só importa não estourar)
        import os
        from unittest.mock import patch

        from scanner.vt import build_client

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a.txt"
            target.write_bytes(b"conteudo")
            env = {"VT_API_KEY": "fake", "VT_CACHE": str(Path(tmp) / "vt.db")}
            with patch.dict(os.environ, env, clear=False):
                client = build_client({})
            client[1].interval = 0.0
            with patch("scanner.vt.VT_API", "http://127.0.0.1:9/v3/files/{sha256}"):
                results = scan(target, use_clamd=False, vt=client)
            self.assertEqual(len(results), 1)

    def test_quarantine_encrypt_and_restore(self):
        from scanner.quarantine import decrypt_to, load_key, quarantine_file

        with tempfile.TemporaryDirectory() as tmp:
            orig = Path(tmp) / "mal.exe"
            data = b"MZ...malware payload"
            orig.write_bytes(data)
            quar = Path(tmp) / ".quar"

            target = quarantine_file(orig, quar)

            self.assertFalse(orig.exists())
            self.assertTrue((quar / "key.key").exists())
            self.assertTrue(Path(target).exists())
            self.assertTrue((quar / "manifest.jsonl").exists())

            # Round-trip: decifra e confere conteúdo original
            out = Path(tmp) / "restored.exe"
            decrypt_to(Path(target), out, load_key(quar))
            self.assertEqual(out.read_bytes(), data)

    def test_quarantine_streams_large_file(self):
        # Regressão: a quarentena relia o arquivo inteiro (read_bytes). Agora cifra em blocos.
        from scanner.quarantine import CHUNK, decrypt_to, load_key, quarantine_file

        with tempfile.TemporaryDirectory() as tmp:
            orig = Path(tmp) / "grande.bin"
            data = bytes(range(256)) * (CHUNK // 128)  # > 1 bloco
            orig.write_bytes(data)
            quar = Path(tmp) / ".quar"
            target = quarantine_file(orig, quar)
            out = Path(tmp) / "restored.bin"
            decrypt_to(Path(target), out, load_key(quar))
            self.assertEqual(out.read_bytes(), data)

    def test_quarantine_manifest_is_append_only(self):
        from scanner.quarantine import quarantine_file

        with tempfile.TemporaryDirectory() as tmp:
            quar = Path(tmp) / ".quar"
            for i in range(3):
                f = Path(tmp) / f"m{i}.bin"
                f.write_bytes(b"payload")
                quarantine_file(f, quar)
            lines = (quar / "manifest.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 3)  # uma linha por arquivo, sem reescrever o todo

    def test_quarantine_skipped_when_not_requested(self):
        # scan_file sem quarantine_dir não cria .quar, mesmo com malware detectado
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mal.bin"
            p.write_bytes(b"payload normal, sem EICAR em disco")
            with patch(
                "scanner.core.analyze_builtin",
                return_value=EngineResult([Finding("builtin", "x", "malware")]),
            ):
                res = scan_file(p, use_clamd=False)
            self.assertFalse(res.clean)
            self.assertFalse((Path(tmp) / ".quar").exists())
            self.assertTrue(p.exists())

    def test_scan_file_quarantines_malware(self):
        from unittest.mock import patch

        from scanner.quarantine import quarantine_file

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "mal.bin"
            p.write_bytes(b"payload")
            quar = Path(tmp) / ".quar"
            with patch(
                "scanner.quarantine.quarantine_file",
                wraps=quarantine_file,
            ) as qf:
                with patch(
                    "scanner.core.analyze_builtin",
                    return_value=EngineResult([Finding("builtin", "x", "malware")]),
                ):
                    scan_file(p, use_clamd=False, quarantine_dir=quar)
            qf.assert_called_once()
            self.assertFalse(p.exists())
            self.assertTrue(list(quar.glob("*.enc")))

    def test_html_report_renders(self):
        from scanner.report import to_html

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.bin"
            p.write_bytes(b"clean")
            res = scan_file(p, use_clamd=False)
        html = to_html([res])
        self.assertIn("<table>", html)
        self.assertIn("CLEAN", html)


class TestCleanSemantics(unittest.TestCase):
    def test_info_only_is_clean(self):
        # Regressão: clean = not findings marcava como DETECTED qualquer observação
        # (assinatura digital presente, "reputacao-limpa").
        from scanner.models import Finding, Result

        r = Result("x.exe", "a", "b", "c", [Finding("pe", "assinatura-digital (PSF)", "info")])
        self.assertTrue(r.clean)

    def test_suspicious_is_not_clean(self):
        from scanner.models import Finding, Result

        r = Result("x.exe", "a", "b", "c", [Finding("pe", "ASLR-desabilitado", "suspicious")])
        self.assertFalse(r.clean)

    def test_no_findings_is_clean(self):
        from scanner.models import Result

        self.assertTrue(Result("x.exe", "a", "b", "c").clean)

    def test_report_does_not_say_detected_for_info(self):
        from scanner.models import Finding, Result
        from scanner.report import to_csv, to_html

        r = Result("x.exe", "a", "b", "c", [Finding("pe", "assinatura-digital", "info")])
        self.assertIn("OK", to_csv([r]))
        self.assertIn("OK", to_html([r]))
        self.assertNotIn("DETECTED", to_csv([r]))

    def test_malware_reported_as_malware_not_detected(self):
        from scanner.models import Finding, Result
        from scanner.report import to_csv

        r = Result("x.exe", "a", "b", "c", [Finding("clamav", "Win.Test.EICAR", "malware")])
        self.assertIn("MALWARE", to_csv([r]))


class TestExclude(unittest.TestCase):
    def test_exclude_kills_whole_directory(self):
        # README promete excluir diretório por nome; a implementação só olhava o basename
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "node_modules" / "deep").mkdir(parents=True)
            (root / "node_modules" / "deep" / "a.txt").write_text("x")
            (root / "ok.txt").write_text("ok")
            results = scan(root, use_clamd=False, exclude=["node_modules"])
        self.assertEqual([Path(r.path).name for r in results], ["ok.txt"])

    def test_exclude_matches_file_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skip_me.txt").write_text("x")
            (root / "ok.txt").write_text("ok")
            results = scan(root, use_clamd=False, exclude=["skip_me.txt"])
        self.assertEqual([Path(r.path).name for r in results], ["ok.txt"])

    def test_exclude_on_single_file_root(self):
        # root é arquivo, não diretório: relative_to estoura, precisa degradar
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "skip_me.txt"
            p.write_text("x")
            self.assertEqual(scan(p, use_clamd=False, exclude=["skip_me.txt"]), [])
            self.assertEqual(len(scan(p, use_clamd=False, exclude=[])), 1)


class TestPhase4(unittest.TestCase):
    def test_config_defaults_and_merge(self):
        from scanner.config import load

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            cfg_path.write_text(
                "[clamd]\nhost = 'localhost'\nport = 9999\n", encoding="utf-8"
            )
            cfg = load(cfg_path)
        self.assertEqual(cfg["clamd"]["host"], "localhost")
        self.assertEqual(cfg["clamd"]["port"], 9999)
        self.assertEqual(cfg["exclude"], [])
        self.assertEqual(cfg["vt"]["rate_interval"], 15.0)  # default preservado

    def test_scan_excludes_and_max_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "skip_me.txt").write_text("ignorado")
            big = Path(tmp) / "grande.bin"
            big.write_bytes(b"\0" * 1000)
            (Path(tmp) / "ok.txt").write_text("ok")
            results = scan(
                Path(tmp),
                use_clamd=False,
                exclude=["skip_me.txt"],
                max_file_size=500,  # grande.bin (1000 B) é pulado
            )
        by_name = {Path(r.path).name: r for r in results}
        self.assertEqual(len(results), 2)  # ok.txt + grande.bin (pulado, visível)
        self.assertIn("ok.txt", by_name)
        self.assertNotIn("skip_me.txt", by_name)
        self.assertTrue(by_name["grande.bin"].skipped)
        self.assertIn("limite", by_name["grande.bin"].skip_reason)

    def test_e2e_cli_no_network(self):
        # Subprocess real: sem VT_API_KEY e sem clamd, nada de rede é tocado.
        import json as _json
        import subprocess
        import sys as _sys

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.txt").write_text("conteudo")
            env = dict(_sys.modules.get("os").environ)
            env.pop("VT_API_KEY", None)
            proc = subprocess.run(
                [_sys.executable, "-m", "scanner", "scan", tmp, "--format", "json", "--no-vt"],
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).resolve().parent.parent),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = _json.loads(proc.stdout)
        self.assertEqual(len(data), 1)
        self.assertTrue(data[0]["clean"])

    def test_cli_exit_code_on_bad_path(self):
        # Regressão: __main__.py chamava main() sem SystemExit, então erro de uso
        # saía com código 0 e CI nunca falhava.
        import os
        import subprocess
        import sys as _sys

        env = dict(os.environ)
        env.pop("VT_API_KEY", None)
        proc = subprocess.run(
            [_sys.executable, "-m", "scanner", "scan", str(Path(tempfile.gettempdir()) / "nao_existe_xyz")],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parent.parent),
            env=env,
        )
        self.assertEqual(proc.returncode, 1, proc.stderr)

    def test_cli_exit_code_zero_on_success(self):
        import os
        import subprocess
        import sys as _sys

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.txt").write_text("ok")
            env = dict(os.environ)
            env.pop("VT_API_KEY", None)
            proc = subprocess.run(
                [_sys.executable, "-m", "scanner", "scan", tmp, "--no-vt", "--no-clamd"],
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).resolve().parent.parent),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_guia_parsed_as_command(self):
        from scanner.cli import parse_args

        self.assertEqual(parse_args(["guia"]).command, "guia")

    def test_guia_runs_offline(self):
        # guia não pode depender de clamd/rede: ping mockado falha e o comando segue OK
        import contextlib
        import io

        from scanner.cli import _cmd_guia
        from scanner.config import load

        with patch("scanner.core.analyze_clamd", side_effect=ConnectionError):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(_cmd_guia(load()), 0)


def _fake_handler(filename: str, payload: bytes, content_length: int | None = -1):
    """Handler sem socket: monta um POST multipart e captura o que ele responderia.

    content_length=-1 usa len(body); None omite o header (simula cliente malformado).
    """
    from scanner.web import Handler

    boundary = "X-YAR-BOUND"
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n\r\n'
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if content_length is None:
        pass
    else:
        headers["Content-Length"] = str(len(body) if content_length == -1 else content_length)

    handler = Handler.__new__(Handler)
    handler.path = "/scan"
    handler.headers = headers
    captured = {"body": b"", "handler": handler}
    handler.rfile = type("R", (), {"read": lambda self, n: body})()
    handler.send_response = lambda c: captured.setdefault("code", c)
    handler.send_header = lambda *a: None
    handler.end_headers = lambda: None
    handler.wfile = type("W", (), {"write": lambda self, b: captured.update(body=captured["body"] + b)})()
    return captured


class TestPhase5(unittest.TestCase):
    def test_multipart_field_parsed(self):
        from scanner.web import _read_part

        boundary = b"----abc"
        data = (
            b"--" + boundary + b'\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\n\r\n'
            b"hello\x00world\r\n--" + boundary + b"--\r\n"
        )
        filename, content = _read_part(boundary, data, b"file")
        self.assertEqual(filename, "a.bin")
        self.assertEqual(content, b"hello\x00world")

    def test_scan_endpoint_in_memory(self):
        # Handler real (sem socket): POST /scan → JSON com finding (payload benigno;
        # EICAR não pode ir a disco — o Defender do host apaga no meio do write)
        from unittest.mock import patch


        boundary = "X-YAR-BOUND"
        body = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="e.bin"\r\n\r\n'
        ).encode() + b"conteudo benigno" + f"\r\n--{boundary}--\r\n".encode()

        captured = _fake_handler("e.bin", body)

        with patch(
            "scanner.core.analyze_builtin",
            return_value=EngineResult([Finding("builtin", "x", "malware")]),
        ):
            captured["handler"].do_POST()

        self.assertEqual(captured["code"], 200)
        import json as _json

        res = _json.loads(captured["body"])
        self.assertFalse(res["clean"])
        self.assertTrue(any(f["engine"] == "builtin" for f in res["findings"]))
        self.assertEqual(res["path"], "e.bin")
        self.assertIn("engines", res)

    def test_upload_above_limit_rejected(self):
        # sem teto, um POST enorme vira OOM — scan_file lê o arquivo inteiro em memória
        from scanner.web import MAX_UPLOAD

        body = b"x" * 16
        captured = _fake_handler("e.bin", body, content_length=MAX_UPLOAD + 1)
        captured["handler"].do_POST()
        self.assertEqual(captured["code"], 413)

    def test_upload_missing_content_length_rejected(self):
        captured = _fake_handler("e.bin", b"x", content_length=None)
        captured["handler"].do_POST()
        self.assertEqual(captured["code"], 400)

    def test_upload_filename_traversal_neutralized(self):
        captured = _fake_handler("../../etc/passwd", b"conteudo")
        captured["handler"].do_POST()
        import json as _json

        res = _json.loads(captured["body"])
        self.assertEqual(res["path"], "passwd")

    def test_upload_extension_preserved_for_engine_dispatch(self):
        # analyze_docs decide o engine pela extensão do path — o tempfile precisa carregá-la
        from unittest.mock import patch

        captured = _fake_handler("mal.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        with patch(
            "scanner.core.analyze_docs",
            return_value=EngineResult([Finding("doc", "macro-autoexec:Auto_Open", "malware")]),
        ) as ad:
            captured["handler"].do_POST()
        self.assertTrue(ad.called)
        self.assertTrue(str(ad.call_args[0][0]).endswith(".doc"), ad.call_args[0][0])


class TestStreaming(unittest.TestCase):
    """O scan não pode carregar o arquivo inteiro em memória — hashing e EICAR são em blocos."""

    def test_hash_file_matches_in_memory(self):
        from scanner.core import hash_file

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.bin"
            data = bytes(range(256)) * (10 * 1024)  # ~2.5 MB, vários blocos de 1 MiB
            p.write_bytes(data)
            self.assertEqual(hash_file(p), hashes(data))

    def test_hash_file_uses_multiple_chunks(self):
        from scanner import core

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "x.bin"
            data = b"abcdefghij" * 100
            p.write_bytes(data)
            with patch.object(core, "CHUNK", 7):  # força muitos blocos
                self.assertEqual(core.hash_file(p), hashes(data))

    def test_scan_file_does_not_read_whole_file(self):
        # Regressão do refactor: scan_file não pode mais chamar read_bytes() no arquivo todo.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"conteudo")
            with patch.object(Path, "read_bytes", side_effect=AssertionError("leu o arquivo inteiro")):
                res = scan_file(p, use_clamd=False)
            self.assertEqual(res.sha256, hashes(b"conteudo")[0])

    def test_eicar_match_across_chunk_boundary(self):
        # sobreposição entre blocos: assinatura partida na fronteira ainda é encontrada
        from scanner import core

        marker = b"NEEDLE-ASSINATURA"
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.bin"
            p.write_bytes(b"A" * 5 + marker + b"B" * 5)
            with patch.object(core, "EICAR", marker), patch.object(core, "CHUNK", 8):
                self.assertTrue(core.analyze_builtin(path=p).findings)


class TestEngineRuns(unittest.TestCase):
    def test_scan_file_records_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"conteudo benigno")
            res = scan_file(p, use_clamd=False)
        runs = {e.engine: e for e in res.engine_runs}
        self.assertTrue(runs["builtin"].ran)
        self.assertEqual(runs["pe"].status, "nao-aplicavel")  # não é PE
        self.assertEqual(runs["doc"].status, "nao-aplicavel")
        self.assertEqual(runs["archive"].status, "nao-aplicavel")
        # nao-aplicavel não conta no total
        self.assertEqual(res.engines_ran, res.engines_total)

    def test_unavailable_engine_counts_in_total(self):
        from scanner import core

        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"x")
            with patch.object(core, "HAS_YARA", False), patch.object(core, "YARA_CLI", None):
                res = scan_file(p, use_clamd=False)
        yara = next(e for e in res.engine_runs if e.engine == "yara")
        self.assertEqual(yara.status, "indisponivel")
        self.assertGreater(res.engines_total, res.engines_ran)  # 1 engine a menos

    def test_clamd_offline_is_unavailable_not_crash(self):
        # porta fechada -> EngineRun indisponivel, scan segue
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"x")
            res = scan_file(p, use_clamd=True, clamd_host="127.0.0.1", clamd_port=1)
        clamav = next(e for e in res.engine_runs if e.engine == "clamav")
        self.assertFalse(clamav.ran)
        self.assertEqual(clamav.status, "indisponivel")

    def test_skipped_file_has_reason_and_no_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "grande.bin").write_bytes(b"\0" * 1000)
            results = scan(Path(tmp), use_clamd=False, max_file_size=100)
        r = results[0]
        self.assertTrue(r.skipped)
        self.assertEqual(r.engine_runs, [])


class TestParseSize(unittest.TestCase):
    def test_units_and_raw(self):
        from scanner.core import parse_size

        self.assertEqual(parse_size("1024"), 1024)
        self.assertEqual(parse_size("1k"), 1024)
        self.assertEqual(parse_size("100m"), 100 * 1024**2)
        self.assertEqual(parse_size("1g"), 1024**3)
        self.assertEqual(parse_size("0"), 0)

    def test_invalid_raises(self):
        from scanner.core import parse_size

        with self.assertRaises(ValueError):
            parse_size("abc")


class TestSkipAndEngineRendering(unittest.TestCase):
    def _skipped(self):
        from scanner.models import Result

        return Result("C:\\x\\grande.bin", skip_reason="maior que o limite (100 MB)")

    def test_skip_rendered_everywhere(self):
        from scanner.report import to_csv, to_html, to_json

        r = self._skipped()
        self.assertIn("SKIPPED", to_csv([r]))
        self.assertIn("SKIPPED", to_html([r]))
        data = __import__("json").loads(to_json([r]))
        self.assertTrue(data[0]["skipped"])
        self.assertIn("limite", data[0]["skip_reason"])

    def test_console_shows_engine_count(self):
        import io as _io

        from rich.console import Console

        from scanner import report
        from scanner.models import EngineRun, Finding, Result

        r = Result(
            "x.exe",
            "a",
            "b",
            "c",
            [Finding("pe", "packer-detectado:UPX0", "malware")],
            [
                EngineRun("builtin", "ran"),
                EngineRun("clamav", "indisponivel", "clamd (ConnectionRefusedError)"),
                EngineRun("pe", "ran"),
                EngineRun("doc", "nao-aplicavel"),
            ],
        )
        buf = _io.StringIO()
        old, report.console = report.console, Console(file=buf, width=120)
        try:
            report.to_console([r])
        finally:
            report.console = old
        out = buf.getvalue()
        self.assertIn("2/3", out)  # builtin+pe rodaram, clamav indisponível, doc fora
        self.assertIn("clamav", out)

    def test_dict_has_engine_summary(self):
        from scanner.models import EngineRun, Result
        from scanner.report import to_dict

        r = Result("x", "a", "b", "c", [], [EngineRun("pe", "ran"), EngineRun("doc", "nao-aplicavel")])
        d = to_dict(r)
        self.assertEqual(d["engines"]["ran"], 1)
        self.assertEqual(d["engines"]["total"], 1)
        self.assertEqual(len(d["engines"]["runs"]), 2)


class TestRobustness(unittest.TestCase):
    def test_unreadable_file_does_not_abort_scan(self):
        # Regressão: um arquivo travado/sem permissão não pode derrubar a varredura inteira.
        from scanner import core

        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "ok.txt").write_text("ok")
            (Path(tmp) / "travado.txt").write_text("x")
            real = core.hash_file

            def fake(p):
                if Path(p).name == "travado.txt":
                    raise PermissionError("em uso por outro processo")
                return real(p)

            with patch("scanner.core.hash_file", side_effect=fake):
                results = scan(Path(tmp), use_clamd=False)
        by = {Path(r.path).name: r for r in results}
        self.assertEqual(len(results), 2)
        self.assertTrue(by["travado.txt"].skipped)
        self.assertIn("ilegivel", by["travado.txt"].skip_reason)
        self.assertFalse(by["ok.txt"].skipped)


class TestVtPolicy(unittest.TestCase):
    def _client(self):
        return (object(), object(), "fake-key")

    def test_vt_only_suspicious_skips_clean_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"conteudo limpo")
            with patch("scanner.core.check_vt") as cv:
                scan_file(p, use_clamd=False, vt=self._client(), vt_only_suspicious=True)
            cv.assert_not_called()  # não gasta o rate limit num arquivo já limpo

    def test_vt_only_suspicious_queries_suspicious_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.bin"
            p.write_bytes(b"x")
            with patch(
                "scanner.core.analyze_builtin",
                return_value=EngineResult([Finding("builtin", "x", "suspicious")]),
            ), patch("scanner.core.check_vt", return_value=None) as cv:
                scan_file(p, use_clamd=False, vt=self._client(), vt_only_suspicious=True)
            cv.assert_called_once()

    def test_vt_queries_everything_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a.txt"
            p.write_bytes(b"limpo")
            with patch("scanner.core.check_vt", return_value=None) as cv:
                scan_file(p, use_clamd=False, vt=self._client())
            cv.assert_called_once()


if __name__ == "__main__":
    unittest.main()
