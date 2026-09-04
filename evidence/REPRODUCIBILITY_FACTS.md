# Reproducibility Facts — What Is Actually Documented

**Prepared:** 2026-08-22

## 1. Software / library versions — documented

| Item | Value | Source |
|---|---|---|
| RDF parsing library | `rdflib 7.6.0` | `REASONER_EXECUTION_REPORT.md` line 14; independently confirmed this session — the live `v7\.venv` virtual environment has `rdflib==7.6.0` installed and importable (`python -c "import rdflib; print(rdflib.__version__)"` → `7.6.0`) |
| Python | 3.14.3 | `REASONER_EXECUTION_REPORT.md` line 17; confirmed this session (`v7\.venv\Scripts\python.exe --version` → `Python 3.14.3`) |
| Reasoning engine (actual) | Custom Python program using rdflib forward-chaining / graph traversal to emulate SWRL rule semantics — **not** a certified OWL/SWRL reasoner | `RiskOnto_WebGoat_Conference_FINAL.tex` lines 116, 1164–1165 (conference paper's own explicit statement); `REASONER_EXECUTION_REPORT.md` lines 41–46 (implicitly, by recommending Pellet/HermiT be run "if required," meaning neither had been) |
| Ontology editor | Protégé 5.x | `RiskOnto_WebGoat_Conference_FINAL.tex` line 699 (cited as the editing tool, not the reasoning engine) |
| Reasoner compatibility claim (not confirmed as used) | "HermiT, Pellet" | `RiskOnto_Current_Capabilities.md` line 44 — states OWL 2 DL profile compatibility, not that either reasoner was actually run |
| Scanners used | Semgrep, SonarQube (Issues + Hotspots), Snyk, OWASP ZAP | Confirmed via primary artifact `finding_normalization_map.csv` (273 rows tagged by scanner) and both papers' tables |
| Scanner tool versions | **NOT FOUND** — no scanner version numbers (e.g. Semgrep X.Y, SonarQube edition/version, Snyk CLI version, ZAP version) located in any evidence file read this session | — |

## 2. Ontology file format and toolchain — documented

- Global ontology files: RDF/XML serialization, confirmed by direct file-header read this session.
- SUT ontology files: **Turtle** serialization, despite `.owl` extension — confirmed by direct file-header read this session (this is a real reproducibility trap: a naive `rdflib.Graph().parse(path)` call without `format="turtle"` fails on every SUT file with a "not well-formed" XML parse error, as reproduced in this session's first parse attempt).
- Python venv with `rdflib`, plus rdflib's bundled CLI utilities (`rdfpipe.exe`, `rdf2dot.exe`, `csv2rdf.exe`, `sparqlquery.exe`, etc.) exists at `v7\.venv\` and an apparently-duplicate `v7\.venv-1\` and a parallel `v7_25\.venv\`/`.venv-1\` — multiple, seemingly redundant virtual environments exist across the project tree; which one (if any) is the "canonical" environment for reproducing published figures is not documented anywhere found this session.
- `v7\SUT\catalog-v001.xml` exists (421 bytes, not opened this session) — likely an OWL catalog file for import resolution; its role in the reproducible build is not documented in any `.md` audit file read.

## 3. Execution procedure — partially documented

- `REASONER_EXECUTION_REPORT.md` line 119 names the script that generated most of the journal-side evidence files: `extract_reasoning.py`, run 2026-06-17 22:38. This script exists at `v7\extract_reasoning.py` (50,828 bytes, confirmed present in this session's directory listing) but was **not opened or executed** this session.
- SI-12 (conference-side activation rule) scripts exist by name at `v7\`: `riskonto_si12.py`, `riskonto_si12_1.py`, `riskonto_si12_forensic.py`, `riskonto_sut2d.py`, `riskonto_sut2d_1.py`, `riskonto_v25_audit.py`, `riskonto_v25_expand.py` — none opened/executed this session.
- SUT-population scripts: `sut2a_pipeline.py`, `sut2a_forensic_audit.py`, `sut2a_probe.py`, `sut2a_reaudit.py`, `sut2b_populate.py`, `sut1_schema_extract.py` — none opened/executed this session.
- SI-phase implementation/audit scripts (si5 through si11): a large number of `.py` and corresponding `_output.txt`/`_report.txt` files exist at `v7\` top level (e.g. `si11_implementation.py` + `si11_1_audit.py`, `si7_reasoning_implementation.py` + `si7_reasoning_report.txt`) — these appear to be a genuine, fairly complete build log of how the ontology reached its current state, phase by phase, but this session did not read them individually; their existence is noted as evidence that a documented, scripted (not manual/ad hoc) construction process exists, even though this session did not verify its contents.
- No single top-level "run this to reproduce everything" script or README describing the end-to-end build order was identified — `v7\README.md` (768 bytes) exists but was not opened this session.

## 4. What this session itself demonstrated is reproducible

- All ontology statistics in `ONTOLOGY_STATISTICS.md` were derived via a from-scratch Python script (`analyze_owl.py`/`analyze_sut.py`, written this session, not part of the original project) that any reader with access to the same `.venv` and the same `.owl`/`.ttl` files could re-run to get identical results — this constitutes an actual reproducibility demonstration, not just a claim.
- Parse times: global files 8.6–12.4 seconds each; SUT files sub-second (small file sizes, 2–2.3K triples). No memory-usage figures were collected or are claimed.

## 5. Sources

- `RiskOnto_v1_revision/REASONER_EXECUTION_REPORT.md`
- `conferencePaper/sourceFile/RiskOnto_webgoat/RiskOnto_WebGoat_Conference_FINAL.tex`
- This session's direct environment inspection (`v7\.venv`) and file-header reads
