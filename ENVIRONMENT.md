# Environment / Software Versions

This documents the software versions actually used to produce the reported
results, as recorded in the project's reproducibility evidence
(`evidence/REVISION2_REPRODUCIBILITY_PROTOCOL.md`,
`evidence/REPRODUCIBILITY_FACTS.md`, `evidence/HARDWARE_ENVIRONMENT_EVIDENCE.md`).
No version is invented here; where a version is not recorded in the
project's evidence archive, that is stated explicitly rather than guessed.

## Core reasoning / ontology tooling

| Tool | Version |
|---|---|
| Python | 3.14.3 |
| rdflib | 7.6.0 |
| HermiT (OWL 2 DL consistency checking only, via Protégé) | 1.4.3.456 |
| Protégé | 5.6 |

## Scanner tools (WebGoat case study)

| Tool | Version |
|---|---|
| Semgrep | 1.161.0 |
| Snyk CLI | 1.1304.1 (currently-installed CLI version; no version field is embedded in the original scan output, so it is not confirmed identical to the CLI version that produced the historical result — see `data/README.md`) |
| SonarQube | 9.9.8.100196 (analysis *server* version; the SonarScanner CLI/plugin version is a distinct number not recoverable from any available artifact) |
| OWASP ZAP | 2.17.0 |
| Target: OWASP WebGoat | 2025.4-SNAPSHOT |

## What is NOT currently recorded

- No `requirements.txt` or `environment.yml` exists in the project archive.
  Exact full transitive dependency pinning (e.g., every package version
  `rdflib` itself depends on) is not currently recorded and is not
  fabricated here. At minimum, `pip install rdflib==7.6.0` on Python 3.14
  reproduces the core reasoning/materialization environment; other
  standard-library-only scripts have no further dependency.
- No CI/build seed values exist for the (deterministic, rule-based, not
  randomized) materialization pipeline — none are applicable, since no
  stochastic process is used in ontology population or reasoning.
- SonarScanner CLI/plugin version and the exact Snyk CLI version at the
  time of the original scan are not recoverable from any available
  artifact (see the caveats in `data/README.md` and
  `data/scanner_raw/` table footnotes carried over from the manuscript).

## Hardware / execution environment

See `evidence/HARDWARE_ENVIRONMENT_EVIDENCE.md` for the machine
specification and parse-time/memory figures recorded for the consolidated
ontology and the WebGoat SUT ontology. These are reported as a one-off,
non-benchmark observation, not a controlled multi-run performance study
(see manuscript Sec. VIII-J, "Reproducibility").

## Portability note

The scripts in `src/` contain hardcoded local Windows filesystem paths
(e.g. `c:\Users\user\Desktop\PhDfiles\v7\...`) from the original research
environment. `user` here is a generic local Windows account name, not a
personal identifier. These paths must be edited to match a new environment
before re-running any script; this is a portability limitation, not a
functional dependency, and none of the released `.owl`, `.csv`, or `.json`
artifacts require running these scripts to be inspected or queried
directly.

## Reproduction steps (as far as currently released evidence permits)

1. Obtain WebGoat 2025.4-SNAPSHOT (OWASP) and run it locally.
2. Run the four scanner tools listed above against the running instance;
   raw outputs are provided in `data/scanner_raw/` for reference/replay
   without re-running the scanners.
3. Normalize and canonicalize raw findings: `src/sut_pipeline/sut2a_pipeline.py`
   (10-phase pipeline: inventory -> catalog -> normalize -> fuse ->
   classify -> exploitability -> audit -> triples -> metrics -> certify).
4. Populate the SUT ontology: `src/sut_pipeline/sut1_schema_extract.py`,
   then `src/sut_pipeline/sut2b_populate.py`.
5. Materialize global reasoning (already pre-materialized in the released
   `ontologies/RiskOnto_global_v27_consolidated.owl` — these scripts
   reproduce that materialization from an unreasoned base ontology, not
   required merely to inspect the released ontology):
   `src/reasoning/si7_reasoning_implementation.py` (R1-R4),
   `src/reasoning/si9_implementation.py` (E1-E4),
   `src/reasoning/si11_implementation.py` (X1-X5).
6. Activate SUT-side VulnerabilityProfile matches:
   `src/reasoning/riskonto_si12.py` (SI-12).
7. Inspect/verify structural counts and generate an ontology inventory
   report: `src/reproducibility/generate_final_cert_report.py`.
8. Query either released `.owl` file directly with `rdflib`/SPARQL to
   reproduce any count reported in the paper.

**Honesty note on reproducibility scope:** running the scanners against a
freshly deployed WebGoat instance may not reproduce byte-identical raw
output (tool updates, WebGoat version drift, non-deterministic scan
ordering in some tools). The released `data/scanner_raw/` files are the
actual historical inputs used to produce the paper's reported counts, so
that downstream stages (3-8 above) can be reproduced deterministically
even if step 2 is not re-run.
