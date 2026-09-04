# Data Artifacts

Raw scanner outputs and intermediate normalization/canonicalization artifacts
for the WebGoat 2025.4-SNAPSHOT case study reported in the paper. These are
copies of the pipeline's own intermediate CSV/JSON outputs, included for
provenance and reproducibility, not hand-curated for publication.

## `scanner_raw/`

The five raw scanner report files (four tools; SonarQube contributes two
streams), matching Table "WebGoat SUT: Scanner Coverage and Normalization" in
the manuscript: `semgrep_report.json` (17 findings), `sonarqube_issues.json`
(100), `sonarqube_hotspots.json` (69), `snyk_results.json` (77),
`zap_webgoat_report.json` (10) — 273 raw findings in total.

`sonarqube_issues.json` and `sonarqube_hotspots.json` include upstream
WebGoat project commit-author email addresses as embedded SonarQube issue
metadata (public open-source contributor information from WebGoat's own
public GitHub history, not private data belonging to this project).
`zap_webgoat_report.json` contains WebGoat's own intentionally-hardcoded demo
credentials (`username=ZAP&password=ZAP`) captured as the finding evidence
for a deliberately vulnerable authentication flow in the WebGoat training
application itself — not a real secret.

## `normalized/mappings/finding_normalization_map.csv`

273 rows — one per raw finding, matching `scanner_raw/` exactly. This is the
authoritative raw-finding-level record referenced throughout the paper.

## `normalized/canonical_catalog/canonical_vulnerability_catalog.csv`

45 rows: `CANVULN-001`-`CANVULN-043` are the 43 CWE-representable canonical
findings that match the paper's reported 43 exactly. `CANVULN-044` and
`CANVULN-045` are the pipeline's internal "no-CWE" catch-all bucket rows
(the single shared, unpublished group the paper's canonicalization algorithm
description routes the 107 out-of-scope raw findings into) — **these two
rows are not `CanonicalSecurityFinding` individuals in the ontology and are
not part of the reported 43.**

The `riskonto_vp` column for `CANVULN-043` (CWE-94) shows
`VulnProfile_Agent_Injection`. **This is a known, stale, single-value
artifact of an early catalog-generation lookup** (`dict.setdefault()` over
CWE, keeping only the first-encountered VulnerabilityProfile in RDF
iteration order — not a relevance ranking), generated before and
independently of the ontology's actual SI-12 activation pass. The ontology
itself asserts 9 `activatesProfile` links for this finding, including the
contextually appropriate `VulnProfile_Code_Injection`; see
`evidence/CV043_CURRENT_STATE_FORENSIC_AUDIT.md` and the paper's CV-043
discussion (Sec. VIII-H) for the authoritative account. This CSV field is
retained unmodified for provenance and must not be read as the paper's
claimed VP mapping for CV-043.

## `normalized/classifications/`

`finding_classification.csv` (44 rows: the 43 canonical findings plus the
`CANVULN-045` no-CWE bucket row) carries a `classification` column;
`exploitable_findings.csv` (13 rows) and `non_exploitable_findings.csv` (31
rows) are that same file split by
`classification == "ExploitableVulnerability"` vs. all other classification
values. **This exploitability classification is unrelated to the legacy
`eligibleForReasoning` datatype flag discussed in the paper (Sec. VIII-E) —
it does not represent, and should not be confused with, the superseded
"13 of 43" reasoning-activation figure.** The paper's current, authoritative
activation-coverage result (43/43) is independently verified by direct
`rdflib` query of the ontology, not from this classification split.

## `metadata/sut_metrics.csv`

Summary pipeline metrics for the WebGoat SUT run.

## Authoritative source of the published counts

For every count reported in the paper (273, 166, 107, 43, 43/43, 19,671,
847, etc.), the **ontology itself** (`../ontologies/WebGoat_SUT_v27_reasoned.owl`
and `../ontologies/RiskOnto_global_v27_consolidated.owl`), queried directly
via `rdflib`, is the authoritative source — not any intermediate CSV in this
folder. The CSVs are included for pipeline-stage transparency and
reproducibility of the intermediate steps, not as a second source of truth.
