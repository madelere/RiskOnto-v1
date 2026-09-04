# Canonicalization Final Count Verification

No manuscript edits precede this document. Answers below are additional to, and cross-validate,
`CANONICALIZATION_FORENSIC_VERIFICATION.md`.

| Question | Answer | Evidence |
|---|---:|---|
| Total raw outputs | **273** | `raw_findings_inventory.csv`, 273 unique `finding_id` |
| Outputs lacking CWE representation | **107** | Same file's own `cwe` column = literal `"NONE"` |
| Outputs entering CWE-based canonicalization | **166** | 273 − 107; independently re-derived (not just subtraction) — see below |
| Canonical security findings produced | **43** | `canonical_findings.csv` (43 CWE-based rows) AND independently re-confirmed by direct query of `SUT/WebGoat_SUT_v27_reasoned.owl`: exactly 43 `CanonicalSecurityFinding` individuals |
| 273 − 107 = 166? | **Yes, arithmetically**, AND **independently confirmed as the true participating population** (not just the remainder) — see below | |
| Do all 166 actually participate in canonicalization (not merely the arithmetic remainder)? | **YES, proven by set-equality, not arithmetic** | The union of `supporting_findings` across all 43 CWE-based canonical rows was computed independently and compared to the set of raw findings with a real CWE: **identical sets, 166 = 166, zero difference** |
| Exact canonicalization grouping logic | CWE-identity via a canonical-ID catalog lookup: `canon_id = cwe_to_canon.get(finding.cwe, none_canon)`; scanner retained as provenance only, never a grouping key; no location/file/line field participates | `sut2a_pipeline.py`, `phase3_normalize`/`phase4_fuse` |
| Additional security filtering beyond CWE availability? | **No.** The only gate is CWE presence. No severity filter, no scanner filter, no category filter exists in the grouping code. | Same source; no `if`/`continue` beyond the dict lookup default |
| Are the 107 retained in the raw dataset, or excluded? | **Retained** in `raw_findings_inventory.csv` (the raw dataset). They also **do** pass through canonicalization — grouped into one shared bucket (`CANVULN-045`, "Code Quality Issue (No CWE)") — but that bucket is not published as one of "the 43" and, critically, **does not become an OWL `CanonicalSecurityFinding` individual** in the SUT ontology (confirmed: ontology has exactly 43, not 44) | `raw_findings_inventory.csv`; `canonical_findings.csv`; direct query of `WebGoat_SUT_v27_reasoned.owl` |
| Exact distribution of the 107 by source/category | SonarQube Issues 99, SonarQube Hotspots 5, ZAP 3, Semgrep 0, Snyk 0; by `raw_category`: `CODE_SMELL` 92, `BUG` 7, `others` 5, `Informational` 3 | `raw_findings_inventory.csv` |

## Independent cross-validation via a second, separately-coded pipeline
A second, independently-organized evidence trail — `SUT/reaudit/phase5_catalog/canonical_vulnerability_catalog.csv`
and `SUT/reaudit/phase8_eligibility/reasoning_entry_candidates.csv` (distinct directory structure,
distinct from `sut2a_pipeline.py`'s `SUT/evidence/` output) — independently produces **the same 44
total groups** (43 CWE-based + 1 `CodeQuality`/no-CWE bucket), corroborating the primary pipeline's
result rather than contradicting it. This second trail is also the confirmed origin of the
historical `eligible_for_reasoning: YES=13 / NO=31` split investigated earlier in this project
(a narrower, two-part legacy gate requiring both `cwe_in_ontology: YES` and `vp_in_ontology: YES`,
superseded by the current SI-12 CWE-based activation mechanism, which the manuscript already
correctly documents as achieving 43/43 independent of that legacy gate).

## Does the intermediate population reproduce exactly, or is there a mismatch requiring a STOP?
**No mismatch. No STOP required.** Two independently-organized pipelines (`sut2a_pipeline.py` →
`SUT/evidence/`, and the reaudit trail → `SUT/reaudit/`) agree exactly on: 273 raw, 107 excluded
from CWE-canonicalization, 43 published canonical findings. The actual SUT ontology file
independently confirms 43 `CanonicalSecurityFinding` individuals. All four sources agree.
Proceeding to manuscript correction is evidence-supported.
