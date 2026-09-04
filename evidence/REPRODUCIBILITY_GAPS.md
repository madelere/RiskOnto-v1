# Reproducibility Gaps — Classified

**UPDATE (post-2026-08-22, this row only):** the "Ontology consistency check (OWL 2 DL,
Pellet/HermiT)" row below, classified NOT AVAILABLE at the time this document was written, is
**superseded** — the author has since supplied direct evidence (Protégé screenshots + confirmation)
that HermiT 1.4.3.456 was run via Protégé with no inconsistencies reported. See
`HERMIT_PROTEGE_CONSISTENCY_EVIDENCE.md` for the current, authoritative state. The rest of this
document's classifications are preserved unchanged as an accurate historical record of the
2026-08-22 evidence state.

**Prepared:** 2026-08-22
**Classification key:** CAN BE MEASURED NOW (this session or a follow-up session has direct access to what's needed) / CAN BE DOCUMENTED FROM EXISTING ENVIRONMENT (the answer exists somewhere accessible but wasn't extracted this session) / NOT AVAILABLE (no evidence anywhere suggests this was ever recorded) / NOT APPLICABLE.

No runtime performance or memory numbers are fabricated anywhere below — where none exist, this is stated as NOT AVAILABLE, not estimated.

| Gap | Classification | Notes |
|---|---|---|
| Scanner tool version numbers (Semgrep, SonarQube, Snyk, ZAP) | **NOT AVAILABLE** | Not found in any evidence file; the raw scanner JSON reports (`v7\SUT\Scanner_results\`) might contain tool-version metadata internally but were not opened this session — reclassify to CAN BE DOCUMENTED FROM EXISTING ENVIRONMENT if those JSON files are later opened and contain version fields. |
| Reasoner/rule-execution engine identity | **CAN BE DOCUMENTED FROM EXISTING ENVIRONMENT** | Already resolved this session: a custom Python/rdflib forward-chaining script, not Pellet/HermiT — see `REPRODUCIBILITY_FACTS.md` §1 and `REASONING_LIFECYCLE.md`. This row is listed as a gap only in the sense that the manuscript itself does not yet state this plainly. |
| rdflib / Python version | **CAN BE MEASURED NOW** | Already measured this session: rdflib 7.6.0, Python 3.14.3, confirmed live in `v7\.venv`. |
| Exact CVSS→(1–5) impact/likelihood mapping formula | **NOT AVAILABLE** | No script implementing this was located or opened; the manuscript's own UVS table (line 1608–1610) states the *inputs* (CVSS Impact subscore; CVSS Attack Complexity + Attack Vector) but not the formula/rounding rule. A specific scoring script may exist among the unopened `v7\*.py` files; if later located and opened, reclassify. |
| CWE-severity→(1–5) lookup table (for the 30 non-eligible findings) | **NOT AVAILABLE** | Same as above — described in prose (`"basic risk scoring via CWE severity classification"`) but no table located. |
| Actual deduplication/merge script logic (to adjudicate the journal-vs-conference key description conflict) | **CAN BE DOCUMENTED FROM EXISTING ENVIRONMENT** (with more work) | Candidate scripts exist by name (`sut2a_pipeline.py`, `sut2b_populate.py`) but were not opened this session. The primary CSV artifact (`finding_normalization_map.csv`) was used instead and gives strong indirect evidence (see `DEDUPLICATION_SPECIFICATION.md`), but does not fully settle the conflict — opening the actual script would. |
| Ontology consistency check (OWL 2 DL, Pellet/HermiT) | **RESOLVED** | HermiT 1.4.3.456 was run through Protégé 5.6, with no inconsistencies reported. It was used only for OWL 2 DL consistency checking, not for SWRL materialization. See `HERMIT_PROTEGE_CONSISTENCY_EVIDENCE.md`. |
| Runtime/latency figures (e.g., time to process one SUT scan end-to-end, SPARQL query latency) | **NOT AVAILABLE** | No file anywhere in the evidence trail reports a runtime/latency number for the pipeline. The only timing figures that exist are this session's own ontology-**parse** times (8.6–12.4s for global files) and the certification reports' generation timestamps — neither is a pipeline runtime figure and neither should be cited as one. |
| Memory usage figures | **NOT AVAILABLE** | Not recorded anywhere. Do not fabricate. |
| Scanner execution environment (container image, OS, hardware) | **PARTIALLY SUPERSEDED** | OS/hardware is now available — see `HARDWARE_ENVIRONMENT_EVIDENCE.md` (author-supplied Device Info screenshot). Container image, if any, remains not available. |
| Full build-order / "run this to reproduce" script or README | **CAN BE DOCUMENTED FROM EXISTING ENVIRONMENT** (partially) | `v7\README.md` (768 B) and dozens of individually-named phase scripts (si5–si11, sut1–sut2d, riskonto_si12*) exist and were not opened this session; a genuine end-to-end reproduction guide could likely be assembled from them with further effort, but no single consolidated document doing so was found. |
| Ontology consistency of the SUT files' odd `owl:AnnotationProperty` declarations | **CAN BE MEASURED NOW** | This session observed that `WebGoat_SUT_v27.owl` locally re-declares `riskonto:impact`, `riskonto:criticalityValue`, `riskonto:defaultSeverity` as `owl:AnnotationProperty` rather than `owl:DatatypeProperty` (see `ONTOLOGY_FACTS.md` §1) — this is a live, checkable fact, but its *implication* for formal reasoning correctness (whether this causes any OWL 2 DL punning/consistency issue when merged with the global ontology's own `DatatypeProperty` declarations for the same URIs) was not evaluated this session and would require a DL reasoner to check — NOT AVAILABLE for that specific sub-question. |
| WebGoat "2023.4" vs. "v2.5" identity | **NOT AVAILABLE** from current evidence | Would require either an author statement or inspecting the actual WebGoat source/build artifacts scanned (not present in either read-only tree or the `phd backup` tree as far as located). |
| Multiple redundant Python venvs (`v7\.venv`, `v7\.venv-1`, `v7_25\.venv`, `v7_25\.venv-1`) — which is canonical | **NOT AVAILABLE** | No documentation found designating one as authoritative. |

## Summary counts
- CAN BE MEASURED NOW: 3
- CAN BE DOCUMENTED FROM EXISTING ENVIRONMENT: 3
- NOT AVAILABLE: 8
- NOT APPLICABLE: 0

## Sources
Same as `REPRODUCIBILITY_FACTS.md`, plus this session's own gap analysis.
