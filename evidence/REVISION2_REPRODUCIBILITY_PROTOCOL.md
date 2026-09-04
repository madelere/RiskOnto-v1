# Revision 2 Reproducibility Protocol — v27-Specific

**UPDATE (post-2026-08-22):** §2's statement that Pellet/HermiT were never run, and §10's listing
of "OWL 2 DL consistency verification (Pellet/HermiT never run)" as an open gap, are **superseded**
by author-supplied evidence (Protégé screenshots + confirmation) that HermiT 1.4.3.456 was run via
Protégé, with no inconsistencies reported. See `HERMIT_PROTEGE_CONSISTENCY_EVIDENCE.md`. This does
not change §2's separate, still-accurate finding that HermiT/Pellet were never used for SWRL
materialization — that remains true and is unaffected.

**Prepared:** 2026-08-22 (Phase 2, author-directed)
**Purpose:** Consolidates and extends the prior phase's `REPRODUCIBILITY_FACTS.md`/`REPRODUCIBILITY_GAPS.md` into a single protocol document, re-grounded specifically in v27. This is a documentation and one-off measurement exercise — no new experiments were run.

---

## 1. Ontology identity

| Item | Value | Evidence |
|---|---|---|
| Global ontology file | `RiskOnto_global_v27.owl` | This session |
| File size | 13,245,432 bytes (12.63 MB) | This session, `os.path.getsize` |
| Last modified | 2026-08-03 13:31 | Filesystem timestamp, this session |
| `owl:versionIRI` | `https://cs.unb.ca/ontologies/riskonto/2.0` | Direct parse, this session — **note: unchanged from earlier internal version IRI despite the `_v27` filename suffix; the filename convention, not an internal version triple, is what actually distinguishes this snapshot from `UPDATED`/`v25`/`v26`.** This is itself a reproducibility gap: a consumer loading the file by its internal `versionIRI` alone cannot distinguish v27 from any earlier snapshot that also declares `.../2.0`. |
| SUT ontology (reasoned) | `WebGoat_SUT_v27_reasoned.owl` | This session |
| SUT file size | 242,109 bytes (0.23 MB) | This session |
| SUT `owl:versionIRI` | `https://cs.unb.ca/ontologies/sut/webgoat/2.7` | Direct parse, this session (confirmed in prior phase too) |
| Format | Global: RDF/XML. SUT: **Turtle**, despite `.owl` extension | Direct file-header read, this session and prior phase |

## 2. Reasoner / execution mechanism (stated honestly, per prior-phase finding, not re-litigated but re-affirmed)

**Custom Python/rdflib forward-chaining script, NOT a certified OWL/SWRL reasoner.** The
released materialization scripts perform plain `rdflib.Graph()` triple-writing (`g.add(...)`),
not certified reasoner invocation. HermiT was separately run through Protégé 5.6 for OWL 2 DL
consistency checking only; it did not produce the SWRL-derived assertions. See
`HERMIT_PROTEGE_CONSISTENCY_EVIDENCE.md`.

## 3. SWRL execution / materialization approach

Per `REASONING_LIFECYCLE.md` (prior phase, not contradicted): SWRL-labeled rules (`swrl:Imp` individuals, 14 of them in v27, confirmed by direct parse this session) are executed **offline, once, during ontology/SUT construction**, and their outputs are persisted as ordinary RDF assertions in the resulting `.owl`/`.ttl` file. Direct evidence specific to this phase: `WebGoat_SUT_v27.owl` (non-reasoned, 2,058 triples, 0 `activatesProfile` assertions) vs. `WebGoat_SUT_v27_reasoned.owl` (2,248 triples, 76 `activatesProfile` assertions) — these are two separately-saved files, confirming the reasoning step is a discrete offline pass, not a live/runtime computation.

## 4. SPARQL / query implementation

`rdflib` (Python), the same library used for parsing — no separate triple store or SPARQL endpoint identified anywhere in the accessible evidence. Query-time access, per `RISKONTO_END_TO_END_FLOW.md` Stage 11, is described as read-only SPARQL over the already-reasoned static graph.

## 5. Software / library versions

| Item | Value | Evidence |
|---|---|---|
| Python | 3.14.3 (`tags/v3.14.3:323c59a, Feb 3 2026`) | `sys.version`, this session, `v7\.venv\Scripts\python.exe` |
| rdflib | 7.6.0 | `rdflib.__version__`, this session and prior phase |
| Ontology editor (construction-time, not reasoning) | Protégé 5.x | `RiskOnto_WebGoat_Conference_FINAL.tex` line 699 |

## 6. Scripts (named, where locatable — content not fully audited beyond what's cited elsewhere in this phase)

| Script | Role (inferred from name/embedded comments) | Opened this session? |
|---|---|---|
| `sut2b_populate.py` | SUT-2B ontology population; contains the `SEV_RISK` risk-scoring placeholder table (see `V27_RISK_SCORING_METHOD.md`) | **Yes — read directly** |
| `sut2a_pipeline.py`, `sut2a_forensic_audit.py`, `sut2a_probe.py`, `sut2a_reaudit.py`, `sut2a1_reasoning_audit.py` | SUT-2A phase (scanner evidence processing, preceding population) | No — name/directory-listing only |
| `sut1_schema_extract.py` | SUT-1 schema extraction | No |
| `riskonto_si12.py`, `riskonto_si12_1.py`, `riskonto_si12_forensic.py` | SI-12 profile-activation rule (the mechanism behind `activatesProfile`) | No |
| `riskonto_sut2d.py`, `riskonto_sut2d_1.py` | Referenced by `WebGoat_SUT_v27_reasoned.owl`'s own comment ("SUT-2D.1 semantic binding cleanup applied") | No |
| `extract_reasoning.py` | Generated most prior-phase journal-side evidence reports | No |
| A "SUT-2C" scoring-override script | **Referenced by name in `sut2b_populate.py`'s own comments and by the "Override in SUT-2C scoring phase" text embedded in the live ontology — but no file matching this description was found anywhere in the accessible `v7\` tree.** | N/A — appears not to exist |

**Reproducibility implication:** the risk-scoring "PLACEHOLDER" values are not a documentation gap — they are the actual, final, shipped values in the current authoritative ontology (v27), because the phase intended to replace them (SUT-2C) does not appear to have been implemented. Any reproduction attempt starting from the same raw scanner data and the same available scripts would arrive at the same placeholder scores, not at genuine CVSS-derived ones.

## 7. Execution procedure (5-phase pipeline, from `REASONING_LIFECYCLE.md`, re-affirmed)

1. Global ontology construction (offline, one-time) → `RiskOnto_global_v27.owl`
2. SUT evidence acquisition (scanners → raw JSON) → `v7\SUT\Scanner_results\` (not enumerated this session)
3. Normalization/deduplication (scripted) → `v7\SUT\normalized\` CSVs
4. SUT ontology population (`sut2b_populate.py` and related) → `WebGoat_SUT_v27.owl` (asserted)
5. SI-12 activation + reasoning materialization (offline) → `WebGoat_SUT_v27_reasoned.owl`

## 8. Input files / output artifacts (v27-specific inventory)

| Type | File | Size |
|---|---|---|
| Input (global) | `RiskOnto_global_v27.owl` | 13,245,432 B |
| Input/output (SUT, asserted) | `WebGoat_SUT_v27.owl` | 123,573 B |
| Output (SUT, reasoned) | `WebGoat_SUT_v27_reasoned.owl` | 242,109 B |
| Intermediate | `v7\SUT\normalized\mappings\finding_normalization_map.csv` | 273 rows |
| Intermediate | `v7\SUT\normalized\classifications\finding_classification.csv` | 44 rows |

## 9. Reproducibility measurement (trivial one-off, NOT a performance benchmark)

Measured this session, this environment, using `time.perf_counter()` + `tracemalloc`:

| File | Triples | Wall time | Peak traced Python memory | File size |
|---|---|---|---|---|
| `RiskOnto_global_v27.owl` | 103,554 | **15.886 s** | **96.7 MB** | 12.63 MB |
| `WebGoat_SUT_v27_reasoned.owl` | 2,248 | **0.278 s** | **3.7 MB** | 0.23 MB |
| `WebGoat_SUT_v27.owl` (asserted) | 2,058 | **0.157 s** | **3.0 MB** | 0.12 MB |

**Environment (this measurement's context):**
- Platform: `Windows-11-10.0.26200-SP0`
- Python: `3.14.3 (tags/v3.14.3:323c59a, Feb 3 2026, 16:04:56) [MSC v.1944 64 bit (AMD64)]`
- Processor: `Intel64 Family 6 Model 170 Stepping 4, GenuineIntel`

**Explicit caveat, per instruction:** this is a plain `rdflib.Graph().parse()` call — parsing only, no reasoning, no query execution, no repeated trials for statistical stability. It measures this session's own re-verification activity, executed in **Claude Code's execution environment**, not necessarily the original authors' hardware/OS/Python build. The manuscript should not present this as an authoritative performance benchmark, and should not claim it characterizes the original authors' own execution environment — but it may honestly be cited as evidence that the shipped v27 ontology **is** parseable end-to-end by a plain rdflib call, with an approximate order-of-magnitude wall-time and memory footprint, as one (not the only) reproducibility data point. A ~16-second global-file parse against ~97 MB of peak traced memory is not a claim about production-system latency; it is a claim about ontology-file loadability.

## 10. Gaps not closed this session (carried from prior phase's `REPRODUCIBILITY_GAPS.md`, unchanged)

Scanner tool version numbers, the exact CVSS→(1–5) mapping formula for the global ontology's 352 RiskAssessments (only the SUT's placeholder mechanism was found, §6), and the canonical build-order script remain open gaps. OWL 2 DL consistency verification is no longer an open gap: HermiT 1.4.3.456 was run through Protégé 5.6 with no inconsistencies reported. HermiT/Pellet were not used for SWRL materialization.

## Sources
- This session's direct environment inspection and timing/memory measurement (`v7\.venv`)
- `sut2b_populate.py`, `WebGoat_SUT_v27_reasoned.owl`, `WebGoat_SUT_v27.owl`, `RiskOnto_global_v27.owl`
- Prior-phase `05_AUTHORITATIVE_EVIDENCE/REPRODUCIBILITY_FACTS.md`, `REPRODUCIBILITY_GAPS.md`, `REASONING_LIFECYCLE.md`
