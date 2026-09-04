# Global Ontology Consolidation — `RiskOnto_global_v27_consolidated.owl`

Per explicit author request, merges the two previously-independent, single-fix working copies of
the global ontology into one file carrying both corrections. Supersedes the "two separate working
copies for two separate claims" state described in prior evidence docs (`DERIVED_FROM_FINDING_AND_
RULE_COUNT_RESOLUTION.md`, risk-tier normalization docs).

## Inputs and method

- **Base:** `RiskOnto_global_v27_riskfixed.owl` (103,906 triples), not the raw frozen original —
  per the author's explicit suggestion, to avoid re-deriving the risk-tier fix.
- **Applied on top:** the identical `derivedFromFinding` property-declaration fix previously
  applied to the raw `RiskOnto_global_v27.owl` (domain corrected `ReasoningEvidence`→`Entity`,
  range corrected `Evidence`→`CanonicalSecurityFinding`, `ThreatScenario rdfs:subClassOf Entity`
  added, explanatory `rdfs:comment` added) — reproduced verbatim from the original fix script
  logic, not re-derived independently, to guarantee identical semantics to the already-verified
  `RiskOnto_global_v27_provenancefixed.owl`.
- **Script:** `merge_riskfixed_provenancefixed.py` (scratchpad, this session).

## Why no conflict was possible

Pre-merge diff of `RiskOnto_global_v27.owl` vs. `RiskOnto_global_v27_riskfixed.owl` (this session,
independently re-derived, not assumed from a prior phase's summary): 1,028 triples added, 676
removed, entirely accounted for by 352 `criticalityValue` relabels + 352 new `hasRiskLevel`
assertions on `RiskAssessment` individuals, plus blank-node list-serialization churn (SWRL rule
body/head `rdf:List` structures get new blank-node IDs on any rdflib load/save round-trip — cosmetic,
not semantic). None of this touches the `derivedFromFinding` property's domain/range declaration or
the `ThreatScenario` class hierarchy, so the two fixes are provably orthogonal.

## Verification (post-merge, this session)

| Check | Result |
|---|---|
| Total triples | 103,906 → 103,908 (+2, identical delta to the original provenancefixed step) |
| `criticalityValue` triples | 352 (unchanged from riskfixed base — risk-tier fix preserved) |
| `hasRiskLevel` on `RiskAssessment` individuals | 352 (unchanged from riskfixed base — risk-tier fix preserved) |
| `derivedFromFinding` domain | `Entity` (was `ReasoningEvidence`) — provenance fix applied |
| `derivedFromFinding` range | `CanonicalSecurityFinding` (was `Evidence`) — provenance fix applied |
| `ThreatScenario rdfs:subClassOf Entity` | Present |
| `hasRiskLevel` total (352 RiskAssessment + 889 XAI objects) | 1,241 |

## Frozen originals — confirmed unmodified (SHA-256, this session)

| File | SHA-256 (first 16 hex) |
|---|---|
| `RiskOnto_global_v27.owl` | `1f04cb4f7465b7bc` — matches the value recorded in every prior phase |
| `RiskOnto_global_v27_riskfixed.owl` | `a08fc3d9e2535df8` (read-only input, unchanged) |
| `RiskOnto_global_v27_provenancefixed.owl` | `2242d3a214984ac1` (unrelated, unchanged) |

**New file:** `RiskOnto_global_v27_consolidated.owl`, SHA-256
`745f6491ad746368d804db0efe7278a01f622cb3f4771b29f115942dc21fef40`
(corrected: the version recorded in this document's first draft and in this
session's own summary message dropped the trailing `0` in transcription;
re-verified by direct re-hash during the ontology consolidation audit
below), at
`C:\Users\user\Desktop\phd backup\v7\global\RiskOnto_global_v27_consolidated.owl`.

## SUT-side note

`WebGoat_SUT_v27_provenancefixed.owl` is **not** re-derived here and needs no merge: the risk-tier
fix never touched any SUT ontology file (confirmed — no `WebGoat_SUT_v27_riskfixed.owl` variant
exists on disk), so the existing SUT-side provenance-fixed file already reflects the complete,
up-to-date SUT-side state on its own.

## File inventory (current, as of this consolidation)

| Path | Role |
|---|---|
| `...\global\RiskOnto_global_v27.owl` | Frozen original. Never modified. |
| `...\global\RiskOnto_global_v27_riskfixed.owl` | Superseded for citation purposes by the consolidated file; retained on disk unmodified as the historical single-fix artifact. |
| `...\global\RiskOnto_global_v27_provenancefixed.owl` | Same — superseded for citation purposes, retained unmodified. |
| `...\global\RiskOnto_global_v27_consolidated.owl` | **Current authoritative working copy for all global-side manuscript claims** (risk-tier + `derivedFromFinding`). |
| `...\SUT\WebGoat_SUT_v27_reasoned.owl` | Frozen original (SUT). Never modified. |
| `...\SUT\WebGoat_SUT_v27_provenancefixed.owl` | **Current authoritative working copy for SUT-side `derivedFromFinding` claims.** No merge needed. |

## Manuscript changes

Updated all four in-text citations of `RiskOnto_global_v27_riskfixed.owl` /
`RiskOnto_global_v27_provenancefixed.owl` (Table VIII footnote, §Risk Assessment Model ×2, the
Reproducibility table's "Authoritative ontology" row) to point to the consolidated file for the
global side, while keeping the SUT-side citation pointing to
`WebGoat_SUT_v27_provenancefixed.owl` (unchanged, still correct on its own).
