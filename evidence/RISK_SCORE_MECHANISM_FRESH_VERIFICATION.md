# Risk Score Generation Mechanism — Fresh Re-Verification Against a Reviewer-Proposed CVSS Conversion

A reviewer proposed that the manuscript document a precise CVSS-attribute-to-1–5 conversion table
with analyst-override support. Before writing any such table, the actual mechanism was
re-investigated fresh this phase via an independent Explore-agent code inspection (not inherited
from prior-phase summaries).

## Findings

**Global 352 `RiskAssessment` individuals:** no populating script survives anywhere in the
accessible codebase (exhaustive `grep` for `riskScoreValue`/`RiskAssessment_` across the full
`v7` tree finds only the WebGoat-specific `sut2b_populate.py`). `riskScoreValue = impact ×
likelihood` holds for all 352/352 (independently confirmed, `RISK_MODEL_BEFORE_AUDIT.md`), but the
values are bare asserted ABox literals with **no `description`/provenance annotation at all** —
unlike the WebGoat SUT individuals, which do carry an explicit placeholder disclosure.

**WebGoat SUT:** `sut2b_populate.py:444,452-460` — a plain Python dict lookup, not multiplication
of independently-sourced CVSS attributes:
```python
SEV_RISK = {
    "Critical":      (5, 5, 25),
    "High":          (4, 4, 16),
    "Medium":        (3, 3, 9),
    "Low":           (2, 2, 4),
    "Informational": (1, 1, 1),
}
impact, likelihood, score = SEV_RISK.get(dom_sev, (3, 3, 9))
```
matching exactly the manuscript's existing "High → (4, 4, 16)" example.

**No genuine CVSS-attribute conversion exists anywhere in the codebase, for either context.** The
only "CVSS" occurrences in the consolidated ontology are illustrative prose inside an unrelated
mitigation-description annotation ("Use vulnerability scoring frameworks like CVSS... A critical
vulnerability with a CVSS score of 9.8...") — narrative text, not executable logic. No script
parses a CVSS vector string or subscore anywhere.

**No SWRL rule performs the multiplication.** `si7_reasoning_implementation.py` declares
`hasRiskLevel`/`hasExposureLevel` as "Reserved for SI-8 risk scoring" (never-implemented future
work) and contains no `swrlb` arithmetic builtin. Independently, all 14 formally-declared
`swrl:Imp` rule bodies were inspected and none references `criticalityValue`, `hasRiskLevel`,
`RiskLevel`, or `riskScoreValue` (`RISK_MODEL_BEFORE_AUDIT.md` §5). `riskScoreValue` is always a
pre-computed, stored ABox fact.

**No analyst-override mechanism exists.** `sut2c` (referenced by the ontology's own "Override in
SUT-2C scoring phase" wording) does not exist anywhere in the tree — confirmed by exhaustive
search. This is aspirational wording embedded in the data, correctly presented in the manuscript
as a quote from the ontology's own annotation, not as a claim that the override phase was built.

**No validation logic exists.** `hasRiskLevel` is a plain `ObjectProperty` assertion added by a
one-time table lookup on the already-stored `riskScoreValue` (the 2026-08-22 risk-tier fix); there
is no OWL cardinality/range restriction and no SWRL rule that validates the score against its
`RiskLevel` interval.

## Supplementary trace: is any global default even "CVSS-informed" without a coded conversion?

Directly queried, this follow-up pass: `rdfs:comment` on the `RiskAssessment` class and on the
`impact`/`likelihood`/`riskScoreValue`/`criticalityValue` properties themselves (not just
per-individual annotations). Result: `impact` = "Impact value 1-5 (integer)", `likelihood` =
"Likelihood value 1-5 (integer)", `riskScoreValue` = "Computed risk score (1-25 integer)",
`criticalityValue` has no comment at all — **no mention of CVSS anywhere in any class/property-level
annotation**, and (confirmed again by sampling individual `RiskAssessment` instances directly, e.g.
`ForcedBrowsingAgainstIamsystem_RiskAssessment`) no per-individual `description`/provenance
annotation exists either. Combined with the prior finding that no populating script survives in the
codebase: **there is no evidence, anywhere accessible, that the 352 global defaults are even loosely
"CVSS-informed."** Their origin is genuinely undocumented — not "informed by CVSS without a coded
conversion," simply unknown. The manuscript's existing wording ("no populating script... located,"
"no genuine CVSS-attribute-to-1--5 conversion exists... for either context") is accurate and does not
overstate this into a false "CVSS-informed" claim; it also does not need to claim the opposite
("arbitrary") since that is equally unverifiable. "Undocumented origin, not a coded CVSS conversion"
is the precise, defensible framing already in use.

## Verdict

**Outcome 2 applies** (per the task's own decision framework): the reviewer's proposed CVSS
conversion table does not describe the implementation and was not fabricated. The manuscript's
§Risk Assessment Model was corrected to state explicitly, with this evidence: (1) an ordinal
risk-prioritization model informed by, not mandated by, NIST SP 800-30/ISO 31000; (2) no CVSS
conversion exists for either the global defaults or the WebGoat SUT; (3) none of the 13 global
SWRL rules performs the multiplication; (4) `hasRiskLevel` is asserted/associated, never
independently validated by the ontology. The pre-existing text already correctly avoided
fabricating a CVSS table or claiming validation — this phase made the underlying mechanism
explicit rather than leaving it implicit.
