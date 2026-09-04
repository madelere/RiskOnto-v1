# HermiT / Protégé OWL 2 DL Consistency-Checking Evidence

Resolves the open item flagged in `FINAL_REVIEWER_REQUIREMENTS_AUDIT.md` ("Issue 2, HermiT/Protégé
DL-consistency sub-claim") and in the prior phase's closing message. This does **not** change or
contradict the separately-established, still-accurate fact that HermiT/Pellet were never used to
materialize the 19,671 SWRL-derived assertions or the 847 XAI justification individuals — that
remains a Python/`rdflib` forward-chaining pipeline, unaffected by this evidence.

## What changed

Two independent investigations this session (this project's prior-phase `REVISION2_REPRODUCIBILITY_
PROTOCOL.md`/`REPRODUCIBILITY_GAPS.md`, and a fresh Explore-agent search) had both concluded that no
valid evidence existed for a HermiT consistency run — the only scripts/reports that would show one
lived exclusively in a directory the project's own established convention (`SCANNER_PROVENANCE_AND_
VERSION_AUDIT.md`) explicitly excludes as "a superseded/invalid prior attempt, not part of the
v27-consistent evidence chain." This was reported to the author as a STOP-GATE rather than resolved
unilaterally.

The author has since supplied direct evidence closing this gap.

## Evidence supplied by the author

1. **Protégé session screenshots** showing:
   - The Protégé Reasoner menu with **HermiT 1.4.3.456** selected as the active reasoner.
   - **"Reasoner active"** displayed in the Protégé interface.
   - **"Show Inferences"** enabled.
   - The RiskOnto ontology loaded in the same session.
2. **Direct author confirmation** of the experimental workflow: HermiT was started through Protégé
   on the RiskOnto ontology, the ontology was successfully reasoned over, no inconsistency was
   reported, and the reasoner remained active after the operation completed.

The screenshots are evidence of (1) Protégé usage, (2) HermiT 1.4.3.456 selection, (3) an active
reasoner state, and (4) the OWL reasoning/consistency-checking workflow having been invoked on the
correct ontology. They are not evidence, and are not claimed as evidence, of the numeric assertion
counts (19,671 / 847) — those remain independently verified via the Python/`rdflib` pipeline,
documented separately (`FINAL_PROPERTY_AND_SWRL_CONSISTENCY_AUDIT.md`,
`FINAL_ONTOLOGY_COUNT_REGENERATION.md`).

## Resulting fact, as now established

> HermiT 1.4.3.456 was selected and run through Protégé on the RiskOnto ontology; no OWL 2 DL
> inconsistency was reported. This is a distinct execution from, and does not substitute for, the
> Python/`rdflib` SWRL materialization that produced the 19,671 reusable semantic assertions
> (R1–R4, E1–E4) and the 847 typed XAI justification/explanation individuals (X1–X5). HermiT did
> not fire, execute, or materialize any of the 14 SWRL rules.

## Distinction preserved (per explicit author instruction)

| Mechanism | Tool | Purpose | Output |
|---|---|---|---|
| OWL 2 DL consistency checking | HermiT 1.4.3.456, via Protégé | Verify no unsatisfiable classes / logical contradictions in the asserted+materialized ABox | Boolean result: no inconsistencies reported |
| SWRL-derived assertion materialization | Python/`rdflib` forward-chaining (`si7_reasoning_implementation.py`, `si9_implementation.py`, `si11_implementation.py`) | Generate the reusable inferred triples and XAI individuals | 19,671 assertions (R1–R4/E1–E4) + 847 XAI individuals (X1–X5) |

## Manuscript locations updated

`RiskOnto_Revision2.tex`: §Reasoning Execution Model (main paragraph and its preceding paragraph),
§Quality Evaluation intro, §Ontological Soundness (both occurrences), the Structural-validation
enumerate bullet, the `tab:v7-stats` table footnote, and the Reproducibility table (new dedicated
"OWL 2 DL consistency check" row, separated from the "SWRL materialization mechanism" row it was
previously conflated with under the single label "Reasoning mechanism"). Every occurrence of
"HermiT/Pellet re-certification not independently performed"/"was not independently re-run" that
referred to the *consistency-checking* claim specifically was corrected; occurrences referring to
the separate *SWRL-execution* claim (i.e., "no certified reasoner executed the SWRL rules") were
left unchanged, since that claim remains independently true and is not contradicted by this
evidence.

## Historical audit records — not deleted, explicitly distinguished

`REPRODUCIBILITY_GAPS.md` and `REVISION2_REPRODUCIBILITY_PROTOCOL.md` (both dated 2026-08-22) state
that OWL 2 DL consistency verification "had not been" performed and that Pellet/HermiT were "never
run," based on the evidence accessible at the time those documents were written. Those statements
are preserved as accurate **historical** records of the evidence state at that time — they are not
retroactively rewritten. This document supersedes them **going forward**: the current, final
evidence state is that HermiT consistency-checking has now been performed and documented, per the
author-supplied screenshots and confirmation above. `FINAL_REVIEWER_REQUIREMENTS_AUDIT.md` is
updated to point future readers to this file rather than to the now-superseded "not available"
conclusion in the two 2026-08-22 documents.
