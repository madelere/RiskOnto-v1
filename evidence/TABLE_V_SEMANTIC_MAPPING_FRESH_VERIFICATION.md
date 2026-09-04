# Table V (Semantic Mapping Chain) — Fresh Forensic Verification

Verifies the reviewer's proposed nine-path semantic mapping list against `RiskOnto_global_v27_
consolidated.owl` and `si7_reasoning_implementation.py`, before any manuscript edit. Confirms the
established project pattern: reviewer-proposed paths from the old draft frequently name phantom
properties/classes not present in the real implementation.

## Path-by-path result

| # | Reviewer claim | Real? | Correction |
|---|---|---|---|
| 1 | VP `mappedToCWE`→ CWEWeakness | Property real (147 triples); class **not** `CWEWeakness` | Target class is `CWE` |
| 2 | VP `exploitableByTechnique`→ AttackTechnique | Real (370 triples), R1 input | No change |
| 3 | CWE `hasTechnique`→ AttackTechnique, "used by R3" | **Fully phantom** — property and class both absent; R3 never touches `AttackTechnique` | R3's real path: `VP→mappedToCWE→CWE→recommendedMitigation→Mitigation`, head `Mitigation→recommendedFor→VP` |
| 4 | AttackTechnique `mitigatedBy`→ Mitigation | Real (3,260 triples), R1 input | No change |
| 5 | Mitigation `implementedBy`→ D3FENDTechnique | Real (2,015 triples), R4 input | No change |
| 6 | Mitigation `affectsSubcat`→ NISTSubcategory, "asserted input" | Property name phantom | Real property: `supportsSubcategory` (810 triples), R1 input — direction/classes as claimed, name wrong |
| 7 | VP `affectsSubcategory`→ NISTSubcategory [R1 output] | Real (5,318 triples) | Correct as stated |
| 8 | NISTSubcategory `belongsToFunction`→ NISTFunction | Property real (128 triples); class **not** `NISTFunction` | Target class is `Function` (6 individuals: Govern/Identify/Protect/Detect/Respond/Recover) |
| 9 | VP `affectsFunction`→ NISTFunction [R2 output] | Property real (605 triples); class **not** `NISTFunction` | Target class is `Function` |

R3's real rule body (`si7_reasoning_implementation.py:562-565`):
```
mappedToCWE(?v,?c) ^ recommendedMitigation(?c,?m) -> recommendedFor(?m,?v)
```
R1's real rule body (`si7_reasoning_implementation.py:526-531`):
```
VulnerabilityProfile(?v) ^ exploitableByTechnique(?v,?t) ^ mitigatedBy(?t,?m) ^
supportsSubcategory(?m,?s) -> affectsSubcategory(?v,?s)
```
R2's real rule body (`si7_reasoning_implementation.py:545-548`):
```
affectsSubcategory(?v,?s) ^ belongsToFunction(?s,?f) -> affectsFunction(?v,?f)
```

## `recommendedMitigation` — verified real and in active use, not removed

The reviewer requested deleting `CWEWeakness→recommendedMitigation→Mitigation` as a phantom path.
**Fresh verification found the opposite is true**: `recommendedMitigation` (CWE→Mitigation, 132
triples) is genuinely declared and is exactly R3's real, currently-used input (line 563,
`recommendedMitigation(?c,?m)`). Per the task's explicit instruction ("if it genuinely exists and
is used elsewhere, do not delete it blindly"), it was **kept**, not removed. What *was* phantom is
the reviewer's proposed replacement path (`hasTechnique`, an `AttackTechnique`-routed R3), which
does not correspond to any real property or rule body.

## Manuscript corrections made

1. **§Semantic Mapping Framework** (`tab:mapping-chain`, "Semantic Mapping Chain" table): renamed
   seven-step → eight-step; added the missing `supportsSubcategory` (Mitigation→NISTSubcategory)
   step, previously absent from the table despite being a genuine R1 input; corrected the target
   class of the `belongsToFunction` step from `NISTFunction` to `Function`; corrected the prose
   attributing the `belongsToFunction` step to "inference by R1 and R2" (it is asserted, not
   inferred — only the `affectsSubcategory` step is rule-inferred, by R1 alone).
2. **Formal Mapping Functions → Formal Mapping Relations**: converted `f_1`–`f_6` single-valued
   function notation to finite binary relation notation (`R_{X,Y}`), since source individuals
   routinely map to multiple targets (e.g. 370 `exploitableByTechnique` triples across 121 VPs).
   Corrected the property mislabeled `affectsSubcategory (R1)` for a Mitigation→NISTSubcategory
   pair — that pair is `supportsSubcategory` (asserted); `affectsSubcategory` is a different
   property (VP→NISTSubcategory, R1's actual output), previously missing from the list entirely.
   Corrected the target class in the final relation from `NISTFunction` to `Function`.
3. **§IV example SWRL rule body** (main text, R1 illustration): `affectsSubcat` → `supportsSubcategory`.
4. **Table VIII (`tab:key-props`, "Core RiskOnto Object Properties")**: added the previously-missing
   `supportsSubcategory` row (R1 input) and `recommendedMitigation` row (R3 input); corrected
   `affectsFunction`'s range from `NISTFunction` to `Function`.
5. **Appendix A, R2's formal rule body**: `CSFFunction(?f)` → `Function(?f)` (the class-membership
   atom named a phantom class not present in the ontology); also corrected the variable-naming
   glossary (`?f = NISTFunction` → `?f = Function`) in two places.
6. **Appendix A, R3**: already correct from an earlier phase (independently re-confirmed this
   pass, no change needed) — matches the verified real rule body exactly.

## Secondary finding, noted but not manuscript-worthy

`belongsToFunction`'s declared `rdfs:domain` is `Category` only, yet 106/128 of its actual triples
have `NISTSubcategory` (not a subclass of `Category`) as subject — an undeclared/incomplete domain
axiom in the ontology itself, of the same category as three other properties the materialization
script's own integrity checks already flag and repair. This is an ontology TBox completeness note,
not a manuscript factual error (the manuscript does not claim a domain restriction that
contradicts this), so no manuscript change was made; recorded here for the author's awareness only.
