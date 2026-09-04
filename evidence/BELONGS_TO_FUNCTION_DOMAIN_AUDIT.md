# `belongsToFunction` Domain Declaration — Forensic Audit

**Scope: audit only.** No file was modified as part of this task — not the ontology, not the
manuscript, not Table V, not Appendix A. All findings below are read-only observations against
`RiskOnto_global_v27_consolidated.owl` (SHA-256 unchanged, re-verified: `745f6491ad746368d804db0e
fe7278a01f622cb3f4771b29f115942dc21fef40`) and `si7_reasoning_implementation.py`.

## 1. Exact current declaration

```
belongsToFunction
  rdf:type    owl:ObjectProperty
  rdfs:domain riskonto:Category
  rdfs:range  riskonto:Function
  rdfs:label  "belongsToFunction"
  rdfs:comment  (none declared)
```

## 2. Exact assertion counts, by subject `rdf:type`

| Subject type | Count | % of 128 |
|---|---:|---:|
| `NISTSubcategory` | 106 | 82.8% |
| `Category` | 22 | 17.2% |
| **Total `belongsToFunction` triples** | **128** | 100% |

Every triple has exactly one subject; 128 distinct subjects, no duplicates.

## 3. Class hierarchy — `NISTSubcategory` vs. `Category`

```
NISTSubcategory   rdf:type owl:Class ;  rdfs:subClassOf riskonto:Entity .
Category          rdf:type owl:Class ;  rdfs:subClassOf riskonto:Entity .
```

**`NISTSubcategory` and `Category` are siblings** — both direct subclasses of `Entity`, with no
`subClassOf` relationship between them in either direction, and **no `owl:disjointWith` axiom and
no `AllDisjointClasses` construct anywhere in the ontology** involving either class.

## 4. What `Category` actually represents (inspected, not inferred from the name)

`Category` has 22 individuals with labels: *Data Security*, *Organizational Context*, *Incident
Response Reporting and Communication*, *Cybersecurity Supply Chain Risk Management*, *Technology
Infrastructure Resilience*, etc. — **these are exactly the 22 NIST CSF 2.0 Categories** (the
middle tier of NIST's three-tier hierarchy: 6 Functions → 22 Categories → 106 Subcategories,
matching this manuscript's own Related Work description of CSF 2.0's structure). `NISTSubcategory`
similarly has exactly 106 individuals (e.g. `RC.RP-06`, `PR.AA-02`) — the 106 CSF Subcategories.

**Conclusion: `Category` and `NISTSubcategory` are parallel, sibling tiers of the same external
NIST CSF hierarchy, not a superclass/subclass pair.** A Subcategory is not "a kind of" Category in
the OWL is-a sense; it is nested one level below Category in NIST's own external taxonomy — a
part-of/narrower-than relationship, not a specialization relationship.

## 5. Analogous domain/range mismatches elsewhere — confirmed, and already actively repaired

`si7_reasoning_implementation.py` lines 363–412 contain a dedicated "SCHEMA REPAIRS (Pre-SI-7
corrections)" pass that fixes exactly this class of bug for three *other* properties, using the
identical diagnostic method (check which class the actual triples' subjects have; correct the
declaration to match):

- **Repair 1** (line 373–382): `violatesSubcategory` domain `VP`→`CWE` — "99 existing triples all
  have CWE subjects. Declaration was wrong."
- **Repair 2** (line 384–393): `recommendedMitigation` domain `VP`→`CWE` — "132 existing triples
  all have CWE subjects. SWRL Rule 3 uses CWE."
- **Repair 3** (line 395–410): `recommendedD3FEND` domain/range flipped `VP→D3FEND`→`D3FEND→VP` —
  "SWRL Rule 4 creates (d3, recommendedD3FEND, vp) triples."

**`belongsToFunction` is not in this repair list.** Given the script's author was clearly aware of
and systematically fixing this exact bug pattern elsewhere, its absence here is best read as an
**omission from an otherwise-systematic pass**, not a considered decision to leave it as-is.

## 6. R2 rule body — actual intended subject class

`si7_reasoning_implementation.py:545-548`:
```
affectsSubcategory(?v,?s) ^ belongsToFunction(?s,?f) -> affectsFunction(?v,?f)
```
`?s` is bound by `affectsSubcategory(?v,?s)`. Directly verified: **100% of `affectsSubcategory`'s
5,318 objects are typed `NISTSubcategory`** (zero are typed `Category`). R2's `belongsToFunction`
atom therefore **always** fires with `?s` bound to a `NISTSubcategory` individual in practice —
confirming `NISTSubcategory`, not `Category`, is the class R2 actually depends on.

## 7. Impact assessment

| Dimension | Affected? | Evidence |
|---|---|---|
| Ontology consistency | **No** | `Category`/`NISTSubcategory` are not declared disjoint; RDFS domain entailment would silently add an inferred `rdf:type Category` to the 106 `NISTSubcategory` individuals, not a contradiction. Consistent with HermiT reporting no inconsistencies (`HERMIT_PROTEGE_CONSISTENCY_EVIDENCE.md`) — this declaration gives HermiT nothing to contradict. |
| Inferred types (if a DL reasoner ran domain entailment) | **Latent, currently inert** | Would entail 106 individuals as also `Category`-typed. Verified: **0 of the 106** currently carry an *asserted* `rdf:type Category` — the entailment has evidently never been materialized/applied anywhere in this project. |
| SWRL rule semantics (R1, R2) | **No** | Both rules test class membership via *asserted* types in their SWRL body atoms (`NISTSubcategory(?s)`, `VulnerabilityProfile(?v)`, etc.), read directly off the ABox by the Python/rdflib materialization — never via domain-declared entailment. R2 fires correctly regardless of this domain declaration. |
| Materialized counts (19,671, 605 `affectsFunction`, etc.) | **No** | All materialization in this project is plain `rdflib` graph traversal (`g.objects(...)`, `g.subjects(...)`), which never computes RDFS/OWL domain entailment. This declaration is invisible to every script in the pipeline. |
| Manuscript claims | **No** | No manuscript text asserts or depends on `belongsToFunction`'s formal domain being `Category` specifically, nor claims the 106 `NISTSubcategory` individuals are `Category`-typed. |

## 8. Would `NISTSubcategory rdfs:subClassOf Category` be justified?

**No — not added, and evidence argues against it.** Per §3–4 above, `Category` and `NISTSubcategory`
represent two distinct, sibling tiers of NIST's external hierarchy. Asserting a subclass
relationship would misrepresent that structure (a Subcategory is not a type of Category in any
OWL is-a sense) purely to make an incidental domain declaration type-check. This was correctly
identified as the wrong fix and was not applied, per instruction.

## 9. Four distinct dimensions, explicitly separated

- **Ontology consistency**: intact. No contradiction exists or would be introduced by this
  declaration under the ontology's current (non-disjoint) class structure.
- **Ontology modeling correctness**: the `rdfs:domain Category` declaration is *incomplete/incorrect*
  relative to actual usage — 83% of the property's real-world subjects are `NISTSubcategory`, not
  `Category`. This is a genuine modeling imprecision.
- **Rule execution correctness**: unaffected. R1 and R2 both execute correctly today and have
  always executed correctly, because rule execution reads asserted types directly, never through
  domain-declaration entailment.
- **Domain/range completeness**: incomplete, by the same standard the script's own three prior
  repairs already apply to sibling properties.

A domain-declaration mismatch is a **modeling/documentation-completeness issue**, not a
consistency defect — these are confirmed as separate axes here, not conflated.

## 10. Recommendation

**DOCUMENT ONLY** for this manuscript-freeze cycle. Justification:

- The issue is real and evidence-backed (§1–6), matches a bug class the ontology's own scripts
  already recognize and repair for three sibling properties (§5), and a future maintenance pass
  could reasonably add a fourth repair entry alongside Repairs 1–3 — most naturally
  `belongsToFunction` domain `Category`→`NISTSubcategory` (matching 83% of actual usage and R2's
  actual dependency, §6) or, if both subject types are intended to remain valid, domain→`Entity`
  (the nearest common ancestor of both siblings) rather than a union-class construction.
- It is currently **inert**: zero measurable effect on consistency, materialized counts, rule
  behavior, or any manuscript claim (§7). There is no pressing correctness reason to touch the
  live ontology mid-freeze.
- **FIX NOW** is not recommended: it would be a live ontology-content edit requiring the same
  author-authorization and full re-verification discipline this project has applied to every
  other ontology change this revision, for a change with no current observable benefit.
- **LEAVE UNCHANGED (silently)** is not recommended either: the finding is real, reproducible, and
  matches an established repair pattern the author already uses — it should not be discarded
  without record.
