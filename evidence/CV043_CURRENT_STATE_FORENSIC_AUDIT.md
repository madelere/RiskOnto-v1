# CV-043 Current-State Forensic Audit

**Audit only — no ontology or manuscript file was modified as part of this task.**

## 1. Authoritative CV-043 state

| Item | Value |
|---|---|
| Finding URI | `https://cs.unb.ca/ontologies/sut/webgoat#Finding_Code_Injection` |
| `canonicalFindingId` | `CV-043` |
| `mappedToCWE` | `CWE-94` |
| `classification` | `DependencyWeakness` |
| `fromScanner` | `Snyk_SCA` |
| `sourceCount` | 3 |
| `activatesProfile` count | **9**, identical in the frozen original and the working copy |

Checked in both:
- `WebGoat_SUT_v27_reasoned.owl` (frozen; SHA-256 `23035d938ed02a97e3462d01cf5953e1c25d14c26c4cf8bb93e3ba5ae63dd650`, matches the value recorded in every prior phase — confirms this is genuinely the untouched authoritative artifact, not a stale copy)
- `WebGoat_SUT_v27_provenancefixed.owl` (working copy — the `derivedFromFinding` fix does not touch `activatesProfile`, and indeed the set is identical)

No later WebGoat SUT ontology snapshot exists (`WebGoat_SUT_v27_reasoned.owl` / `_provenancefixed.owl` are the only two SUT artifacts referenced anywhere in the current evidence trail). No script was found that removes or replaces any of the 9 `activatesProfile` triples after SI-12 materialization. **All 9 assertions are explicit, materialized ABox triples** (not runtime-inferred) — they were written once by `riskonto_si12.py`'s offline materialization pass and persisted into the reasoned `.owl` file.

## 2. Origin of the nine activations

Traced directly to `riskonto_si12.py` (SI-12 rule materialization), lines 300–314:

```python
# Rule: CSF(?f) ∧ VP(?vp) ∧ mappedToCWE(?f,?cwe) ∧ mappedToCWE(?vp,?cwe)
finding_cwes = set(g_work.objects(finding, R.mappedToCWE))
...
for vp in g_work.subjects(R.mappedToCWE, cwe):
    ...
for vp in vps_activated:
    ...  # activatesProfile(finding, vp) asserted for every match
```

The rule is a **pure CWE join with no further filter**: for a finding's CWE, it activates *every*
`VulnerabilityProfile` in the global ontology that also declares that same `mappedToCWE`, with no
category, asset-type, platform or technology-stack constraint. Directly confirmed by querying the
global ontology for `mappedToCWE = CWE-94`: **exactly 9 VulnerabilityProfile individuals**, an
exact 1:1 match to CV-043's 9 `activatesProfile` triples.

| Profile | Category (asserted `rdf:type`) | Why activated | Contextually applicable to WebGoat? |
|---|---|---|---|
| `VulnProfile_Code_Injection` | `InjectionVulnerability` | `mappedToCWE CWE-94` | **Yes** — generic code-injection is a real risk for a Java/Spring application |
| `VulnProfile_Template_Injection` | `InjectionVulnerability` | `mappedToCWE CWE-94` | **Borderline.** Same broad category as Code_Injection (not AI-specific), but this specific finding is a `DependencyWeakness` (a vulnerable library, per Snyk SCA), not a template-rendering issue — template injection is a plausible vulnerability *class* for a web app in general, but not a strong match for *this specific* dependency finding |
| `VulnProfile_Agent_Injection` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No — WebGoat has no AI-agent component |
| `VulnProfile_Agent_Manipulation` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No |
| `VulnProfile_Indirect_Prompt_Injection` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No |
| `VulnProfile_LLM_Prompt_Injection` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No |
| `VulnProfile_Prompt_Injection` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No |
| `VulnProfile_RAG_Manipulation` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No |
| `VulnProfile_Tool_Injection` | `AILLMVulnerability` | `mappedToCWE CWE-94` | No |

**Precise count, corrected from the manuscript's implicit "1 correct + 8 mismatched" framing:**
1 clearly appropriate (`Code_Injection`), 1 same-category-but-questionable-for-this-specific-finding
(`Template_Injection`), 7 clearly domain-mismatched (AI/LLM/agent-specific). The manuscript's "8
further, domain-mismatched" figure is defensible as-is (`Template_Injection` is not a strong match
for a *dependency* finding either, so lumping it with the "not clearly correct" set is reasonable),
but the finer distinction — 7 are unambiguously wrong on category grounds, 1 (`Template_Injection`)
is same-category but still a poor fit for *this* finding's actual nature — was not previously
documented and is recorded here for completeness. This is a nuance the author may wish to consider
for precision, not a claim that the manuscript's current "8" figure is factually wrong.

## 3. Stale description field

`RiskOnto_global_v27...` — no, this is a **SUT-side** field: `riskonto:description` on
`Finding_Code_Injection`, reading:

> *"Code Injection (CWE-94) — DependencyWeakness. Evidence from: Snyk_SCA. Raw finding count: 3.
> VP: VulnProfile_Agent_Injection"*

- **Generating script/function:** `sut2b_populate.py`, Phase 4 ("CanonicalSecurityFinding
  Individuals"), lines 294–327. The `vp` value embedded in the string comes from
  `c.get("mapped_vulnerability_profile", "NONE")` — a single value read from the finding's
  catalog row, not from `activatesProfile`.
- **Ultimate source of that single value:** `sut2a_reaudit.py` line 107,
  `cwe_to_vp.setdefault(f"CWE-{num}", vp_l)` — a `dict.setdefault()` call during global-ontology
  scanning that keeps only the *first* `VulnerabilityProfile` encountered for each CWE and silently
  discards the rest. Which VP is "first" depends on RDF triple iteration order in `rdflib`, which is
  not semantically meaningful (not alphabetical, not a relevance ranking) — it is an artifact of
  internal graph storage order, not a deliberate "best match" selection.
- **Timing:** this description string is generated in Phase 4 of `sut2b_populate.py` (SUT
  population), which runs **before** `riskonto_si12.py`'s SI-12 activation pass (a separate,
  later phase). The description field therefore reflects the *early*, single-value CWE→VP lookup
  used for catalog bookkeeping, not the *final*, exhaustive 9-profile `activatesProfile` result
  computed afterward by a completely different script.
- **Intent:** the field's own f-string comment ("VP: {vp}") suggests it was meant to identify one
  representative/primary VP for human-readable display purposes at catalog-generation time, not to
  enumerate all VPs and not to represent a final, authoritative binding.
- **Is the `Agent_Injection` reference stale?** **Yes** — relative to the final `activatesProfile`
  layer, this string names one specific profile (arbitrarily, by iteration order) out of the 9 that
  are actually asserted, and that one happens not to be the contextually strongest match
  (`Code_Injection`).
- **Does it affect reasoning, SPARQL, or downstream artifacts?** **No.** `description` is a plain
  `xsd:string` literal, never parsed or queried by any script in the pipeline (confirmed: no script
  reads this field back). It carries zero semantic weight for materialization, activation, or any
  manuscript-reported count. This is a cosmetic/display inconsistency only.

## 4. Manuscript CV-043 claim — current wording, verified against source

Current text (`RiskOnto_Revision2.tex`, §Assertion Counts and Mapping Quality):

> *"The CV-043 case is the most actionable finding: a generic Java/Spring dependency finding
> (CWE-94/20) correctly matches `VulnProfile_Code_Injection` via T1059, but the same CWE-94-based
> activation rule also fires 8 further, domain-mismatched LLM/AI-agent-specific VP archetypes...
> This is reported as a genuine, observed limitation of the current SI-12 activation granularity...
> not a positive capability."*

Classification against the audit's options: **B and E** (CV-043 exposed over-generalization; CV-043
demonstrates CWE-only over-generalization) and **D** (activates multiple profiles, stated as 9 total
implicitly via "1 correct + 8 mismatched"). **Not A** (does not claim a currently-incorrect single
mapping) and **not C** (does not claim a correction occurred). This matches the current, verified
ontology state exactly — **no manuscript change is required.**

## 5–7. Three-concept distinction, scientific interpretation

Already correctly preserved in the current manuscript:
- **CWE association** (CV-043 → CWE-94): asserted fact, unambiguous.
- **VP activation coverage** (9 profiles activated, part of the 43/43 workflow-coverage headline
  result): a structural fact, not a relevance judgment.
- **Semantic appropriateness** (only `Code_Injection`, and arguably not even
  `Template_Injection`, is a genuine contextual fit): explicitly NOT claimed to be established by
  the 43/43 figure — the manuscript already states this is "a genuine, observed limitation...
  not a positive capability" and elsewhere states 43/43 is "structural workflow coverage, not a
  demonstration of semantic correctness for every inferred association (the CV-043
  over-generalization case... remains the concrete counter-example)."

CV-043 legitimately motivates context-aware activation, richer evidence-aware matching, and future
expert/precision-recall evaluation — exactly as currently framed. It is not used, and should not be
used, to claim a numeric precision figure for the whole ontology; the manuscript makes no such claim.

## 8. Recommendation

**LEAVE ONTOLOGY UNCHANGED / DOCUMENT LIMITATION.**

Justification:
- The 9-profile `activatesProfile` set is the correct, intentional (if imprecise) output of the
  documented SI-12 mechanism — a pure CWE join, exactly as the manuscript already describes it.
  There is nothing to "repair" here without changing the activation algorithm itself, which is a
  design decision (context-aware matching) already correctly deferred to future work.
- The stale `description` string (§3) is a genuine, minor artifact inconsistency, but it (a) has
  zero effect on any reasoning, query, or manuscript-reported count, and (b) is not referenced by
  the manuscript at all — no manuscript claim depends on or is contradicted by it. Repairing it
  would be a reasonable, low-risk future housekeeping fix (regenerate the string from the full
  `activatesProfile` set, or drop the single-VP field entirely), but is optional and out of scope
  for a manuscript-freeze cycle; it does not currently mislead any reader of the paper, since the
  manuscript does not quote or rely on this internal field.
- No manuscript change is required: the current text already accurately reflects 9 total
  activations (1 correct, 8 questionable-to-wrong), already explicitly declines to call this a
  correction, and already uses it correctly as a limitation/counterexample rather than as a
  disproof of the 43/43 workflow-coverage result.

## Stop-gate answers

1. Does CV-043 currently activate 9 profiles? **Yes.**
2. Is `Code_Injection` among them? **Yes.**
3. Is `Agent_Injection` still among them? **Yes — not removed.**
4. Are the other 7 AI/LLM/agent profiles still present? **Yes, all 7, plus `Template_Injection`
   (same broad category as `Code_Injection`, still present) — 9 total, unchanged.**
5. Is 43/43 still correctly described as activation/workflow coverage, not semantic correctness?
   **Yes**, throughout the manuscript, with CV-043 explicitly retained as the counter-example.
6. Is the "corrected to Code_Injection" narrative unsupported? **Yes — unsupported.** No script,
   ontology snapshot, or certification report anywhere in the accessible evidence shows the 8/9
   mismatched profiles ever being removed.
7. Is the description annotation inconsistent with the relationship layer? **Yes** — it names one
   VP (`Agent_Injection`) while `activatesProfile` asserts nine.
8. Is that inconsistency stale metadata or semantically meaningful? **Stale metadata** — an
   artifact of `dict.setdefault()` iteration order in an earlier, single-value catalog field,
   generated before and independently of the later, exhaustive SI-12 activation pass. Not
   semantically meaningful (does not indicate a deliberate "best match" judgment).
9. Does CV-043 provide valid evidence of over-generalization? **Yes**, precisely as the manuscript
   already presents it.
10. Should the ontology be changed now? **No** — see Recommendation above.
