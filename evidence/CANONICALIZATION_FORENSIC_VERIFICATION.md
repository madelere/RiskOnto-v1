# Canonicalization Forensic Verification

**No manuscript edits were made in the production of this document.** This is a narrow,
record-level forensic verification of a single claim, performed independently of and in addition
to the aggregate-level check reported in `FINAL_DEDUPLICATION_REPRODUCTION.md`.

## 1. Executive Verdict

**VERIFIED WITH FILTERING.**

All 273 raw findings enter the pipeline and are accounted for, but the pipeline is not a pure
"273 findings → merge into 43 groups" transformation. It is: 273 raw findings → CWE-presence
check → 166 findings with a CWE are grouped into 43 canonical findings; 107 findings with no CWE
are pooled into one separate, unpublished group. This is now confirmed at the individual-record
level (not just aggregate counts), cross-validated from two independent primary sources, and
independently re-confirmed against the actual SUT ontology file. The finding reported previously
is real, not a misunderstanding, duplication artifact, or pagination artifact (Possibility C is
ruled out).

## 2. Authoritative Data Sources Inspected

| File | Role | Row/triple count |
|---|---|---|
| `SUT/evidence/parsed_findings/raw_findings_inventory.csv` | Primary raw-finding record, one row per finding, with its own `cwe` column | 273 rows, 273 unique `finding_id` values (no duplicates) |
| `SUT/evidence/fusion_logs/canonical_findings.csv` | Output of the canonicalization/fusion script | 44 rows |
| `sut2a_pipeline.py` | The canonicalization script itself (`phase3_normalize`, `phase4_fuse`) | — |
| `SUT/WebGoat_SUT_v27_reasoned.owl` | The actual SUT ontology used for reasoning (Turtle format) | 2,248 triples |

## 3. Reconstruction of 273 Raw Findings

Derived directly from `raw_findings_inventory.csv` (`Counter` over the `scanner` column, 273
unique finding IDs, zero duplicates):

| Scanner / Report Stream | Count |
|---|---:|
| Semgrep | 17 |
| Snyk | 77 |
| SonarQube Issues | 100 |
| SonarQube Hotspots | 69 |
| OWASP ZAP | 10 |
| **TOTAL** | **273** |

Confirmed exact match to the manuscript's Scanner Coverage table.

## 4. Actual Canonicalization Algorithm (from `sut2a_pipeline.py`)

```python
# phase3_normalize
for f in raw_findings:
    canon_id = cwe_to_canon.get(f["cwe"], none_canon)   # none_canon = ONE shared bucket ID
                                                          # for every finding with no CWE match
    norm_rows.append({finding_id, scanner, cwe, canonical_id: canon_id, severity, title})

# phase4_fuse
grp = defaultdict(list)               # canonical_id -> [finding_id, ...]
for n in norm_rows:
    grp[n["canonical_id"]].append(n["finding_id"])
# one canonical_findings.csv row is emitted per group in grp,
# including one row for the none_canon group
```

There is **no filtering step that drops findings before this point** — every one of the 273 raw
findings is read, normalized, and assigned to exactly one group (either one of the 43 CWE-matched
groups, or the single `none_canon` group). Nothing is silently discarded pre-canonicalization;
the "exclusion" is a downstream editorial choice (which groups the manuscript reports), not a
pipeline data-loss bug.

## 5. Pipeline Count Reconciliation

| Stage | Count | Evidence |
|---|---:|---|
| Stage 0: Raw scanner findings | 273 | §3 above |
| Stage 1: Findings loaded into pipeline | 273 | `norm_rows` has one entry per input row — verified no row is skipped in `phase3_normalize` (unconditional loop, no `continue`/filter) |
| Stage 2: Findings removed/filtered before grouping | **0** | No filtering step exists before grouping; see §4 |
| Stage 3: Findings assigned a real CWE group | 166 | Directly counted from `raw_findings_inventory.csv`'s own `cwe` column: 166 rows where `cwe` is a real value (not the literal string `"NONE"`) |
| Stage 3b: Findings assigned the shared no-CWE group | 107 | Same source, 107 rows where `cwe == "NONE"` |
| Stage 4: Canonical groups produced | 44 | `canonical_findings.csv` row count |
| Stage 5: Canonical findings **reported in the manuscript** | 43 | The 44th group (`CANVULN-045`, "Code Quality Issue (No CWE)") is never referenced anywhere in the manuscript |

Arithmetic: 166 + 107 = 273. Exact, no remainder, no unexplained gap.

## 6. Investigation of the Alleged 107 Findings

### Q1 — Are there exactly 107 findings?
**YES.** Confirmed by two fully independent counting methods that agree exactly:
1. Counting rows in `raw_findings_inventory.csv` where the record's own `cwe` field equals the
   literal string `"NONE"`: **107**.
2. Parsing the `supporting_findings` list of the fusion script's `CANVULN-045` output row: **107**
   finding IDs.

These two independently-derived sets of finding IDs were compared programmatically:
**set-equality confirmed — identical, zero difference in either direction.**

### Q2 — Do they belong to the original 273 raw findings?
**YES.** All 107 IDs exist in `raw_findings_inventory.csv` (they were extracted from it directly;
this is definitionally true, and was also independently cross-checked against the fusion output's
own list, which draws from the same source).

### Q3 — Do they have missing CWE values?
**YES**, in every one of the 107 cases, the raw record's own `cwe` field is the literal string
`"NONE"` — confirmed by direct inspection of the primary CSV, not inferred.

### Q4 — Were they explicitly filtered by the implementation?
**No explicit filter/drop.** They were not removed from the dataset; they were *grouped together*
under one shared canonical-ID bucket (`none_canon`) via the same `cwe_to_canon.get(f["cwe"],
none_canon)` lookup every other finding goes through. The "exclusion" is that this one group was
not included when the manuscript enumerated "the 43 canonical findings" — a reporting/scoping
decision downstream of the pipeline, not a bug in the pipeline itself.

### Q5 — Were they excluded before canonicalization?
**No.** They went *through* canonicalization (see §4) — they simply canonicalized into a group
that was not published as one of the 43.

### Q6 — Could they instead be:
- **Duplicate intermediate records?** No — 273 unique `finding_id` values confirmed, zero
  duplicates.
- **Findings outside the intended vulnerability scope?** **Substantially yes, for most of them** —
  see the `raw_category` breakdown below.
- **API pagination artifacts?** No — this is a distinct, separate issue also found this session
  (the SonarQube Issues *export itself* being 100-of-497 due to pagination) but it is unrelated to
  the 107-finding question; the 107 come from the 273 that *were* exported, not from anything cut
  off by the earlier pagination limit.
- **Generic code-quality issues?** **Yes, predominantly.** `raw_category` breakdown across the 107:
  `CODE_SMELL` = 92, `BUG` = 7, `others` (SonarQube Hotspots) = 5, `Informational` (ZAP) = 3.
  92 of 107 (86%) are SonarQube's own "code smell" category (maintainability/style issues such as
  "Define a constant instead of duplicating this literal," "Replace this String concatenation with
  Text block," "Remove this 'public' modifier" — see §7 for exact examples), which SonarQube does
  not assign a CWE to because they are not security weaknesses in SonarQube's own taxonomy.
- **Records represented elsewhere?** No evidence of this — each of the 107 appears exactly once,
  only in the `none_canon` group, nowhere else.
- **An alternative processing branch?** No — same `phase3_normalize`/`phase4_fuse` code path as
  every other finding; there is only one branch.

**One nuance to report honestly, not glossed over:** severity distribution within the 107 is not
uniformly low. Of the 107: Low=31, Informational=28, Medium=24, **Critical=20**, High=4. The
"Critical" label on several `CODE_SMELL` rows (e.g., SQI-001, "Critical" severity, about a
duplicated string literal) reflects SonarQube's own maintainability-severity convention, not a
security-risk rating — SonarQube rates code-smell issues on a severity scale that measures
maintainability impact, not exploitability. This is stated here as a fact for the record, not
interpreted further, per instruction not to reinterpret without direct evidence.

### Q7 — Does the canonicalization script contain an explicit exclusion condition?
**Not an exclusion condition — an inclusion default.** The exact line is:
```python
canon_id = cwe_to_canon.get(f["cwe"], none_canon)
```
`dict.get(key, default)` returns `none_canon` whenever `f["cwe"]` is not a key in the CWE-catalog
lookup table (which happens whenever `f["cwe"] == "NONE"`, since `"NONE"` is never a catalog key).
There is no `if`/`continue`/`drop` statement anywhere in `phase3_normalize` or `phase4_fuse`.

## 7. Reproduction: Manual Trace of a Sample

| Finding ID | Scanner | `raw_category` | Title | Raw `cwe` field | Loaded? | Normalized? | Assigned CWE? | Canonical group |
|---|---|---|---|---|---|---|---|---|
| SQI-001 | SonarQube_Issues | CODE_SMELL | "Define a constant instead of duplicating this literal 'status' 3 times." | `NONE` | Yes | Yes | No | `CANVULN-045` (shared, unpublished) |
| SQI-002 | SonarQube_Issues | CODE_SMELL | "Replace this String concatenation with Text block." | `NONE` | Yes | Yes | No | `CANVULN-045` |
| SQI-050 | SonarQube_Issues | CODE_SMELL | "Remove this 'public' modifier." | `NONE` | Yes | Yes | No | `CANVULN-045` |
| SQH-065 | SonarQube_Hotspots | others | "Make sure publicly writable directories are used safely here." | `NONE` | Yes | Yes | No | `CANVULN-045` |
| ZAP-007 | ZAP | Informational | "Authentication Request Identified" | `NONE` | Yes | Yes | No | `CANVULN-045` |
| **SQI-072** *(contrast case)* | SonarQube_Issues | VULNERABILITY | "Don't use the default 'PasswordEncoder' relying on plain-text." | `CWE-916` | Yes | Yes | **Yes** | `CANVULN-041` (published, CV-041) |
| **SEM-001** *(contrast case)* | Semgrep | SQL Injection | "tainted sql string" | `CWE-89` | Yes | Yes | **Yes** | `CANVULN-040` (published, CV-040) |

SQI-072 is directly adjacent to SQI-071/SQI-073 in the ID sequence (both no-CWE) — its presence in
the has-CWE set demonstrates the split is driven by each record's actual content
(`VULNERABILITY` category, genuine CWE-916 weakness), not an ID-range or positional artifact.

## 8. Impact on Current Manuscript

The manuscript's current sentence pattern (paraphrased from §Scanner Coverage and Normalization):
*"Normalization consolidated 273 raw findings to 43 canonical findings... an approximately 84%
reduction."*

**Classification: PARTIALLY TRUE, requires qualification.**
- It is TRUE that 273 raw findings were collected and that 43 canonical findings were produced by
  CWE-based canonicalization.
- It is **not stated, and would be misleading if read as implying**, that all 273 raw findings
  distribute across those 43 via merging. 107 of the 273 (39%) were canonicalized into a separate,
  unpublished group and are not part of the "43."
- The "84% reduction" figure (273→43, computed as (273−43)/273) is arithmetically correct but
  conflates two different things: genuine CWE-based deduplication (166→43, a real ~74% reduction
  within the security-relevant subset) and the exclusion of the 107 non-security/no-CWE records
  (which is not deduplication at all — nothing was "duplicated" among those 107 relative to each
  other in the sense the manuscript's algorithm describes).

## 9. Recommended Manuscript Action (not applied)

Minimal, non-alarmist wording addition to §Scanner Coverage and Normalization, immediately after
the existing "84% reduction" sentence:

> Of the 273 raw findings, 166 carried a CWE identifier and were canonicalized by CWE identity
> into the 43 canonical findings (CV-001–CV-043) that enter the semantic reasoning workflow; the
> remaining 107 raw findings — predominantly SonarQube code-quality/style observations
> (`CODE_SMELL`, 92 of 107) without a CWE mapping, plus a small number of informational OWASP ZAP
> alerts — were canonicalized into a separate group and are not part of the 43.

This is the only change recommended. It does not alter the 43/43 workflow-coverage claim, the
84%-reduction arithmetic (which remains correct as a 273→43 ratio, just now precisely scoped), or
any other claim in the manuscript.

## Final Stop-Gate Answers

**Q1 — Did all 273 raw findings enter the canonicalization workflow?**
**YES**, with evidence: `phase3_normalize` processes every row unconditionally (§4); all 273
finding IDs are accounted for across the 44 output groups with zero gap (§5).

**Q2 — Were exactly 107 findings excluded [from the published 43]?**
**YES**, with evidence: independently derived and cross-validated from two separate primary
sources (raw inventory's own `cwe` column, and the fusion script's `none_canon` group membership)
— identical 107-ID sets, confirmed by set-equality check (§6, Q1).

**Q3 — Does the current implementation reproduce exactly 43 canonical findings?**
**YES**, with evidence: 43 CWE-based groups in `canonical_findings.csv`; independently
re-confirmed by directly querying the actual SUT ontology file
(`SUT/WebGoat_SUT_v27_reasoned.owl`), which contains exactly 43 `CanonicalSecurityFinding`
individuals.

**Q4 — Is the manuscript's "273 raw findings → 43 canonical findings" statement technically
accurate as currently written?**
**REQUIRES QUALIFICATION.** Both numbers (273, 43) are individually correct and the pipeline that
connects them is fully reproducible, but the implicit "all 273 flow into the 43 via merging"
reading is not accurate — see §8/§9.

## Bonus verification (Phase 7 of the task): is 43/43 workflow coverage independently sound?

Verified directly against `SUT/WebGoat_SUT_v27_reasoned.owl` (2,248 triples), independent of the
raw-finding canonicalization question entirely:
- 43 `CanonicalSecurityFinding` individuals exist in the SUT ontology (matches CV-001–CV-043).
- All 43 have at least one `activatesProfile` assertion (0 findings with zero activations).
- 76 total `activatesProfile` assertions across the 43 findings (i.e., 12 findings activate more
  than one VP, matching the manuscript's existing "12 of 43 activate more than one VP" statement).

**The 43/43 semantic workflow coverage result is fully independent of, and unaffected by, the
273-raw-finding canonicalization question.** Even if the upstream 273→43 description is refined
per §9's recommendation, the 43 findings that exist in the SUT ontology and their 43/43 activation
result require no change whatsoever.
