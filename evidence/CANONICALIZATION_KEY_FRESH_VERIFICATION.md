# Canonicalization Key — Fresh Re-Verification Against a Reviewer-Proposed Alternative

A reviewer (writing against the earlier 16-page manuscript) proposed replacing the current
canonicalization description with a location-sensitive, type-specific key scheme:
`hash(scanner_family, CWE, repository, normalized_file_path, start_line, sink/source_signature)`
for code findings, with separate schemes for web and dependency findings, plus a cross-scanner
equivalence-clustering layer. Before touching the manuscript, the actual implementation was
re-inspected fresh this phase (not inherited from the existing `§sec:dedup` text, which was itself
written in a prior phase per `V27_DEDUPLICATION_RECONCILIATION.md`).

## Fresh findings (this phase, independent Explore-agent investigation)

**Script:** `sut2a_reaudit.py` (current/certified pipeline; `sut2a_pipeline.py` is an earlier,
functionally identical version). Canonicalization logic: `phase4_normalize()` /
`phase5_catalog()` (`sut2a_reaudit.py:707,733`), mirrored by `phase2_catalog`/`phase3_normalize`/
`phase4_fuse` in `sut2a_pipeline.py:442,502,540`.

**The canonical key is CWE identity alone** (with one hardcoded variant collapse, CWE-23→CWE-22):
```python
CWE_VARIANT_MAP = {"CWE-23": "CWE-22"}
def canonical_cwe(cwe): return CWE_VARIANT_MAP.get(cwe, cwe)
groups = defaultdict(list)
for f, n in zip(all_findings, norm_rows):
    groups[n["canonical_cwe"]].append(f)
```
(`sut2a_reaudit.py:657-659,739-741`; identical pattern at `sut2a_pipeline.py:547-549`). No file
path, line number, host, HTTP method, parameter, package name, or dependency path is read
anywhere in this grouping code.

**Scanner identity is provenance only**, feeding `confidence_score` and `supporting_scanners`
metadata (`sut2a_pipeline.py:554,557`) — never a grouping key.

**Location data exists in the raw records but is never used for merging.**
`raw_findings_inventory.csv` has populated `file`/`line` columns for code scanners, but neither
field is referenced anywhere in the grouping functions.

**No cross-scanner equivalence-clustering layer exists.** The only merge-provenance annotation is
a hardcoded string, `"merge_reason": "same_canonical_cwe"` (`sut2a_pipeline.py:601`).

**Missing-field handling** exists only for missing CWE (all CWE-less rows route to one catch-all
bucket, `sut2a_pipeline.py:480-488`); there is no location-collision check at all.

**Concrete, verified cross-location merge:** `CV-042` (CWE-918, SSRF) merges `SEM-005`
(`file=src\main\java\...\JWTHeaderJKUEndpoint.java, line=57`, a Semgrep SAST hit) and `SNYK-007`
(`file=com.thoughtworks.xstream:xstream@1.4.5, line=NONE`, a Snyk dependency finding whose "file"
field is a package coordinate, not a path). These share no file path or line; they merge solely
because `canonical_cwe("CWE-918")` is identical for both — direct proof the merge is location-blind.

**Numeric trace, independently re-confirmed against the actual CSVs (not assumed from prior
counts):** `raw_findings_inventory.csv` = 273 rows; `finding_normalization_map.csv` = 273 rows
(hasCWE=166, NONE=107); `canonical_vulnerability_catalog.csv` = 44 rows (CV-001–CV-043 = 43
CWE-keyed canonical findings; CV-044 = the single NONE-CWE catch-all bucket, excluded from the
43-finding reporting boundary).

## Verdict

**The reviewer's proposed key does not describe the implementation and was not adopted.** The
existing manuscript text in `§sec:dedup` ("Canonicalization algorithm (current implementation)")
was independently re-verified against this fresh code inspection and found to already accurately
describe: (1) CWE-identity-only keying, (2) scanner identity as provenance not a merge gate, (3) a
single shared no-CWE bucket for CWE-less findings, (4) the CV-040 cross-scanner merge example
(22 raw findings, 2 scanners, shared CWE-89), (5) the explicit "current limitation: does not
retain file, line, URL, endpoint or parameter information" disclosure, and (6) the reviewer's
proposed context-aware key presented correctly as unimplemented future work, not a present
capability. **No manuscript change was required for this section — it already matches the
verified implementation exactly.**
