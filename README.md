# RiskOnto — Threat Reasoning Ontology

**RiskOnto** is an OWL 2 ontology that operationalises threat-informed risk reasoning for cybersecurity systems. It integrates MITRE ATT&CK, MITRE D3FEND, and NIST Cybersecurity Framework 2.0 (CSF 2.0 / SP 800-53r5) into a single, reusable knowledge graph that supports SWRL-driven explainable risk inference.

---

## Repository Contents

| File | Type | Description |
|------|------|-------------|
| `RiskOnto_v1_revised.owl` | Global Ontology | Reusable threat reasoning core — 100,016 triples |
| `WebGoat_SUT.owl` | SUT Ontology | Experimental population of RiskOnto against OWASP WebGoat |

---

## `RiskOnto_v1_revised.owl` — Global Ontology

The global ontology is the **reusable, SUT-independent core**. It encodes the complete threat reasoning knowledge base and is intended to be imported by any System Under Test (SUT) ontology.

### Key Metrics

| Layer | Count |
|-------|-------|
| VulnerabilityProfile individuals | 116 |
| ATT&CK Techniques | 995 (Enterprise + Mobile + ICS) |
| Mitigations | 111 |
| D3FEND Techniques | 383 |
| CWE Individuals | 250 |
| NIST CSF 2.0 Subcategories | 106 |
| ThreatScenario individuals | 352 |
| RiskAssessment individuals | 352 |
| Total OWL triples | 100,016 |

### Architecture

```
VulnerabilityProfile
  ├─ mappedToCWE          → CWE
  ├─ exploitableByTechnique → ATT&CK Technique
  │     └─ mitigatedBy    → Mitigation
  │           └─ implementedBy → D3FEND Technique
  ├─ affectsSubcategory   → NIST CSF 2.0 Subcategory
  ├─ affectsFunction      → NIST CSF 2.0 Function
  ├─ recommendedFor       → (Mitigation → VP, materialised)
  └─ recommendedD3FEND    → (D3FEND → VP, materialised)
```

### SWRL Reasoning Rules

Thirteen SWRL rules (SI-7, SI-9, SI-11) materialise the full reasoning chain when an `Asset` is linked to a `VulnerabilityProfile` via `hasVulnerability`:

- **R1–R4**: ATT&CK chain, mitigation recommendations, D3FEND, NIST compliance gap
- **X1–X5**: Explainability layer — `RiskJustification`, `MitigationJustification`, `DefenseJustification`, `RiskScore`, `ExplanationStatement`
- **E1–E3**: Risk level assignment from impact × likelihood

### Semantic Integrity

- Certified at **Semantic Integrity Score 100/100** (SI-11.1 audit)
- No synthetic ATT&CK or D3FEND mappings
- All 462 `recommendedFor` and 2,814 `recommendedD3FEND` triples materialised from authoritative source data
- NIST CSF 2.0 backbone: 120 D3FEND→NIST `supports` triples; 810 Mitigation→NIST `supportsSubcategory` triples

---

## `WebGoat_SUT.owl` — WebGoat System Under Test

`WebGoat_SUT.owl` is an **experimental SUT ontology** that applies RiskOnto to [OWASP WebGoat](https://owasp.org/www-project-webgoat/) — a deliberately insecure Java Spring web application used for security training. It is provided as a reference integration to demonstrate how RiskOnto reasoning activates against real scanner evidence.

### Evidence Sources

Four commercial/open-source scanners were run against WebGoat and all findings were normalised before population:

| Scanner | Type | Raw Findings |
|---------|------|-------------|
| Semgrep | SAST | 17 |
| SonarQube (Issues + Hotspots) | SAST | 169 |
| Snyk | SCA | 77 |
| OWASP ZAP | DAST | 10 |
| **Total raw** | | **273** |

### Population Summary

| Metric | Value |
|--------|-------|
| Canonical security findings | 43 |
| ExploitableVulnerability | 4 |
| DependencyWeakness (Snyk) | 26 |
| ConfigurationWeakness (ZAP) | 5 |
| SecurityWeakness (CWE, no VP) | 8 |
| OWL triples | 2,031 |
| SWRL activation points (`hasVulnerability`) | 13 |

### Integration Architecture

```
WebGoat_SUT.owl  imports  RiskOnto_v1_revised.owl
        │
        ├─ wg:SystemUnderTest  (WebGoat application)
        ├─ riskonto:Asset      (Asset_WebGoatApp, Asset_WebGoatDB, …)
        ├─ wg:CanonicalSecurityFinding  rdfs:subClassOf  riskonto:Evidence
        ├─ wg:EvidenceBundle            rdfs:subClassOf  riskonto:Evidence
        │
        └─ Asset  riskonto:hasVulnerability  VulnerabilityProfile
                       ↓  (activates 13 SWRL rules)
                  ATT&CK chain → Mitigations → D3FEND → NIST gap → XAI
```

The **sole integration primitive** is one `hasVulnerability` triple per asset. All risk reasoning, mitigation recommendations, D3FEND controls, NIST compliance gaps, and explainability traces are inferred by the global ontology's SWRL rules — the SUT contains only evidence.

### Namespaces

| Prefix | IRI |
|--------|-----|
| `riskonto:` | `https://cs.unb.ca/ontologies/riskonto#` |
| `wg:` | `https://cs.unb.ca/ontologies/sut/webgoat#` |

### Experimental Status

WebGoat_SUT.owl is provided for **demonstration and validation** purposes only:

- Risk assessment placeholders (`impact`, `likelihood`) are not scored — scoring is performed in SUT-2C
- 30 of 43 findings are represented but not yet reasoning-enabled (awaiting RiskOnto v2.5 expansion)
- The SUT does **not** contain risk scores, compliance recommendations, or D3FEND mappings — all reasoning output is derived exclusively from the Global Ontology

---

## Usage

To load and reason over the combined ontology:

```python
from rdflib import Graph
g = Graph()
g.parse("RiskOnto_v1_revised.owl", format="xml")
g.parse("WebGoat_SUT.owl", format="turtle")
# Apply SWRL rules using an OWL 2 RL reasoner (e.g. Pellet, HermiT, owlrl)
```

Or in Protégé: open `WebGoat_SUT.owl` — it will auto-import `RiskOnto_v1_revised.owl` via the `owl:imports` declaration.

---

## Citation

If you use RiskOnto in your research, please cite:

```
Adelere, M. A. (2026). RiskOnto: A Threat-Informed Risk Reasoning Ontology
Integrating MITRE ATT&CK, D3FEND, and NIST CSF 2.0.
University of New Brunswick, Faculty of Computer Science.
```

---

## License

This work is part of ongoing PhD research at the University of New Brunswick (UNB).
All rights reserved pending publication. Contact: michael.a.adelere@gmail.com
