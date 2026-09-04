"""
SUT-1 Schema Extraction: Full audit of Global Ontology structure for SUT integration design.
Produces structured output for use in architecture documents.
"""
import io, sys, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from collections import defaultdict
from rdflib import Graph, Namespace, RDF, RDFS, OWL, Literal, URIRef, XSD

RISKONTO = Namespace("https://cs.unb.ca/ontologies/riskonto#")
SWRL_NS  = Namespace("http://www.w3.org/2003/11/swrl#")

def local(uri): return str(uri).split("#")[-1]

print("Loading ontology...")
g = Graph()
g.parse("global/RiskOnto_global_UPDATED.owl", format="xml")
print(f"  {len(g)} triples\n")

# ─── 1. Ontology declaration ───────────────────────────────────────────────
print("=" * 70)
print("SECTION 1: ONTOLOGY DECLARATION")
print("=" * 70)
for ont in g.subjects(RDF.type, OWL.Ontology):
    print(f"  Ontology URI: {ont}")
    for v in g.objects(ont, OWL.versionIRI):
        print(f"  versionIRI: {v}")
    for imp in g.objects(ont, OWL.imports):
        print(f"  imports: {imp}")

# ─── 2. All Classes ────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 2: ALL CLASSES")
print("=" * 70)
classes = set()
for s in g.subjects(RDF.type, OWL.Class):
    if str(s).startswith("https://cs.unb.ca/ontologies/riskonto#"):
        classes.add(local(str(s)))
for s in g.subjects(RDFS.subClassOf, None):
    if str(s).startswith("https://cs.unb.ca/ontologies/riskonto#"):
        classes.add(local(str(s)))
classes_sorted = sorted(classes)
print(f"  Total classes: {len(classes_sorted)}")
for c in classes_sorted:
    uri = RISKONTO[c]
    subs = [local(str(s)) for s in g.subjects(RDFS.subClassOf, uri)
            if str(s).startswith("https://cs.unb.ca/ontologies/riskonto#")]
    sup  = [local(str(s)) for s in g.objects(uri, RDFS.subClassOf)
            if str(s).startswith("https://cs.unb.ca/ontologies/riskonto#")]
    cnt  = len(list(g.subjects(RDF.type, uri)))
    label = str(g.value(uri, RDFS.label) or "")
    sub_str  = f"  subclasses: [{', '.join(subs)}]" if subs else ""
    sup_str  = f"  superclass: [{', '.join(sup)}]" if sup else ""
    print(f"  {c}  (individuals: {cnt}){sub_str}{sup_str}")

# ─── 3. All Object Properties ──────────────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 3: OBJECT PROPERTIES")
print("=" * 70)
obj_props = set()
for s in g.subjects(RDF.type, OWL.ObjectProperty):
    if str(s).startswith("https://cs.unb.ca/ontologies/riskonto#"):
        obj_props.add(local(str(s)))
for p in sorted(obj_props):
    uri = RISKONTO[p]
    cnt = len(list(g.triples((None, uri, None))))
    dom = [local(str(d)) for d in g.objects(uri, RDFS.domain) if "riskonto" in str(d)]
    rng = [local(str(r)) for r in g.objects(uri, RDFS.range) if "riskonto" in str(r)]
    dom_str = f"  domain: {dom}" if dom else ""
    rng_str = f"  range: {rng}" if rng else ""
    print(f"  {p}  (triples: {cnt}){dom_str}{rng_str}")

# ─── 4. All Datatype Properties ────────────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 4: DATATYPE PROPERTIES")
print("=" * 70)
dat_props = set()
for s in g.subjects(RDF.type, OWL.DatatypeProperty):
    if str(s).startswith("https://cs.unb.ca/ontologies/riskonto#"):
        dat_props.add(local(str(s)))
for p in sorted(dat_props):
    uri = RISKONTO[p]
    cnt = len(list(g.triples((None, uri, None))))
    rng = [str(r).split("#")[-1] for r in g.objects(uri, RDFS.range)]
    dom = [local(str(d)) for d in g.objects(uri, RDFS.domain) if "riskonto" in str(d)]
    dom_str = f"  domain: {dom}" if dom else ""
    rng_str = f"  range: {rng}" if rng else ""
    print(f"  {p}  (triples: {cnt}){dom_str}{rng_str}")

# ─── 5. SWRL Rules ─────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 5: SWRL RULES (13 total)")
print("=" * 70)
rules = list(g.subjects(RDF.type, SWRL_NS.Imp))
for rule in sorted(rules, key=lambda r: str(r)):
    rid   = str(rule)
    label = str(g.value(rule, RDFS.label) or "")
    print(f"  {rid}")
    if label: print(f"    label: {label}")

# ─── 6. Individual inventory by class ──────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 6: INDIVIDUAL INVENTORY BY CLASS")
print("=" * 70)
for c in classes_sorted:
    uri  = RISKONTO[c]
    inds = list(g.subjects(RDF.type, uri))
    if inds:
        sample = [local(str(i)) for i in inds[:3]]
        print(f"  {c}: {len(inds)} individuals — e.g. {sample}")

# ─── 7. Key property chain inventory ──────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 7: KEY PROPERTY CHAIN CONNECTIVITY")
print("=" * 70)

vps = list(g.subjects(RDF.type, RISKONTO.VulnerabilityProfile))
sample_vp = RISKONTO.VulnProfile_SQL_Injection

def chain_props(subj, props):
    results = {}
    cur = [subj]
    for p in props:
        nxt = []
        for s in cur:
            nxt.extend(g.objects(s, RISKONTO[p]))
        results[p] = len(nxt)
        cur = nxt
    return results

chains = chain_props(sample_vp, [
    "mappedToCWE","mitigatedBy","exploitableByTechnique",
    "affectsSubcategory","affectsFunction","recommendedFor",
    "recommendedD3FEND","explainsRisk","explainsMitigation",
    "explainsDefense","explainsComplianceGap","hasReasoningTrace",
    "hasJustification"
])
print("  SQL Injection VP chain depths:")
for k,v in chains.items():
    print(f"    {k}: {v}")

# ─── 8. Existing classes relevant to SUT (SystemUnderTest, Asset, etc.) ────
print("\n" + "=" * 70)
print("SECTION 8: SUT-RELEVANT CLASS PRESENCE CHECK")
print("=" * 70)
sut_candidates = [
    "SystemUnderTest","Asset","Application","Database","API","Host",
    "CloudService","NetworkDevice","Container","DataPipeline",
    "IdentityProvider","Finding","Evidence","ScenarioEvidence",
    "Scanner","ScanFinding","Vulnerability","CAPEC","AttackPath",
    "RiskPropagation","AssetRisk","ThreatActor","BusinessImpact",
    "Remediation","ScanReport","AssetGroup","AssetCategory",
    "ThreatScenario","RiskAssessment","ReasoningTrace",
    "VulnerabilityProfile","CWE","Mitigation","AttackTechnique",
    "D3FENDTechnique","NISTSubcategory","Control","Function",
    "RiskJustification","MitigationJustification","ComplianceJustification",
    "RecommendationStatement","DefenseJustification",
    "RootCauseExplanation","ImpactExplanation","EvidenceStatement",
    "ExplanationTemplate","RiskLevel","LegacyControlReference",
]
for name in sut_candidates:
    uri = RISKONTO[name]
    present = (uri, RDF.type, OWL.Class) in g or \
              any(True for _ in g.subjects(RDFS.subClassOf, uri)) or \
              any(True for _ in g.subjects(RDF.type, uri))
    inds = len(list(g.subjects(RDF.type, uri)))
    status = "CLASS EXISTS" if (uri, RDF.type, OWL.Class) in g else \
             ("INDIVIDUALS ONLY" if inds > 0 else "ABSENT")
    print(f"  {name:40s} {status}  ({inds} individuals)")

# ─── 9. ThreatScenario + RiskAssessment property audit ─────────────────────
print("\n" + "=" * 70)
print("SECTION 9: ThreatScenario + RiskAssessment PROPERTY AUDIT")
print("=" * 70)
ts_list = list(g.subjects(RDF.type, RISKONTO.ThreatScenario))
ra_list = list(g.subjects(RDF.type, RISKONTO.RiskAssessment))
print(f"  ThreatScenario count: {len(ts_list)}")
print(f"  RiskAssessment count: {len(ra_list)}")
if ts_list:
    ts_sample = ts_list[0]
    ts_props = set(p for _,p,_ in g.triples((ts_sample, None, None)))
    print(f"  ThreatScenario sample props: {[local(str(p)) for p in ts_props]}")
if ra_list:
    ra_sample = ra_list[0]
    ra_props = set(p for _,p,_ in g.triples((ra_sample, None, None)))
    print(f"  RiskAssessment sample props: {[local(str(p)) for p in ra_props]}")

# ThreatScenario → VP links
ts_vp = sum(1 for ts in ts_list if list(g.objects(ts, RISKONTO.assessesVulnerability)))
ts_vp2 = sum(1 for ts in ts_list if list(g.objects(ts, RISKONTO.targetsVulnerability)))
ts_vp3 = sum(1 for ts in ts_list if list(g.objects(ts, RISKONTO.hasVulnerabilityProfile)))
print(f"  TS→VP via assessesVulnerability: {ts_vp}")
print(f"  TS→VP via targetsVulnerability: {ts_vp2}")
print(f"  TS→VP via hasVulnerabilityProfile: {ts_vp3}")
# All TS outgoing properties
ts_all_props = defaultdict(int)
for ts in ts_list:
    for _, p, _ in g.triples((ts, None, None)):
        ts_all_props[local(str(p))] += 1
print("  All ThreatScenario property usage:")
for k, v in sorted(ts_all_props.items(), key=lambda x: -x[1]):
    print(f"    {k}: {v}")

# RiskAssessment all properties
ra_all_props = defaultdict(int)
for ra in ra_list:
    for _, p, _ in g.triples((ra, None, None)):
        ra_all_props[local(str(p))] += 1
print("  All RiskAssessment property usage:")
for k, v in sorted(ra_all_props.items(), key=lambda x: -x[1]):
    print(f"    {k}: {v}")

# ─── 10. Namespace inventory ───────────────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 10: NAMESPACE INVENTORY")
print("=" * 70)
namespaces = dict(g.namespaces())
for prefix, ns in sorted(namespaces.items()):
    print(f"  {prefix!r:20s} {ns}")

# ─── 11. SWRL variable/atom patterns ──────────────────────────────────────
print("\n" + "=" * 70)
print("SECTION 11: SWRL RULE BODY/HEAD PATTERN SUMMARY")
print("=" * 70)
for rule in sorted(rules, key=lambda r: str(r)):
    rid = local(str(rule)).replace("urn:swrl:rule:","")
    label = str(g.value(rule, RDFS.label) or rid)
    # collect class atoms and property atoms
    body_bn = g.value(rule, SWRL_NS.body)
    head_bn = g.value(rule, SWRL_NS.head)
    def extract_atoms(bn):
        if bn is None: return []
        atoms = []
        visited = set()
        cur = bn
        while cur and cur not in visited:
            visited.add(cur)
            first = g.value(cur, RDF.first)
            rest  = g.value(cur, RDF.rest)
            if first:
                t = g.value(first, RDF.type)
                if t == SWRL_NS.ClassAtom:
                    cp = g.value(first, SWRL_NS.classPredicate)
                    atoms.append(f"ClassAtom({local(str(cp)) if cp else '?'})")
                elif t == SWRL_NS.IndividualPropertyAtom:
                    pp = g.value(first, SWRL_NS.propertyPredicate)
                    atoms.append(f"ObjPropAtom({local(str(pp)) if pp else '?'})")
                elif t == SWRL_NS.DatavaluedPropertyAtom:
                    pp = g.value(first, SWRL_NS.propertyPredicate)
                    atoms.append(f"DataPropAtom({local(str(pp)) if pp else '?'})")
                elif t:
                    atoms.append(f"{local(str(t))}(?)")
            cur = rest
        return atoms
    body_atoms = extract_atoms(body_bn)
    head_atoms = extract_atoms(head_bn)
    print(f"\n  Rule: {rid}")
    print(f"    BODY: {body_atoms}")
    print(f"    HEAD: {head_atoms}")

print("\n\nExtraction complete.")
