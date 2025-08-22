# ✅ Final working dashboard.py
import streamlit as st
from pyvis.network import Network
import tempfile
import os
from rdflib import Graph, Namespace, RDF, RDFS, Literal, SKOS, URIRef
import pandas as pd
import plotly.express as px

# Load Ontology
g = Graph()
g.parse("RiskOnto_v1.owl", format="xml")

# Namespaces
NIST = Namespace("http://example.org/riskonto#")
D3F = Namespace("http://example.org/d3fend#")
SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")
g.bind("nist", NIST)
g.bind("d3fend", D3F)
g.bind("skos", SKOS)

# Clean helper
def clean_label(label):
    if isinstance(label, Literal):
        label = str(label)
    return label.replace("Subcategory for ", "").strip()

def is_valid_uri(uri):
    return isinstance(uri, URIRef) and " " not in uri and "," not in uri

# Streamlit Config
st.set_page_config(layout="wide")
st.title("🛡️ RiskOnto Compliance & Risk Dashboard")

# -------------------------
# Graph Explorer
# -------------------------
st.subheader("🔗 RiskOnto Graph Explorer")
net = Network(height="700px", width="100%", bgcolor="#111111", font_color="white")
net.set_options("""
var options = {
  "interaction": {"navigationButtons": true},
  "physics": {
    "forceAtlas2Based": {
      "gravitationalConstant": -30,
      "springLength": 90,
      "springConstant": 0.04
    },
    "minVelocity": 0.75,
    "solver": "forceAtlas2Based"
  }
}
""")

added_nodes = set()
for subcat in g.subjects(RDF.type, NIST.SubCategory):
    if not is_valid_uri(subcat): continue
    subcat_label = clean_label(next(g.objects(subcat, RDFS.label), subcat.split("#")[-1]))
    if subcat_label not in added_nodes:
        net.add_node(subcat_label, label=subcat_label, color="#1f77b4", shape="box")
        added_nodes.add(subcat_label)
    for control in g.objects(subcat, NIST.hasControl):
        if not is_valid_uri(control): continue
        control_label = clean_label(next(g.objects(control, RDFS.label), control.split("#")[-1]))
        if control_label not in added_nodes:
            net.add_node(control_label, label=control_label, color="#ff7f0e", shape="ellipse")
            added_nodes.add(control_label)
        net.add_edge(subcat_label, control_label)
        for tech in g.objects(control, NIST.hasMitigation):
            if not is_valid_uri(tech): continue
            tech_label = clean_label(next(g.objects(tech, RDFS.label), tech.split("#")[-1]))
            if tech_label not in added_nodes:
                net.add_node(tech_label, label=tech_label, color="#2ca02c", shape="diamond")
                added_nodes.add(tech_label)
            net.add_edge(control_label, tech_label)

with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
    net.save_graph(tmp_file.name)
    tmp_path = tmp_file.name
with open(tmp_path, "r", encoding="utf-8") as f:
    html_content = f.read()
st.components.v1.html(html_content, height=750, scrolling=True)
st.download_button("📥 Download Graph HTML", data=html_content, file_name="ontology_graph.html")
os.remove(tmp_path)

# -------------------------
# Mapped Mitigations Table
# -------------------------
st.subheader("🧩 Mapped Mitigations")
triples = list(g.triples((None, NIST.hasMitigation, None)))
st.code(f"🔍 Total hasMitigation triples: {len(triples)}")

mapped = []
for control, _, technique in triples:
    if not (is_valid_uri(control) and is_valid_uri(technique)):
        continue
    subcat = next(g.subjects(NIST.hasControl, control), None)
    if not subcat or not is_valid_uri(subcat):
        continue
    subcat_label = clean_label(next(g.objects(subcat, RDFS.label), subcat.split("#")[-1]))
    control_label = clean_label(next(g.objects(control, RDFS.label), control.split("#")[-1]))
    technique_label = clean_label(next(g.objects(technique, RDFS.label), technique.split("#")[-1]))
    mapped.append({
        "NIST Subcategory": subcat_label,
        "NIST Control": control_label,
        "D3FEND Technique": technique_label
    })

df_mapped = pd.DataFrame(mapped).drop_duplicates()

# Filter UI
col1, col2, col3 = st.columns(3)
with col1:
    selected_subcat = st.selectbox("🔎 Filter by Subcategory", ["All"] + sorted(df_mapped["NIST Subcategory"].unique()))
with col2:
    selected_control = st.selectbox("🎛 Filter by Control", ["All"] + sorted(df_mapped["NIST Control"].unique()))
with col3:
    selected_tech = st.selectbox("🛡️ Filter by Technique", ["All"] + sorted(df_mapped["D3FEND Technique"].unique()))

filtered = df_mapped.copy()
if selected_subcat != "All":
    filtered = filtered[filtered["NIST Subcategory"] == selected_subcat]
if selected_control != "All":
    filtered = filtered[filtered["NIST Control"] == selected_control]
if selected_tech != "All":
    filtered = filtered[filtered["D3FEND Technique"] == selected_tech]

st.dataframe(filtered, use_container_width=True)
st.bar_chart(filtered["NIST Control"].value_counts())
st.bar_chart(filtered["D3FEND Technique"].value_counts())
# -------------------------
# Tool Compliance
# -------------------------

# Extract tools
tools = sorted([str(next(g.objects(t, RDFS.label), t.split("#")[-1])) for t in g.subjects(RDF.type, NIST.Tool)])
tool_filter = st.sidebar.selectbox("🔧 Select Tool", ["All"] + tools)

controls = list(g.subjects(RDF.type, NIST.Control))
compliance_summary = []
recommendations = []

for tool in g.subjects(RDF.type, NIST.Tool):
    tool_label = next(g.objects(tool, RDFS.label), tool.split("#")[-1])
    if tool_filter != "All" and tool_label != tool_filter:
        continue
    compliant = set(g.objects(tool, NIST.implementsControl))
    missing = set(controls) - compliant
    rec_techs = [next(g.objects(t, RDFS.label), t.split("#")[-1]) for m in missing for t in g.objects(m, NIST.hasMitigation)]
    compliance_summary.append({
        "Tool": tool_label,
        "Compliant With": ", ".join(sorted([c.split("#")[-1] for c in compliant])) or "None",
        "Non-Compliant With": ", ".join(sorted([m.split("#")[-1] for m in missing])) or "None",
        "Recommended Mitigations": ", ".join(sorted(set(rec_techs))) or "None"
    })
    for m in missing:
        m_label = next(g.objects(m, RDFS.label), m.split("#")[-1])
        for t in g.objects(m, NIST.hasMitigation):
            t_label = next(g.objects(t, RDFS.label), t.split("#")[-1])
            recommendations.append({
                "Tool": tool_label,
                "Missing Control": m_label,
                "Suggested Technique": t_label,
                "Explanation": f"{tool_label} lacks NIST control {m_label}, which is mitigated by {t_label} of the D3fend Technique."
            })

df_compliance = pd.DataFrame(compliance_summary)
df_reco = pd.DataFrame(recommendations)

st.subheader("🧪 Tool Compliance Overview")
st.dataframe(df_compliance)

st.subheader("🤖 Smart Recommendations")
if not df_reco.empty:
    st.dataframe(df_reco)
    st.download_button("📥 Download Recommendations", df_reco.to_csv(index=False).encode("utf-8"), "xai_tool_mitigations.csv")
else:
    st.info("All tools are compliant. No recommendations to display.")

# -------------------------
# Risk Analysis & Heatmap
# -------------------------
risk_data = []
compliance_rows = []
alerts = []

all_controls = list(g.subjects(RDF.type, NIST.Control))
for tool in g.subjects(RDF.type, NIST.Tool):
    label = next(g.objects(tool, RDFS.label), tool.split("#")[-1])
    if tool_filter != "All" and label != tool_filter:
        continue
    implemented = list(g.objects(tool, NIST.implementsControl))
    comp = len(implemented)
    noncomp = len(set(all_controls) - set(implemented))
    total = len(all_controls)
    score = (comp / total * 100) if total > 0 else 0

    compliance_rows.append({"Tool": label, "Score (%)": round(score, 2), "Passed": comp, "Failed": noncomp})

    for asset, _, threat in g.triples((None, NIST.isTargetedBy, None)):
        a_label = next(g.objects(asset, RDFS.label), asset.split("#")[-1])
        t_label = next(g.objects(threat, RDFS.label), threat.split("#")[-1])
        sev = next(g.objects(threat, NIST.severityLevel), Literal("Unknown"))
        lik = next(g.objects(threat, NIST.likelihood), Literal(0.0))
        imp = next(g.objects(threat, NIST.impact), Literal(0))
        risk = next(g.objects(threat, NIST.riskScore), Literal(0.0))

        risk_data.append({"Tool": label, "Asset": a_label, "Threat": t_label, "Severity": str(sev), "Likelihood": float(lik), "Impact": int(imp), "Risk Score": float(risk)})

        if float(risk) >= 5.0 and str(sev) == "High" and score < 50:
            alerts.append({"Tool": label, "Asset": a_label, "Threat": t_label, "Severity": str(sev), "Risk Score": float(risk), "Compliance Score (%)": round(score, 2), "Alert": "⚠️ High risk threat + low compliance"})

df_risk = pd.DataFrame(risk_data)
df_compliance = pd.DataFrame(compliance_rows)
df_alerts = pd.DataFrame(alerts)

st.subheader("📊 Simulated Compliance Scoring")
st.dataframe(df_compliance)
if not df_compliance.empty:
    st.bar_chart(df_compliance.set_index("Tool")["Score (%)"])
if not df_alerts.empty:
    st.subheader("🚨 Compliance Alerts")
    st.dataframe(df_alerts)

# Risk Filters
asset_filter = "All"
severity_filter = "All"
if not df_risk.empty:
    if "Asset" in df_risk.columns:
        asset_filter = st.sidebar.selectbox("Asset", ["All"] + sorted(df_risk["Asset"].unique()))
    if "Severity" in df_risk.columns:
        severity_filter = st.sidebar.selectbox("Severity", ["All"] + sorted(df_risk["Severity"].unique()))

filtered_risk = df_risk.copy()
if "Tool" in filtered_risk.columns and tool_filter != "All":
    filtered_risk = filtered_risk[filtered_risk["Tool"] == tool_filter]
if "Asset" in filtered_risk.columns and asset_filter != "All":
    filtered_risk = filtered_risk[filtered_risk["Asset"] == asset_filter]
if "Severity" in filtered_risk.columns and severity_filter != "All":
    filtered_risk = filtered_risk[filtered_risk["Severity"] == severity_filter]

st.subheader("📊 Risk Score by Asset")
if not filtered_risk.empty and "Asset" in filtered_risk.columns:
    st.bar_chart(filtered_risk.groupby("Asset")["Risk Score"].sum())
st.subheader("📈 Threat Severity Distribution")
if not filtered_risk.empty and "Severity" in filtered_risk.columns:
    st.bar_chart(filtered_risk["Severity"].value_counts())
st.dataframe(filtered_risk)

# Heatmap
st.subheader("🔥 Threat Heatmap: Tool × Asset × Risk")
if not filtered_risk.empty and "Tool" in filtered_risk.columns and "Asset" in filtered_risk.columns:
    heatmap_df = filtered_risk.pivot_table(index="Tool", columns="Asset", values="Risk Score", aggfunc="sum", fill_value=0)
    fig = px.imshow(heatmap_df, labels=dict(x="Asset", y="Tool", color="Risk Score"), color_continuous_scale="Reds", aspect="auto")
    st.plotly_chart(fig, use_container_width=True)

# Downloads
st.download_button("📥 Download Risk CSV", filtered_risk.to_csv(index=False).encode("utf-8"), "risk_exposure_report.csv")
st.download_button("📥 Download Compliance CSV", df_compliance.to_csv(index=False).encode("utf-8"), "compliance_scores.csv")
if not df_alerts.empty:
    st.download_button("📥 Download Alert Summary", df_alerts.to_csv(index=False).encode("utf-8"), "compliance_risk_alerts.csv")
