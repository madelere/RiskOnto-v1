# Updated dashboard.py (Fully functional with subcategories, techniques, and graph)
import streamlit as st
from pyvis.network import Network
import tempfile
import os
from rdflib import Graph, Namespace, RDF, RDFS, Literal, SKOS
import pandas as pd
import plotly.express as px

# Load ontology
g = Graph()
g.parse("backup.owl", format="xml")

# Namespaces
NIST = Namespace("http://example.org/riskonto#")
D3F = Namespace("http://example.org/d3fend#")
SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")
g.bind("nist", NIST)
g.bind("d3fend", D3F)
g.bind("skos", SKOS)

st.set_page_config(layout="wide")
st.title("🛡️ RiskOnto Compliance & Risk Dashboard")

# -------------------------
# Ontology Graph Explorer
# -------------------------
st.subheader("🔗 RiskOnto Graph Explorer")
st.caption("Explore Subcategory → Control → D3FEND Technique relationships")

net = Network(height="700px", width="100%", bgcolor="#222222", font_color="white", notebook=False)
net.set_options("""
var options = {
  "interaction": {"navigationButtons": true, "keyboard": true},
  "layout": {"improvedLayout": true},
  "physics": {
    "forceAtlas2Based": {
      "gravitationalConstant": -50,
      "centralGravity": 0.01,
      "springLength": 100,
      "springConstant": 0.08
    },
    "minVelocity": 0.75,
    "solver": "forceAtlas2Based"
  }
}
""")

added_nodes = set()
for subcat in g.subjects(RDF.type, NIST.SubCategory):
    label = next(g.objects(subcat, RDFS.label), subcat.split("#")[-1])
    if not label.lower().startswith("subcategory for"):
        net.add_node(label, label=label, color="#1f77b4", shape="box")
        added_nodes.add(label)
        for control in g.objects(subcat, NIST.hasControl):
            c_label = next(g.objects(control, RDFS.label), control.split("#")[-1])
            net.add_node(c_label, label=c_label, color="#ff7f0e", shape="ellipse")
            net.add_edge(label, c_label)
            added_nodes.add(c_label)
            for tech in g.objects(control, NIST.hasMitigation):
                t_label = next(g.objects(tech, RDFS.label), tech.split("#")[-1])
                net.add_node(t_label, label=t_label, color="#2ca02c", shape="diamond")
                net.add_edge(c_label, t_label)
                added_nodes.add(t_label)

with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
    net.save_graph(tmp.name)
    html = open(tmp.name, 'r', encoding='utf-8').read()
os.remove(tmp.name)
st.components.v1.html(html, height=750, scrolling=True)

# Mapped Mitigations
st.subheader("🧩 Mapped Mitigations")
mapped = []
for control, _, tech in g.triples((None, NIST.hasMitigation, None)):
    for subcat in g.subjects(NIST.hasControl, control):
        s_label = next(g.objects(subcat, RDFS.label), subcat.split("#")[-1])
        if s_label.lower().startswith("subcategory for"):
            continue
        c_label = next(g.objects(control, RDFS.label), control.split("#")[-1])
        t_label = next(g.objects(tech, RDFS.label), tech.split("#")[-1])
        mapped.append({"NIST Subcategory": s_label, "NIST Control": c_label, "D3FEND Technique": t_label})

df = pd.DataFrame(mapped)
st.code(f"🔍 Total hasMitigation triples: {len(df)}")

sc = st.sidebar.selectbox("Filter Subcategory", ["All"] + sorted(df["NIST Subcategory"].unique()))
cc = st.sidebar.selectbox("Filter Control", ["All"] + sorted(df["NIST Control"].unique()))
tc = st.sidebar.selectbox("Filter Technique", ["All"] + sorted(df["D3FEND Technique"].unique()))

if sc != "All": df = df[df["NIST Subcategory"] == sc]
if cc != "All": df = df[df["NIST Control"] == cc]
if tc != "All": df = df[df["D3FEND Technique"] == tc]

st.dataframe(df, use_container_width=True)
st.bar_chart(df["NIST Control"].value_counts())
st.bar_chart(df["D3FEND Technique"].value_counts())

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
