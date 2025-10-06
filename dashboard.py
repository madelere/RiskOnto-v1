# Imports
import streamlit as st
from pyvis.network import Network
import tempfile, os
from rdflib import Graph, Namespace, Literal
from rdflib.namespace import RDF, RDFS, OWL, SKOS   # <-- fix: import SKOS from rdflib.namespace
import pandas as pd
import plotly.express as px
import numpy as np
import plotly.graph_objects as go

#### Table Formating
def publication_table(df, title=None, colwidths=None):
    # alternating row colors for print-friendly tables
    n = len(df)
    stripes = np.where(np.arange(n) % 2 == 0, "#ffffff", "#f6f7f9").tolist()

    fig = go.Figure(
        data=[go.Table(
            header=dict(
                values=[f"<b>{c}</b>" for c in df.columns],
                fill_color="#111827",  # very dark header
                font=dict(color="#ffffff", size=14),
                align="left",
                height=34
            ),
            cells=dict(
                values=[df[c] for c in df.columns],
                fill_color=[stripes],  # zebra stripes
                font=dict(color="#111111", size=13),
                align=["left"] * len(df.columns),
                height=28
            ),
            columnwidth=colwidths
        )]
    )
    fig.update_layout(
        title=dict(text=title, x=0.01, xanchor="left", font=dict(size=16)),
        margin=dict(l=10, r=10, t=40, b=10),
    )
    return fig



# Load ontology
g = Graph()
g.parse("RiskOnto_v1-worked.owl", format="xml")

# Namespaces (match your OWL)
RISK = Namespace("https://cs.unb.ca/ontologies/riskonto#")         # <-- fix: real base
D3F  = Namespace("https://cs.unb.ca/ontologies/d3fend#")           # <-- fix: real D3FEND
g.bind("risk", RISK)
g.bind("d3f", D3F)
g.bind("skos", SKOS)

# Helper: safe labels everywhere
def lab(x):
    return str(next(g.objects(x, RDFS.label), Literal(str(x).split("#")[-1])))

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
for subcat in g.subjects(RDF.type, RISK.SubCategory):
    label = next(g.objects(subcat, RDFS.label), subcat.split("#")[-1])
    if not label.lower().startswith("subcategory for"):
        net.add_node(label, label=label, color="#1f77b4", shape="box")
        added_nodes.add(label)
        for control in g.objects(subcat, RISK.hasControl):
            c_label = next(g.objects(control, RDFS.label), control.split("#")[-1])
            net.add_node(c_label, label=c_label, color="#ff7f0e", shape="ellipse")
            net.add_edge(label, c_label)
            added_nodes.add(c_label)
            for tech in g.subjects(RISK.isMitigatedBy, control):
                t_label = lab(tech)
                net.add_node(t_label, label=t_label, color="#2ca02c", shape="diamond")
                net.add_edge(c_label, t_label)

with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp:
    net.save_graph(tmp.name)
    html = open(tmp.name, 'r', encoding='utf-8').read()
os.remove(tmp.name)
st.components.v1.html(html, height=750, scrolling=True)
st.download_button("📥 Download Graph HTML", data=html, file_name="ontology_graph.html")


# Mapped Mitigations
st.subheader("🧩 Mapped Mitigations")
mapped = []
# technique --isMitigatedBy--> control; subcategory --hasControl--> control
for tech, _, control in g.triples((None, RISK.isMitigatedBy, None)):
    for subcat in g.subjects(RISK.hasControl, control):
        s_label = lab(subcat)
        if s_label.lower().startswith("subcategory for"):
            continue
        mapped.append({
            "NIST Subcategory": s_label,
            "NIST Control": lab(control),
            "D3FEND Technique": lab(tech)
        })

df = pd.DataFrame(mapped)
st.code(f"🔍 Total isMitigatedBy triples joined to subcategories: {len(df)}")

# Guard if empty to avoid KeyErrors in the sidebar filters
if df.empty:
    st.warning("No Subcategory–Control–Technique mappings found. Check `isMitigatedBy` and `hasControl` in your OWL.")
else:
    sc = st.sidebar.selectbox("Filter Subcategory", ["All"] + sorted(df["NIST Subcategory"].unique()))
    cc = st.sidebar.selectbox("Filter Control", ["All"] + sorted(df["NIST Control"].unique()))
    tc = st.sidebar.selectbox("Filter Technique", ["All"] + sorted(df["D3FEND Technique"].unique()))

    if sc != "All": df = df[df["NIST Subcategory"] == sc]
    if cc != "All": df = df[df["NIST Control"] == cc]
    if tc != "All": df = df[df["D3FEND Technique"] == tc]

    st.plotly_chart(
    publication_table(df, "Mapped Mitigations"),
    use_container_width=True
    )
    png = publication_table(df, "Mapped Mitigations").to_image(format="png", scale=2)
    st.download_button("Download table (PNG)", png, file_name="mapped_mitigations.png")
    st.bar_chart(df["NIST Control"].value_counts())
    st.bar_chart(df["D3FEND Technique"].value_counts())

# -------------------------
# Tool Compliance
# -------------------------

# Extract tools
# Extract tools
tools = sorted([lab(t) for t in g.subjects(RDF.type, RISK.Tool)])
tool_filter = st.sidebar.selectbox("🔧 Select Tool", ["All"] + tools)

controls = list(g.subjects(RDF.type, RISK.Control))
compliance_summary, recommendations = [], []

for tool in g.subjects(RDF.type, RISK.Tool):
    tool_label = lab(tool)
    if tool_filter != "All" and tool_label != tool_filter:
        continue

    compliant = set(g.objects(tool, RISK.implementsControl))
    missing = set(controls) - compliant

    # FIX: inverse direction for recommendations
    rec_techs = [lab(t) for m in missing for t in g.subjects(RISK.isMitigatedBy, m)]

    compliance_summary.append({
        "Tool": tool_label,
        "Compliant With": ", ".join(sorted([lab(c) for c in compliant])) or "None",
        "Non-Compliant With": ", ".join(sorted([lab(m) for m in missing])) or "None",
        "Recommended Mitigations": ", ".join(sorted(set(rec_techs))) or "None"
    })

    for m in missing:
        m_label = lab(m)
        for t in g.subjects(RISK.isMitigatedBy, m):
            t_label = lab(t)
            recommendations.append({
                "Tool": tool_label,
                "Missing Control": m_label,
                "Suggested Technique": t_label,
                "Explanation": f"{tool_label} lacks NIST control {m_label}, which maps to D3FEND technique {t_label}."
            })


df_compliance = pd.DataFrame(compliance_summary)
df_reco = pd.DataFrame(recommendations)

st.subheader("🧪 Tool Compliance Overview")
st.plotly_chart(
    publication_table(df_compliance, "Tool Compliance Overview"),
    use_container_width=True
)
png = publication_table(df_compliance, "Tool Compliance Overview").to_image(format="png", scale=2)
st.download_button("Download table (PNG)", png, file_name="Tool_Compliance_Overview.png")
st.subheader("🤖 Smart Recommendations")
if not df_reco.empty:
    st.plotly_chart(
    publication_table(df_reco, "Smart Recommendations"),
    use_container_width=True
    )
    png = publication_table(df_reco, "Smart Recommendations").to_image(format="png", scale=2)
    st.download_button("Download table (PNG)", png, file_name="Smart_Recommendation.png")
    st.download_button("📥 Download Recommendations", df_reco.to_csv(index=False).encode("utf-8"), "xai_tool_mitigations.csv")
else:
    st.info("All tools are compliant. No recommendations to display.")

# -------------------------
# Risk Analysis & Heatmap
# -------------------------
risk_data = []
compliance_rows = []
alerts = []

all_controls = list(g.subjects(RDF.type, RISK.Control))
for tool in g.subjects(RDF.type, RISK.Tool):
    label = next(g.objects(tool, RDFS.label), tool.split("#")[-1])
    if tool_filter != "All" and label != tool_filter:
        continue
    implemented = list(g.objects(tool, RISK.implementsControl))
    comp = len(implemented)
    noncomp = len(set(all_controls) - set(implemented))
    total = len(all_controls)
    score = (comp / total * 100) if total > 0 else 0

    compliance_rows.append({"Tool": label, "Score (%)": round(score, 2), "Passed": comp, "Failed": noncomp})

    for asset, _, threat in g.triples((None, RISK.isTargetedBy, None)):
        a_label = next(g.objects(asset, RDFS.label), asset.split("#")[-1])
        t_label = next(g.objects(threat, RDFS.label), threat.split("#")[-1])
        sev = next(g.objects(threat, RISK.severityLevel), Literal("Unknown"))
        lik = next(g.objects(threat, RISK.likelihood), Literal(0.0))
        imp = next(g.objects(threat, RISK.impact), Literal(0))
        risk = next(g.objects(threat, RISK.riskScore), Literal(0.0))

        risk_data.append({"Tool": label, "Asset": a_label, "Threat": t_label, "Severity": str(sev), "Likelihood": float(lik), "Impact": int(imp), "Risk Score": float(risk)})

        if float(risk) >= 5.0 and str(sev) == "High" and score < 50:
            alerts.append({"Tool": label, "Asset": a_label, "Threat": t_label, "Severity": str(sev), "Risk Score": float(risk), "Compliance Score (%)": round(score, 2), "Alert": "⚠️ High risk threat + low compliance"})

df_risk = pd.DataFrame(risk_data)
df_compliance = pd.DataFrame(compliance_rows)
df_alerts = pd.DataFrame(alerts)

st.subheader("📊 Simulated Compliance Scoring")
st.plotly_chart(
    publication_table(df_compliance, "Simulated Compliance Scoring"),
    use_container_width=True
)
png = publication_table(df_compliance, "Simulated Compliance Scoring").to_image(format="png", scale=2)
st.download_button("Download table (PNG)", png, file_name="Compliance_Scoring.png")
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

st.subheader("Placeholder Risk Analysis: Severity, Likelihood, Impact = Risk Score")
st.caption("For now, this placeholder is used only to demonstrate the ontology’s capability to represent and reason about risk, and is not intended as the final solution")

# The table
st.plotly_chart(
    publication_table(filtered_risk, "Placeholder Risk Analysis"),
    use_container_width=True
)

png = publication_table(filtered_risk, "Placeholder Risk Analysis").to_image(format="png", scale=2)
st.download_button("Download table (PNG)", png, file_name="Risk_Analysis.png")

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
