import dash
from dash import html, dcc, Input, Output
import pandas as pd
import plotly.express as px

# Load and preprocess data
df = pd.read_csv("known_exploited_vulnerabilities.csv")
df['dateAdded'] = pd.to_datetime(df['dateAdded'], errors='coerce')
df = df.dropna(subset=['dateAdded'])

# Normalize ransomware column to lowercase trimmed strings
df['knownRansomwareCampaignUse'] = df['knownRansomwareCampaignUse'].astype(str).str.strip().str.lower()

# Extract filters
years = sorted(df['dateAdded'].dt.year.unique())
vendors = sorted(df['vendorProject'].dropna().unique())
cwes = sorted(set(cwe for row in df['cwes'].dropna() for cwe in str(row).split(',')))
ransomware_options = ['All', 'Known', 'Unknown']

# Initialize Dash app with external stylesheet for dark theme and font
external_stylesheets = [
    "https://cdnjs.cloudflare.com/ajax/libs/bootswatch/5.3.2/darkly/bootstrap.min.css",
    "https://fonts.googleapis.com/css2?family=Oswald:wght@400;600&display=swap"
]
app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

app.layout = html.Div([
    html.H1("KNOWN EXPLOITED VULNERABILITIES DASHBOARD",
            style={"textAlign": "center", "fontFamily": "Oswald, sans-serif", "fontWeight": 600, "marginTop": "20px"}),

    html.Div([
        dcc.Dropdown(
            options=[{"label": str(y), "value": y} for y in years],
            multi=True,
            placeholder="Select Years",
            id="year-filter",
            style={"minWidth": "150px", "color": "black"}
        ),
        dcc.Dropdown(
            options=[{"label": v, "value": v} for v in vendors],
            multi=True,
            placeholder="Select Vendor(s)",
            id="vendor-filter",
            style={"minWidth": "300px", "color": "black"}
        ),
        dcc.Dropdown(
            options=[{"label": cwe.strip(), "value": cwe.strip()} for cwe in cwes],
            multi=True,
            placeholder="Select CWE(s)",
            id="cwe-filter",
            style={"minWidth": "300px", "color": "black"}
        ),
        dcc.RadioItems(
            options=[{"label": opt, "value": opt} for opt in ransomware_options],
            value='All',
            id="ransomware-filter",
            labelStyle={'display': 'inline-block', 'margin-right': '10px'},
            style={"color": "white"}
        )
    ], style={"display": "flex", "flexWrap": "wrap", "gap": "10px", "justifyContent": "center", "marginBottom": "20px"}),

    dcc.Graph(id="time-series-graph", animate=True),
    html.Div([
        html.Br(),
        html.P("Data: CISA KEV, accessed 11 Jun 2025",
               style={"textAlign": "center", "marginTop": "10px", "fontSize": "12px", "color": "#cccccc"})
    ])



], style={"backgroundColor": "#2a2a2a", "color": "white", "fontFamily": "Oswald, sans-serif"})

@app.callback(
    Output("time-series-graph", "figure"),
    Input("year-filter", "value"),
    Input("vendor-filter", "value"),
    Input("cwe-filter", "value"),
    Input("ransomware-filter", "value")
)
def update_graph(selected_years, selected_vendors, selected_cwes, ransomware_filter):
    filtered_df = df.copy()

    if selected_years:
        filtered_df = filtered_df[filtered_df['dateAdded'].dt.year.isin(selected_years)]
    if selected_vendors:
        filtered_df = filtered_df[filtered_df['vendorProject'].isin(selected_vendors)]
    if selected_cwes:
        filtered_df = filtered_df[filtered_df['cwes'].apply(lambda x: any(cwe in str(x) for cwe in selected_cwes))]

    if ransomware_filter == 'Known':
        filtered_df = filtered_df[filtered_df['knownRansomwareCampaignUse'] == 'known']
    elif ransomware_filter == 'Unknown':
        filtered_df = filtered_df[filtered_df['knownRansomwareCampaignUse'] != 'known']

    if filtered_df.empty:
        return px.line(title="No data matches the selected filters.")

    monthly_counts = filtered_df.groupby(filtered_df['dateAdded'].dt.to_period('M')).size().rename("cve_count").reset_index()
    monthly_counts['dateAdded'] = monthly_counts['dateAdded'].dt.to_timestamp()

    fig = px.line(monthly_counts, x='dateAdded', y='cve_count',
                  title='Monthly Count of Exploited CVEs',
                  labels={'dateAdded': 'Month', 'cve_count': 'Number of CVEs'},
                  markers=True,
                  template='plotly_dark')
    fig.update_traces(line_shape='spline', mode='lines+markers')
    fig.update_layout(transition_duration=500)
    return fig

if __name__ == "__main__":
    app.run(debug=False)
