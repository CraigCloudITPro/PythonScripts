from azure.identity import InteractiveBrowserCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from datetime import datetime, timedelta
import csv

# Authenticate once
tenant_id = "xxxxx-xxxxx-xxxxx"  # Replace with your directory ID
credential = InteractiveBrowserCredential(tenant_id=tenant_id)
client = LogsQueryClient(credential)

# Workspace-to-Customer Mapping
workspace_to_customer = {
    "11111111-1111-1111-1111-111111111111": "Customer1",
    "22222222-2222-2222-2222-222222222222": "Customer2",
    "33333333-3333-3333-3333-333333333333": "Customer3"
}

# Define timespan
start_time = datetime.utcnow() - timedelta(days=90)  # 90 days ago
end_time = datetime.utcnow()  # Now

# Query for High Severity Incidents with Tactics and Techniques
query = """
    SecurityIncident
    | where Severity == "High"
    | where TimeGenerated >= ago(90d)
    | extend Tactics = parse_json(tostring(AdditionalData.tactics)), 
                Techniques = parse_json(tostring(AdditionalData.techniques))
    | mv-expand Tactic = Tactics
    | mv-expand Technique = Techniques
    | distinct Tactic = tostring(Tactic), Technique = tostring(Technique)
"""

# Run query and process results
def run_query(client, workspace_to_customer, query):
    results = []
    seen_techniques = set()  # Set to track unique tactic-technique pairs
    for workspace, customer_name in workspace_to_customer.items():
        response = client.query_workspace(
            workspace_id=workspace,
            query=query,
            timespan=(start_time, end_time)
        )
        if response.status == LogsQueryStatus.SUCCESS:
            rows = response.tables[0].rows if response.tables and response.tables[0].rows else []
            for row in rows:
                tactic, technique = row
                if (tactic, technique) not in seen_techniques:
                    results.append([customer_name, tactic, technique])
                    seen_techniques.add((tactic, technique))
        else:
            print(f"Error querying workspace {workspace}: {response.error}")
    return results

# Execute and export results
query_results = run_query(client, workspace_to_customer, query)

# Write to CSV
output_file = "C:/temp/high_incident_tactics_techniques.csv"  # Update path as needed
headers = ["CustomerName", "Tactic", "Technique"]

with open(output_file, "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(headers)
    writer.writerows(query_results)

print(f"Results exported to {output_file}")
