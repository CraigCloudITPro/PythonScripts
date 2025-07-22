This script authenticates to Azure using InteractiveBrowserCredential, 

queries multiple Microsoft Sentinel workspaces for high severity incidents from the last 90 days, 

extracts unique MITRE ATT&CK tactics and techniques, associates them with the customer name, deduplicates the results globally, and exports the final dataset to a CSV.

Replace the tenant_id with a fake UUID

Replace real workspace_ids with fake full-length GUIDs
