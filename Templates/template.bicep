param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = 'c1c4g894-7826-43e2-8164-93586d5b2750'

resource workspace_Microsoft_SecurityInsights_analytic_id 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    description: 'Description of rule'
    displayName: 'Analytic Rule Name'
    enabled: false
    query: 'DeviceProcessEvents\n| where FolderPath endswith "\\\\curl.exe" and (ProcessCommandLine contains "api.telegram.org/s/" or ProcessCommandLine contains "telegram.me/s/" or ProcessCommandLine contains "-o" or ProcessCommandLine contains "\\\\AppData\\\\Local\\\\Temp\\\\")\n'
    queryFrequency: 'P1D'
    queryPeriod: 'P1D'
    severity: 'Medium'
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'CommandAndControl'
    ]
  }
}
