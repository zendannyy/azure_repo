param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = 'c1c9d894-7829-43f2-8164-93586d5b2750'

resource workspace_Microsoft_SecurityInsights_analytic_id 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    description: 'Detects curl.exe invoked with Telegram-related URLs or writing output under AppData\\Local\\Temp, which can indicate payload staging or C2 retrieval via Telegram.'
    displayName: 'Curl From Telegram'
    enabled: true
    query: 'DeviceProcessEvents\n| where FolderPath endswith "\\\\curl.exe" and (ProcessCommandLine contains "api.telegram.org/s/" or ProcessCommandLine contains "telegram.me/s/" or ProcessCommandLine contains "-o" or ProcessCommandLine contains "\\\\AppData\\\\Local\\\\Temp\\\\")\n'
    queryFrequency: '6h'
    queryPeriod: '7h'
    severity: 'Medium'
    suppressionDuration: '4h'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'CommandAndControl'
    ]
  }
}
