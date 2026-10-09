param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = '01a11e9e-5ec3-736d-a1d8-bac080d04db4'

resource workspace_Microsoft_SecurityInsights_analytic_id 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    description: 'Looks to build a baseline of ClientAuthMethod of Client Secret. Will re-visit'
    displayName: 'Client Secret AuthN Baseline'
    enabled: true
    query: '''
        MicrosoftGraphActivityLogs
        | extend ClientAuthMethod = case(ClientAuthMethod == 0, "Public client", ClientAuthMethod == 1, "Client Secret","Client Certifiate" )
        | where ClientAuthMethod contains "Client Secret"
        | summarize TotalRequests = count() by ClientAuthMethod
        | order by TotalRequests desc
    '''
    queryFrequency: 'PT12H'
    queryPeriod: 'PT13H'
    severity: 'Medium'
    suppressionDuration: 'PT4H'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'CredentialAccess'
    ]
  }
}
