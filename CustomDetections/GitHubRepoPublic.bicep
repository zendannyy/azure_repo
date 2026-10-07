param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = 'a6e2afd3-559c-4e88-a693-39c1f6789ef1'

resource workspace_Microsoft_SecurityInsights_analytic_id 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    description: 'Identifies GitHub activities where a repository was changed from private to public (repo.access MODIFY with Visibility PUBLIC).'
    displayName: 'GitHub Repo switched from private to public'
    enabled: true
    query: 'GitHubAudit\n| where Action == "repo.access"\n| where OperationType == "MODIFY"\n| where Visibility == "PUBLIC"\n| project TimeGenerated, Action, Actor, Country, Repository, Visibility\n'
    queryFrequency: '6h'
    queryPeriod: '7h'
    severity: 'Medium'
    suppressionDuration: '4h'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'Collection'
    ]
  }
}
