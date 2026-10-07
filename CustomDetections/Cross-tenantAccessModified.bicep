param workspace string

@description('Unique id for the scheduled alert rule')
@minLength(1)
param analytic_id string = 'd1c9d862-7828-43f2-8164-93586d5b2750'

resource workspace_Microsoft_SecurityInsights_analytic_id 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2020-01-01' = {
  name: '${workspace}/Microsoft.SecurityInsights/${analytic_id}'
  kind: 'Scheduled'
  location: resourceGroup().location
  properties: {
    description: 'Detects when Access Type in modified outbound settings for Cross-Tenant Access'
    displayName: 'Cross-tenant Access Settings Outbound Modified'
    enabled: true
    query: '''
        // When Access Type in modified outbound settings value is 1 that means that now access is allowed. When Access Type in modified outbound settings value is 2 that means that now access is blocked.
        AuditLogs
        | where OperationName has "Update a partner cross-tenant access setting"
        | mv-apply TargetResource = TargetResources on
          (
              where TargetResource.type =~ "Policy"
              | extend Properties = TargetResource.modifiedProperties
          )
        | mv-apply Property = Properties on
          (
              where Property.displayName =~ "b2bCollaborationOutbound"
              | extend PremodifiedOutboundSettings = trim('"',tostring(Property.oldValue)),
                      ModifiedOutboundSettings = trim(@'"',tostring(Property.newValue))
          )
        | where PremodifiedOutboundSettings != ModifiedOutboundSettings
        | extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
        | extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
        | extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
        | extend InitiatingIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddress), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
        | extend InitiatingAccountName = tostring(split(InitiatingUserPrincipalName, "@")[0]), InitiatingAccountUPNSuffix = tostring(split(InitiatingUserPrincipalName, "@")[1])
    '''
    queryFrequency: 'PT6H'
    queryPeriod: 'PT7H'
    severity: 'Medium'
    suppressionDuration: 'PT4H'
    suppressionEnabled: false
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    tactics: [
      'Persistence'
    ]
  }
}
