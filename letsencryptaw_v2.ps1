#######################################################################################
# Script that renews a Let's Encrypt certificate for an Azure Application Gateway
# Pre-requirements:
#      - Have a storage account in which the folder path has been created: 
#        '/.well-known/acme-challenge/', to put here the Let's Encrypt DNS check files

#      - Add "Path-based" rule in the Application Gateway with this configuration: 
#           - Path: '/.well-known/acme-challenge/*'
#           - Check the configure redirection option
#           - Choose redirection type: permanent
#           - Choose redirection target: External site
#           - Target URL: <Blob public path of the previously created storage account>
#                - Example: 'https://test.blob.core.windows.net/public'
#      - For execution on Azure Automation: Import 'AzureRM.profile', 'AzureRM.Network' 
#        and 'ACMESharp' modules in Azure
#
#      UPDATE 2019-11-27
#      - Due to deprecation of ACMEv1, a new script is required to use ACMEv2.
#        The module to use is called ACME-PS.
#
#      UPDATE 2020-09-03
#      - Migrated to Az modules.
#        Following modules are needed now: Az.Accounts, Az.Network, Az.Storage
#
#      UPDATE 2021-06-05
#      - Added second domain (can be used e.g. to add wildcard domain).
#      - Used DNS challenge instead of HTTP
#
#######################################################################################

Param(
    [string]$domain1,
    [string]$domain2,
    [string]$EmailAddress,
    [string]$dnsResourceGroupName,
    [string]$dnsName,
    [string]$AGResourceGroupName,
    [string]$AGName,
    [string]$AGOldCertName
)

# Ensures that no login info is saved after the runbook is done
Disable-AzContextAutosave

# Log in as the service principal from the Runbook
$connection = Get-AutomationConnection -Name AzureRunAsConnection
Login-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationId $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

# Create a state object and save it to the harddrive
$state = New-ACMEState -Path $env:TEMP
$serviceName = 'LetsEncrypt'

# Fetch the service directory and save it in the state
Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru;

# Get the first anti-replay nonce
New-ACMENonce $state;

# Create an account key. The state will make sure it's stored.
New-ACMEAccountKey $state -PassThru;

# Register the account key with the acme service. The account key will automatically be read from the state
New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS;

# Load an state object to have service directory and account keys available
$state = Get-ACMEState -Path $env:TEMP;

# It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example.
New-ACMENonce $state -PassThru;

# Create the identifier for the DNS name

$identifier = @($domain1, $domain2);

# Create the order object at the ACME service.
$order = New-ACMEOrder $state -Identifiers $identifier;

# Fetch the authorizations for that order
$authorizations = @(Get-ACMEAuthorization -State $state -Order $order);

$Records = @()
$Challenges = @()

foreach($authz in $authorizations) {

    # Select a challenge to fullfill
    $challenge = Get-ACMEChallenge -State $state -Authorization $authz -Type "dns-01";

    $Challenges += $challenge;
    $Records += New-AzDnsRecordConfig -Value $challenge.Data.Content;
    
    $res = ConvertTo-Json $challenge
    Write-Warning $res

}

# Add DNS record
New-AzDnsRecordSet -Overwrite -Name "_acme-challenge" -RecordType TXT -ZoneName $dnsName -ResourceGroupName $dnsResourceGroupName -Ttl 3600 -DnsRecords $Records

# Signal the ACME server that the challenges are ready
foreach($ch in $Challenges) {
    $ch | Complete-ACMEChallenge $state;
}

# Wait a little bit and update the order, until we see the states
while($order.Status -notin ("ready","invalid")) {
    Start-Sleep -Seconds 10;
    $order | Update-ACMEOrder $state -PassThru;
    $res = ConvertTo-Json $order
    Write-Warning $res
}

if($order.Status -eq "invalid") {
    throw "Your order has been marked as invalid - certificate cannot be issued."
}

# We should have a valid order now and should be able to complete it
# Therefore we need a certificate key
$certKey = New-ACMECertificateKey -Path "$env:TEMP\$dnsName.key.xml";

# Complete the order - this will issue a certificate singing request
Complete-ACMEOrder $state -Order $order -CertificateKey $certKey;

# Now we wait until the ACME service provides the certificate url
while(-not $order.CertificateUrl) {
    Start-Sleep -Seconds 15
    $order | Update-Order $state -PassThru
}

# As soon as the url shows up we can create the PFX
$password = ConvertTo-SecureString -String "password" -Force -AsPlainText
Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$dnsName.pfx" -Password $password;

# Delete dns record to check DNS
$RecordSet = Get-AzDnsRecordSet -Name "_acme-challenge" -RecordType TXT -ResourceGroupName $dnsResourceGroupName -ZoneName $dnsName
Remove-AzDnsRecordSet -RecordSet $RecordSet

### RENEW APPLICATION GATEWAY CERTIFICATE ###
$appgw = Get-AzApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName
Set-AzApplicationGatewaySSLCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\$domain.pfx" -Password $password
Set-AzApplicationGateway -ApplicationGateway $appgw


