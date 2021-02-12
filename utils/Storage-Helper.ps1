#!/usr/bin/env pwsh
#Requires -PSEdition Core

param
(
)

Set-StrictMode -Version latest
$ErrorActionPreference = "Stop"
$ThisScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )

    if ($Severity -eq 'Information') {
        Write-Host -ForegroundColor Magenta $Message
    }

    if ($Severity -eq 'Warning') {
        Write-Warning $Message
    }

    if ($Severity -eq 'Error') {
        Write-Error $Message
    }
}

function Get-AuthHeaders {
    $token = az account get-access-token | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $headers = @{
        'Authorization' = "Bearer $($token.accessToken)"
        'Content-Type' = 'application/json'
        'Accept' = 'application/json'
    }

    $headers
}

function Verify-StorageAccountAvailability
{
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,

        [Parameter(Mandatory = $true)]
        [string]
        $StateContainerName
    )

    $headers = Get-AuthHeaders
    $stateContainerUrl = "https://management.azure.com/subscriptions/$SubscriptionId" +
        "/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage" +
        "/storageAccounts/$StorageAccountName/blobServices/default/containers/$StateContainerName" +
        "?api-version=2019-06-01"

    $stateContainerBody = @{
        'properties' = @{
            'publicAccess' = 'None'
        }
    }

    $retryCount = 0
    $stateOk = $false
    $maxRetries = 30
    for ($retryCount = 0; $retryCount -lt $maxRetries -and !$stateOk; $retryCount++) {
        try
        {
            Invoke-RestMethod -Uri $stateContainerUrl -Headers $headers -Body ($stateContainerBody | ConvertTo-Json -Depth 100) -Method PUT | Out-Null
            Write-Log "Verified that State Container '$StateContainerName' exists."
            $stateOk = $true
        }
        catch
        {
            $stateOk = $false
        }

        if (!$stateOk)
        {
            Write-Log "Waiting for firewall change to become effective. Retry $( $retryCount + 1 )/$( $maxRetries )."
            Start-sleep -seconds 3
        }
    }

    $retryCount = 0
    $stateOk = $false
    $maxRetries = 30
    $keys = az storage account keys list --account-name $StorageAccountName | ConvertFrom-Json
    if ($LastExitCode -gt 0)
    {
        throw "az CLI error."
    }

    $key = $keys[0].value

    for ($retryCount = 0; $retryCount -lt $maxRetries -and !$stateOk; $retryCount++) {
        try
        {
            $ignore = az storage blob list --account-name $StorageAccountName --account-key $key --container-name $StateContainerName
            if ($LastExitCode -gt 0)
            {
                throw "az CLI error."
            }

            Write-Log "Verified listing blobs in container $StateContainerName."
            $stateOk = $true
        }
        catch
        {
            $stateOk = $false
        }

        if (!$stateOk)
        {
            Write-Log "Waiting for firewall change to become effective. Retry $( $retryCount + 1 )/$( $maxRetries )."
            Start-sleep -seconds 3
        }
    }
}

function Open-StorageFirewall {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName
    )

    Write-Log "Opening storage account firewall..."
    $armUrl = "https://management.azure.com/subscriptions/$SubscriptionId" +
        "/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage" +
        "/storageAccounts/$StorageAccountName" + "?api-version=2019-06-01"

    $headers = Get-AuthHeaders

    $body = @{
        'properties'= @{
            'networkAcls'= @{
                'defaultAction'= 'Allow'
            }
        }
    }

    Invoke-RestMethod -Uri $armUrl -Headers $headers -Method PATCH -Body ($body | ConvertTo-Json -Depth 100) | Out-Null
    Verify-StorageAccountAvailability -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -StateContainerName "tf-state"
    Write-Log "Storage account firewall opened."
}

function Close-StorageFirewall {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName
    )

    Write-Log "Closing storage account firewall..."
    $armUrl = "https://management.azure.com/subscriptions/$SubscriptionId" +
        "/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage" +
        "/storageAccounts/$StorageAccountName" + "?api-version=2019-06-01"

    $headers = Get-AuthHeaders

    $body = @{
        'properties'= @{
            'networkAcls'= @{
                'defaultAction'= 'Deny'
            }
        }
    }

    Invoke-RestMethod -Uri $armUrl -Headers $headers -Method PATCH -Body ($body | ConvertTo-Json -Depth 100) | Out-Null

    Write-Log "Storage account firewall closed."
}


try {
    Open-StorageFirewall -SubscriptionId "46527c81-d7f4-4053-ab21-88b3b993b663" -ResourceGroupName "foo_rg" -StorageAccountName "sqlvalr53i4fxpxrj6"
}
finally {
    Close-StorageFirewall -SubscriptionId "46527c81-d7f4-4053-ab21-88b3b993b663" -ResourceGroupName "foo_rg" -StorageAccountName "sqlvalr53i4fxpxrj6"
}
