#!/usr/bin/env pwsh
#Requires -PSEdition Core

<#
.SYNOPSIS 
    A wrapper around Terraform to ease integration with Azure state backends.
    It is very convention-driven, so please see https://github.com/olohmann/terraform-azure-runner/README.md
    for details. 
.DESCRIPTION 
    See https://github.com/olohmann/terraform-azure-runner/README.md for details.
.NOTES 
    File Name  : tf.ps1 
    Author     : Oliver Lohmann (oliver@lohmann.io) 
.LINK 
    https://github.com/olohmann/terraform-azure-runner
.EXAMPLE 
    See https://github.com/olohmann/terraform-azure-runner/README.md for details.
#>

param (
    # Target Path to the Terraform .tf files directory.
    [Parameter(
            Mandatory = $true)]
    [string]
    $TargetPath,

    # Name of the environment (e.g. dev, qa, prod). Is translated to a Terraform workspace.
    [Parameter(
            Mandatory = $false,
            HelpMessage = "EnvironmentName is a lowercase, alphanumeric name, starting with a letter.")]
    [Alias('e')]
    [ValidatePattern('(?-i:^[a-z][a-z0-9]+$)')]
    [ValidateLength(1,8)]
    [string]
    $EnvironmentName = "dev",

    # A shared prefix which is used to prefix the resource group for the storage account.
    # It will also be set to a TF_prefix environment variable when envoking the Terraform
    # deployment process.
    [Parameter(
            Mandatory = $false,
            HelpMessage = "Prefix is a lowercase, alphanumeric name, starting with a letter.")]
    [ValidatePattern('(?-i:^[a-z][a-z0-9]+$)')]
    [ValidateLength(1,8)]
    [string]
    $Prefix = "fabrikam",

    # The location for the resource group and storage account that will be created for the 
    # Terraform state store.
    [Parameter(
            Mandatory = $false,
            HelpMessage = "Location is a valid Azure location.")]
    [string]$Location = "westeurope",
    
    # The path to a Terraform variable file that shall be passed to the deployment.
    [Parameter(Mandatory = $false)][string]$VarFile = "",

    # When set, uses the explicit name for the util resource group instead of a generated
    # one. Not recommended to use, instead follow the conventional defaults.
    [Parameter(Mandatory = $false)][string]$UtilResourceGroupName = "",

    # The Terraform binary version to use.
    [Parameter(Mandatory = $false)][string]$TfVersion = "",

    # Application Insights Instrumentation Key for Metrics.
    [Parameter(Mandatory = $false)][string]$ApplicationInsightsInstrumentationKey = "",

    # Application Insights Instrumentation Key for Metrics.
    [Parameter(Mandatory = $false)][int]$DelayAfterFirewallChange = 10,

    # Do not print colored console ouptut when set.
    [switch]$NoColor = $false,

    # GitToken
    [Parameter(Mandatory = $false)][string]$GitToken = "",
    # GitHost
    [Parameter(Mandatory = $false)][string]$GitHost = "dev.azure.com",

    # Run Terraform init.
    [switch]$Init = $false,

    # Run no upgrade in Terraform init.
    [switch]$TfInitWithoutUpgrade = $false,

    # Run Terraform plan.
    [switch]$Plan = $false,

    # Run Terraform destroy.
    [switch]$Destroy = $false,

    # Run Terraform apply.
    [switch]$Apply = $false,

    # Run Terraform validate.
    [switch][Alias('v')]$Validate = $false,

    # Run Terraform output.
    [switch]$Output = $false,

    # Use an existing Terraform plan (when applying).
    [switch]$UseExistingTerraformPlan = $false,
    
    # Keep the Azure Storage Account's firewall open instead of putting it to default deny 
    # when finishing the deployment process.
    [switch]$LeaveFirewallOpen = $false,
    
    # Print the script's version and exit.
    [switch]$Version = $false,

    # Download the Terraform binary in the minimal required version. 
    [switch][Alias('d')]$DownloadTerraform = $false,
   
    # Print the environment variables during execution.
    [switch][Alias('p')]$PrintEnv = $false,
    
    # Force, that is do not ask for interactive input.
    [switch][Alias('f')]$Force = $false,

    # Show an error message that asks the user to retry the run in the likely case of a FW error.
    [switch]$ShowFirewallErrorRetryMessage = $false
)

Set-StrictMode -Version latest
$ErrorActionPreference = "Stop"
$ScriptVersion = [version]"4.0.0"

# Define default version, if no parameter or unexpected content in TfVersion is set.
$TfVersionDefault = "1.0.5"

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

# this function wraps native command Execution
# for more information, read https://mnaoumov.wordpress.com/2015/01/11/execution-of-external-commands-in-powershell-done-right/
function Start-NativeExecution
{
    param(
        [scriptblock]$sb,
        [switch]$IgnoreExitcode,
        [switch]$VerboseOutputOnError,
        [switch]$Retry
    )

    $backupEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $retryCount = 0
        if ($Retry)
        {
            $maxRetries = 30
        }
        else {
            $maxRetries = 1
        }

        for ($retryCount = 0; $retryCount -lt $maxRetries; $retryCount++) {
            if ($VerboseOutputOnError.IsPresent)
            {
                $output = & $sb 2>&1
            }
            else
            {
                & $sb
            }

            if ($LASTEXITCODE -eq 0)
            {
                break;
            }
            elseif ($Retry)
            {
                Write-Log "Retry $( $retryCount + 1 )/$( $maxRetries )."
                Start-sleep -seconds 3
            }
        }

        # note, if $sb doesn't have a native invocation, $LASTEXITCODE will
        # point to the obsolete value
        if ($LASTEXITCODE -ne 0 -and -not $IgnoreExitcode)
        {
            if ($VerboseOutputOnError.IsPresent -and $output)
            {
                $output | Out-String | Write-Verbose -Verbose
            }

            # Get caller location for easier debugging
            $caller = Get-PSCallStack -ErrorAction SilentlyContinue
            if ($caller)
            {
                $callerLocationParts = $caller[1].Location -split ":\s*line\s*"
                $callerFile = $callerLocationParts[0]
                $callerLine = $callerLocationParts[1]

                $errorMessage = "Execution of {$sb} by ${callerFile}: line $callerLine failed with exit code $LASTEXITCODE"
                throw $errorMessage
            }
            throw "Execution of {$sb} failed with exit code $LASTEXITCODE"
        }
    } finally {
        $ErrorActionPreference = $backupEAP
    }
}

# Verify that parameter TfVersion is set to a valid version number. See https://semver.org/
if ($TfVersion -eq "") {
    Write-Host "Using default terraform version $TfVersionDefault"
    $TfVersion = $TfVersionDefault
}
elseif (-not ($TfVersion -match '^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$')) {
    Write-Warning "Found un-expected content in parameter TfVersion: '$TfVersion'. Fallback to default terraform version $TfVersionDefault"
    $TfVersion = $TfVersionDefault
}

$TerrafomMinimumVersion = [version]$TfVersion
$TerraformNoColor = if ($NoColor) { "-no-color" } else { "" }
$TerraformPlanPath = "terraform.tfplan"
$TerraformOutputPath = "output.json"

$AzureResourceManagerBaseUrl = $(Start-NativeExecution { az cloud show --output json --output json } | ConvertFrom-Json).endpoints.resourceManager
$AzureResourceManagerBaseUrl = $($AzureResourceManagerBaseUrl).Trim('/')

Write-Log "Using AzureResourceManagerBaseUrl $AzureResourceManagerBaseUrl"

# Prepare Options
if ($UtilResourceGroupName -eq "") {
    $UtilResourceGroupName = "$($Prefix)_$($EnvironmentName)_util_rg".ToLower()
}

# Check Location parameter to avoid Error:
# The specified location '/home/vsts/work/1/s' is invalid. A location must consist of characters, whitespace, digit, or following symbols '(,)'.
$CurrentLocation = Get-Location
if ($Location -match $CurrentLocation)
{
    Write-Warning "Found un-expected content in -Location: $Location . Fallback to 'westeurope'"
    $Location = "westeurope"
}

$Location = $Location.ToLower()
$Location = $Location -Replace " "

# If a non-expanded Azure DevOps Variable assignment was found, print a
# warning and continue with the default.
if ($Location -match '\$\([^)]*\)')
{
    $Location = "westeurope"
    Write-Warning "Found un-expanded Azure DevOps Variable assigned to -Location. Fallback to 'westeurope'"
}

$TargetPath = Resolve-Path $TargetPath

$global:TfStateStorageAccountName = ""
$global:TfStateContainerName = "tf-state"

Write-Log ""
Write-Log "[Information]"
Write-Log "Script Version                  $ScriptVersion"
Write-Log "Current working location:       $CurrentLocation"
Write-Log ""
Write-Log "[Provided Options]"
Write-Log "TargetPath:                     $TargetPath"
Write-Log "TfVersion                       $TfVersion"
Write-Log "TfInitWithoutUpgrade            $TfInitWithoutUpgrade"
Write-Log "EnvironmentName:                $EnvironmentName"
Write-Log "Prefix:                         $Prefix"
Write-Log "Location:                       $Location"
Write-Log "VarFile:                        $VarFile"
Write-Log "UtilResourceGroupName:          $UtilResourceGroupName"
Write-Log ""
Write-Log "[Automatically Created TF Environment Variables]"
Write-Log "TF_VAR_prefix                   $Prefix"
Write-Log "TF_VAR_location                 $Location"
Write-Log "TF_VAR_util_resource_group_name $UtilResourceGroupName"
Write-Log ""

if ($VarFile) {
    if ([System.IO.File]::Exists($VarFile)) {
        $VarFile = Resolve-Path $VarFile
    } else {
        Write-Log "Provided VarFile points to not-existing path. Ignoring..."
    }
}

$env:TF_VAR_prefix = $Prefix
$env:TF_VAR_location = $Location
$env:TF_VAR_util_resource_group_name = $UtilResourceGroupName


function GetLocalTerraformInstallation() {
    $tf = $null

    try {
        $tf = Get-Command terraform
    }
    catch {
        if (!$DownloadTerraform) {
            throw "No local terraform client found and option 'DownloadTerraform' not specified."
        }
    }

    return $tf.Source
}

function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

function Get-ArmAuthHeaders {
    $token = az account get-access-token | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $headers = @{
        'Authorization' = "Bearer $($token.accessToken)"
        'Content-Type' = 'application/json' 
        'Accept' = 'application/json' 
    }

    $headers
}

function Open-StorageAccountFirewall {
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
    $headers = Get-ArmAuthHeaders
    $armUrl = "$AzureResourceManagerBaseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$($StorageAccountName)?api-version=2019-06-01"

    $body = @{
        'properties'= @{
            'networkAcls' = @{
                'defaultAction' = 'Allow'
            }
        }
    }

    Invoke-RestMethod -Uri $armUrl -Headers $headers -Method PATCH -Body ($body | ConvertTo-Json -Depth 100) | Out-Null
    Verify-StorageAccountAvailability -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccountName `
        -StateContainerName $global:TfStateContainerName

    Write-Log "Storage account firewall opened."
}

function Close-StorageAccountFirewall {
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
    $headers = Get-ArmAuthHeaders
    $armUrl = "$AzureResourceManagerBaseUrl/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$($StorageAccountName)?api-version=2019-06-01"

    $body = @{
        'properties'= @{
            'networkAcls' = @{
                'defaultAction' = 'Deny'
            }
        }
    }

    Invoke-RestMethod -Uri $armUrl -Headers $headers -Method PATCH -Body ($body | ConvertTo-Json -Depth 100) | Out-Null
    Write-Log "Closed storage account firewall successfully."
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

    $headers = Get-ArmAuthHeaders
    $stateContainerUrl = "$AzureResourceManagerBaseUrl/subscriptions/$SubscriptionId" +
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
            Start-NativeExecution { az storage blob list --account-name $StorageAccountName --account-key $key --container-name $StateContainerName --output none } -IgnoreExitcode
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

    if ($DelayAfterFirewallChange -lt 0)
    {
        Write-Log "Waiting for firewall change to become effective ($DelayAfterFirewallChange secs)..."
        Start-Sleep -Seconds $DelayAfterFirewallChange
    }
}

function GetTerraformOsName {
    if ($IsLinux) {
        return "linux"
    }
    elseif ($IsMacOS) {
        return "darwin"
    }
    elseif ($IsWindows) {
        return "windows"
    }
    else {
        throw "This script is executed in an unsupported OS."
    }
}

function VerifyTerraformSignature {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TerraformDownloadBaseFolder,
        [Parameter(Mandatory = $true)]
        [string]
        $TerraformZipFilePath
    )

    $tfShaSums = Join-Path -Path $TerraformDownloadBaseFolder -ChildPath "terraform_SHA265SUMS"
    $tfShaSumsSig = Join-Path -Path $TerraformDownloadBaseFolder -ChildPath "terraform_SHA265SUMS.sig"

    # See https://www.hashicorp.com/security.html
    $HashiCorpGpgSig = @"
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    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
    ZF5q4h4I33PSGDdSvGXn9UMY5Isjpg==
    =7pIB
    -----END PGP PUBLIC KEY BLOCK-----
"@
    # TODO: Test for gpg in path instead.
    if ($IsWindows -or $IsMacOS) {
        Write-Log "Skipping SHA256SUM signature validation on Windows and MacOS. Requires GPG."
    }
    else {
        $hashiCorpGpgTmpFile = Join-Path $TerraformDownloadBaseFolder -ChildPath "hashicorp.gpg"
        Set-Content -Path $hashiCorpGpgTmpFile -Value $HashiCorpGpgSig
        Start-NativeExecution { gpg --quiet --no-verbose --batch --no-tty --import $hashiCorpGpgTmpFile }
        Start-NativeExecution { gpg --quiet --no-verbose --batch --no-tty --verify  $tfShaSumsSig $tfShaSums }
    }

    $hash = Get-FileHash -Path $TerraformZipFilePath -Algorithm 'SHA256'
    $zipFileName = Split-Path $TerraformZipFilePath -Leaf

    $success = $false
    $shaSums = Get-Content $tfShaSums
    foreach ($line in $shaSums) {
        if ($line -like "*$zipFileName*") {
            $result = $line -Split '  '
            if ($result.Count -gt 0) {
                $success = $result[0] -eq $hash.Hash
            }
        }
    }

    if (!$success) {
        throw "Validating the signature of the downloaded terraform release failed. See Path: $($TerraformDownloadBaseFolder)"
    }
}

function DownloadCurrentTerraformVersionToTemporaryLocation {
    $osName = GetTerraformOsName
    $uriBinary = "https://releases.hashicorp.com/terraform/$TerrafomMinimumVersion/terraform_$($TerrafomMinimumVersion)_$($osName)_amd64.zip"
    $uriShaSums = "https://releases.hashicorp.com/terraform/$TerrafomMinimumVersion/terraform_$($TerrafomMinimumVersion)_SHA256SUMS"
    $uriShaSumsSig = "https://releases.hashicorp.com/terraform/$TerrafomMinimumVersion/terraform_$($TerrafomMinimumVersion)_SHA256SUMS.sig"

    $tmpDirectory = New-TemporaryDirectory
    $outputBinary = Join-Path -Path $tmpDirectory -ChildPath "terraform_$($TerrafomMinimumVersion)_$($osName)_amd64.zip"
    $outputShaSums = Join-Path -Path $tmpDirectory -ChildPath "terraform_SHA265SUMS"
    $outputShaSumsSig = Join-Path -Path $tmpDirectory -ChildPath "terraform_SHA265SUMS.sig"

    Invoke-WebRequest -Uri $uriBinary -OutFile $outputBinary | Out-Null
    Invoke-WebRequest -Uri $uriShaSums -OutFile $outputShaSums | Out-Null
    Invoke-WebRequest -Uri $uriShaSumsSig -OutFile $outputShaSumsSig | Out-Null

    VerifyTerraformSignature -TerraformDownloadBaseFolder $tmpDirectory -TerraformZipFilePath $outputBinary
    Expand-Archive -Path $outputBinary -DestinationPath $tmpDirectory | Out-Null

    if ($IsWindows) {
        $tfExe = Join-Path $tmpDirectory -ChildPath "terraform.exe"
        return $tfExe 
    }
    else {
        $tfExe = Join-Path $tmpDirectory -ChildPath "terraform"
        chmod +x $tfExe
        return $tfExe 
    }
}

function SendTelemetry
{
    [CmdletBinding()]
    Param
    (
        [Parameter(
            Mandatory=$true,
            HelpMessage='Specify the message to log.')]
        [System.String]
        [ValidateNotNullOrEmpty()]
        $Message,

        [Parameter(
            Mandatory=$true,
            HelpMessage='Specify the message severity. Acceptable values are Verbose, Information, Warning, Error, and Critical.')]
        [System.String]
        [ValidateSet('Verbose','Information','Warning','Error','Critical')]
        $Severity,

        [Parameter(Mandatory=$false)]
        [Hashtable]
        $CustomProperties
    )
    Process
    {
        if (!$ApplicationInsightsInstrumentationKey) 
        {
            Write-Log "Sending metrics to APPLICATION INSIGHTS is DISABLED (no instrumentation key present)."
        }
        else {
            Write-Log "Sending metrics to APPLICATION INSIGHTS ($($ApplicationInsightsInstrumentationKey))."
            # See: https://github.com/microsoft/ApplicationInsights-Home/blob/master/EndpointSpecs/ENDPOINT-PROTOCOL.md
            $AppInsightsIngestionEndpoint = "https://dc.services.visualstudio.com/v2/track"
            
            if ($PSBoundParameters.ContainsKey('CustomProperties') -and $CustomProperties.Count -gt 0)
            {
                $customPropertiesObj = [PSCustomObject]$CustomProperties
            }
            else
            {
                $customPropertiesObj = [PSCustomObject]@{}
            }

            $bodyObject = [PSCustomObject]@{
                'name' = "Microsoft.ApplicationInsights.$($ApplicationInsightsInstrumentationKey).Trace"
                'time' = ([System.DateTime]::UtcNow.ToString('o'))
                'iKey' = $ApplicationInsightsInstrumentationKey
                'tags' = [PSCustomObject]@{
                    'ai.cloud.roleInstance' = 'tf'
                    'ai.internal.sdkVersion' = 'tf'
                }
                'data' = [PSCustomObject]@{
                    'baseType' = 'MessageData'
                    'baseData' = [PSCustomObject]@{
                        'ver' = '2'
                        'message' = $Message
                        'severityLevel' = $Severity
                        'properties' = $customPropertiesObj
                    }
                }
            }

            $bodyAsCompressedJson = $bodyObject | ConvertTo-JSON -Depth 10 -Compress
            $headers = @{
                'Content-Type' = 'application/x-json-stream';
            }

            Invoke-RestMethod -Uri $AppInsightsIngestionEndpoint -Method Post -Headers $headers -Body $bodyAsCompressedJson
        }
    }
}

function ValidateTerraformMinimumVersion {
    $versionInfo = [Version]"0.0.0"
    $versionStr = &"$TerraformPath" --% -version
    if ($LastExitCode -gt 0) { throw "Cannot validate terraform version." }

    [Regex]$regex = "v(?<versionNumber>\d+.\d+.\d+)"
    $regexMatch = $regex.Match($versionStr)
    if ($regexMatch.Success) {
        $versionInfo = [Version]$($regexMatch.Groups["versionNumber"].Value)
    }
    else {
        throw "Cannot get version number from terraform."
    }

    if (!$($versionInfo -ge $TerrafomMinimumVersion)) {
        throw "Require at least terraform v$TerrafomMinimumVersion but found terraform v$versionInfo."
    }
}

function Set-TokenForTerraformGitModules
(
    $Token,
    $GitHost = "dev.azure.com"
)
{
    if ($IsLinux -or $IsMacOS)
    {
        if ([String]::IsNullOrEmpty($Token)) {throw "No token provided." }
        $stdinForGitCreds = "protocol=https`nhost=$GitHost`nusername=any`npassword=$Token`n`n"
        Write-Output $stdinForGitCreds | git credential-cache store
        if ($LastExitCode -gt 0) { throw "git CLI error." }
        git config --global credential.helper cache
        if ($LastExitCode -gt 0) { throw "git CLI error." }
        Write-Host "We have set git creds in cache for Host $GitHost, using the provided token."
    }
    else
    {
        Write-Warning "SECURITY ISSUE! 'git config --global credential.helper cache' requires Unix sockets, thus caching does not work on Windows. Storing token unencrypted as file instead. This is insecure and may only be used for testing purposes!"
        $credPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "tempgitcred.txt")
        $stdinForGitCreds = "protocol=https`nhost=$GitHost`nusername=any`npassword=$Token`n`n"
        Write-Output $stdinForGitCreds | git credential-store --file "$credPath" store
        if ($LastExitCode -gt 0) { throw "git CLI error." }
        git config --global credential.helper "store --file $credPath"
        if ($LastExitCode -gt 0) { throw "git CLI error." }
        Write-Host "Stored creds in $credPath for Host $GitHost."
        Get-Content $credPath | Write-Host
    }
}


function GetSha256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $InputString,
        [Parameter(Mandatory = $false)]
        [int]
        $TrimTo = -1
    )

    $hashValue = New-Object System.Security.Cryptography.SHA256Managed `
    | ForEach-Object { $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString)) } `
    | ForEach-Object { $_.ToString("x2") } `
    | Join-String 
    
    $hashValue = $hashValue.ToLower()
    if ($trimTo -gt -1) {
        $hashValue = $hashValue.Substring(0, $trimTo)
    }

    return $hashValue
}

function TryUploadTestBlob {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountName,
        [Parameter(Mandatory = $true)]
        [string]
        $StorageAccountContainerName
    )


}

function CreateOrUpdateTerraformBackend {
    Write-Log "CreateOrUpdate Terraform State Storage"
    Start-NativeExecution { az group create --name "$UtilResourceGroupName" --location "$Location" --output none }

    $azRes = Start-NativeExecution { az group show --name "$UtilResourceGroupName" --output json } | ConvertFrom-Json 

    $tf_backend_resource_group_id = $azRes.Id
    $tf_hash_suffix = GetSha256 -InputString $tf_backend_resource_group_id -TrimTo 6

    $global:TfStateStorageAccountName = "tf$($Prefix)$($EnvironmentName)$($tf_hash_suffix)"

   Start-NativeExecution { az storage account create --name $global:TfStateStorageAccountName `
        --resource-group $UtilResourceGroupName `
        --location $Location --sku "Standard_LRS" `
        --kind "BlobStorage" --access-tier "Hot" `
        --encryption-service "blob" `
        --encryption-service "file" `
        --https-only "true" `
        --default-action "Allow" `
        --bypass "None" `
        --output none `
        --tags "environment=$EnvironmentName" "purpose=TerraformStateStorage" "prefix=$Prefix" }
}

function EnsureAzureCliContext () {
    $defaultSubscriptionDetails = Start-NativeExecution { az account list --all --query "[?isDefault] | [0]" } | ConvertFrom-Json 

    $defaultSubscriptionId = $defaultSubscriptionDetails.id;
    $defaultSubscriptionName = $defaultSubscriptionDetails.name;

    if ($Force) {
        Write-Log "Subscription ID = $defaultSubscriptionId"
        Write-Log "Subscription Name = $defaultSubscriptionName"
        return
    }

    Write-Host "Detected the following Azure configuration:"
    Write-Host "Subscription ID = $defaultSubscriptionId"
    Write-Host "Subscription Name = $defaultSubscriptionName"


    $confirmation = Read-Host "Continue using this subscription? (y/n)"
    if ($confirmation.ToLower() -ne 'y') {
        Write-Host "Stopped by user."
        Write-Host ""
        exit
    }
}

function SwitchToTerraformWorskpace {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,
        [Parameter(Mandatory = $true)]
        [string]
        $Workspace
    )

    Write-Log "Switch Workspace: $Path"

    Push-Location
    try {
        Set-Location -Path $Path
        $tfWorkspace = Start-NativeExecution { &"$TerraformPath" workspace show } -Retry

        Write-Log "Current workspace: $tfWorkspace"
        if ($tfWorkspace.ToLower() -eq $Workspace.ToLower()) {
            Write-Log "No workspace switch required."
        }
        else {
            $tfWorkspaceListString = Start-NativeExecution { &"$TerraformPath" workspace list } -Retry
            $tfWorkspaceList = $tfWorkspaceListString.Split([Environment]::NewLine)
            $found = $false
            foreach ($tfWorkspaceItem in $tfWorkspaceList) {
                Write-Log "Found workspace $tfWorkspaceItem"
                if ($tfWorkspaceItem.ToLower().Contains($Workspace.ToLower())) {
                    $found = $true
                    Break
                }
            }

            if ($found) {
                Start-NativeExecution { &"$TerraformPath" workspace select $Workspace.ToLower() } -Retry -VerboseOutputOnError
            }
            else {
                Start-NativeExecution { &"$TerraformPath" workspace new $Workspace.ToLower() } -Retry -VerboseOutputOnError
            }
        }
    }
    finally {
        Pop-Location
    }
}

function TerraformPlan {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Log "Plan: $Path"

    Push-Location
    try {
        Set-Location -Path $Path
        if ($VarFile) {
            Start-NativeExecution { &"$TerraformPath" plan $TerraformNoColor -input=false -var-file="$VarFile" -out="`"$TerraformPlanPath`"" }
        } else {
            Start-NativeExecution { &"$TerraformPath" plan $TerraformNoColor -input=false -out="`"$TerraformPlanPath`"" }
        }
    }
    finally {
        Pop-Location
    }
}

function TerraformApply {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Log "Apply: $Path"

    Push-Location
    try {
        Set-Location -Path $Path

        if (!$force) {
            $confirmation = Read-Host "Continue deployment? (y/n)"
            if ($confirmation.ToLower() -ne 'y') {
                Write-Host "Stopped by user."
                Write-Host ""
                exit
            }
        }

        Start-NativeExecution { &"$TerraformPath" apply $TerraformNoColor -input=false "`"$TerraformPlanPath`"" }
    }
    finally {
        Pop-Location
    }
}

function TerraformDestroy {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Log "Destroy: $Path"

    Push-Location
    try {
        Set-Location -Path $Path

        if (!$force) {
            $confirmation = Read-Host "Continue with terraform destroy? (y/n)"
            if ($confirmation.ToLower() -ne 'y') {
                Write-Host "Stopped by user."
                Write-Host ""
                exit
            }
        }

        if ($VarFile) {
            Start-NativeExecution { &"$TerraformPath" destroy $TerraformNoColor -auto-approve -input=false -var-file="$VarFile" }
        } else {
            Start-NativeExecution { &"$TerraformPath" destroy $TerraformNoColor -auto-approve -input=false }
        }
    }
    finally {
        Pop-Location
    }
}

function TerraformOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Log "Output: $Path"

    Push-Location
    try {
        Set-Location -Path $Path

        $terrafomOutput = Start-NativeExecution { &"$TerraformPath" output $TerraformNoColor -json }
        Set-Content -Path $TerraformOutputPath  -Value $terrafomOutput
    }
    finally {
        Pop-Location
    }
}


function CleanTerraformDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    $tfStateFile = Join-Path -Path $Path -ChildPath ".terraform" -AdditionalChildPath "terraform.tfstate"
    $tfStateEnvironmentFile = Join-Path -Path $Path -ChildPath ".terraform" -AdditionalChildPath "environment"
    Remove-Item -ErrorAction SilentlyContinue -Path $tfStateFile
    Remove-Item -ErrorAction SilentlyContinue -Path $tfStateEnvironmentFile
    if (!$UseExistingTerraformPlan)
    {
        $tfPlanFile = Join-Path -Path $Path -ChildPath "terraform.tfplan"
        Remove-Item -ErrorAction SilentlyContinue -Path $tfPlanFile
    }
}

function InitTerraformWithRemoteBackend {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Log "Init: $Path"


    Push-Location
    try {
        Set-Location -Path $Path
        Open-StorageAccountFirewall -SubscriptionId $env:ARM_SUBSCRIPTION_ID -ResourceGroupName $UtilResourceGroupName -StorageAccountName $global:TfStateStorageAccountName

        $accountKeyResponse = Start-NativeExecution { az storage account keys list --account-name $global:TfStateStorageAccountName } | ConvertFrom-Json
        $key = $accountKeyResponse[0].value

        Start-NativeExecution { az storage container create --account-name $global:TfStateStorageAccountName --account-key $key --name $global:TfStateContainerName --auth-mode key --output none } -Retry -VerboseOutputOnError
        if (!$TfInitWithoutUpgrade) {
            Start-NativeExecution { &"$TerraformPath" init $TerraformNoColor -upgrade -backend-config "resource_group_name=$UtilResourceGroupName" -backend-config "storage_account_name=$($global:TfStateStorageAccountName)" -backend-config "container_name=$($global:TfStateContainerName)" -backend-config "access_key=`"$key`"" } -Retry -VerboseOutputOnError
        }
        else {
            Start-NativeExecution { &"$TerraformPath" init $TerraformNoColor -backend-config "resource_group_name=$UtilResourceGroupName" -backend-config "storage_account_name=$($global:TfStateStorageAccountName)" -backend-config "container_name=$($global:TfStateContainerName)" -backend-config "access_key=`"$key`"" } -Retry -VerboseOutputOnError
        }  
        
   }
    finally {
        Pop-Location
    }
}

function InitTerraformWithLocalBackend {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Push-Location
    try {
        Set-Location -Path $Path
        if (!$TfInitWithoutUpgrade) {
            Start-NativeExecution { &"$TerraformPath" init -upgrade -backend=false $TerraformNoColor } -VerboseOutputOnError
        }
        else {
            Start-NativeExecution { &"$TerraformPath" init -backend=false $TerraformNoColor } -VerboseOutputOnError
        }                    
    }
    finally {
        Pop-Location
    }
}

function RunTerraformValidate {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Push-Location
    try {
        Set-Location -Path $Path
        Start-NativeExecution { &"$TerraformPath" validate } -VerboseOutputOnError
    } 
    finally {
        Pop-Location
    }
}

function PatchTerraformEnvironmentVariables {
    $environmentVariables = (Get-ChildItem env:*).GetEnumerator() | Sort-Object Name 
    if ($PrintEnv) {
        Write-Log ""
        Write-Log "[ Original Environment Variables ]"
        foreach ($environmentVariable in $environmentVariables) {
            Write-Log "$($environmentVariable.Name)=$($environmentVariable.Value)"
        }
    }

    foreach ($environmentVariable in $environmentVariables) {
        if ($environmentVariable.Name.StartsWith("TF_VAR_")) {
            $caseFixedName = "TF_VAR_" + $environmentVariable.Name.Remove(0, "TF_VAR_".Length).ToLower()
            Set-Item -LiteralPath Env:$caseFixedName -Value $environmentVariable.Value
            if (!$PrintEnv)
            {
                # Only be verbose if there is an actual case fix.
                if ($environmentVariable.Name -ne $caseFixedName)
                {
                    Write-Log "Patched Environment Variable: $( $environmentVariable.Name )='$( $environmentVariable.Value )' ==> $( $caseFixedName )='$( $environmentVariable.Value )'"
                }
            }
        }
    }

    if ($PrintEnv) {
        $environmentVariables = (Get-ChildItem env:*).GetEnumerator() | Sort-Object Name 

        Write-Log ""
        Write-Log "[ Patched Environment Variables ]"
        foreach ($environmentVariable in $environmentVariables) {
            Write-Log "$($environmentVariable.Name)=$($environmentVariable.Value)"
        }

        Write-Log ""
        Write-Log ""
    }
}

function SendMetricsToApplicationInsights {
    $tfProvidersHashSet = New-Object System.Collections.Generic.HashSet[string]
    $tfProvidersRaw = Get-ChildItem -Path "$TargetPath/.terraform" -Filter terraform-provider* -Recurse -ErrorAction SilentlyContinue -Force
    foreach ($tfProvider in $tfProvidersRaw) {
        $tfProvidersHashSet.Add($tfProvider.Name) | Out-Null
    }

    $tfProviders = New-Object string[] $tfProvidersHashSet.Count
    $tfProvidersHashSet.CopyTo($tfProviders) | Out-Null

    $defaultSubscriptionDetails = Start-NativeExecution { az account list --all --query "[?isDefault] | [0]" } | ConvertFrom-Json 
    $defaultSubscriptionId = $defaultSubscriptionDetails.id;
    $defaultSubscriptionName = $defaultSubscriptionDetails.name;

    $metrics = @{
        'timestampUtc' = Get-Date -Format o
        'scriptVersion' = $ScriptVersion.ToString()
        'terraformVersion' = $TfVersion
        'tfInitWithOutUpgrade' = $TfInitWithoutUpgrade
        'teamFoundationCollectionUri' = $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI
        'teamProject' = $env:SYSTEM_TEAMPROJECT
        'teamProjectId' = $env:SYSTEM_TEAMPROJECTID
        'buildNumber' = $env:BUILD_BUILDNUMBER
        'buildId' = $env:BUILD_BUILDID
        'subscriptionId' = $defaultSubscriptionId
        'subscriptionName' = $defaultSubscriptionName
        'tfProviders' = $tfProviders
    }
    
    SendTelemetry -Message "Metrics" -Severity "Information" -CustomProperties $metrics
}

function GetTfCloudNameFromAzCloudName
{
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $azCloudName
    )
    
    switch ($azCloudName) {
        "AzureChinaCloud" { return "china" }
        "AzureUSGovernment" { return "usgovernment" }
        "AzureGermanCloud" { return "german" }
    }  

    return $null
}

# ------------------------------------------------------------------------------
if ($Version) {
    Write-Host $ScriptVersion
    return
}

if (![String]::IsNullOrEmpty($GitToken)) {
    Write-Host "GitToken is set for Terraform Modules."
    Set-TokenForTerraformGitModules $GitToken $GitHost
} else {
    Write-Host "No GitToken set for Terraform Modules."
}

# Prepare Terraform Environment ------------------------------------------------
if ($Validate) {
    Write-Log "Validate only, skipping Azure Backend configuration check."
}
elseif ($env:ARM_CLIENT_ID -and $env:ARM_CLIENT_SECRET -and $env:ARM_SUBSCRIPTION_ID -and $env:ARM_TENANT_ID) {
    Write-Log "Detected Terraform-specific Azure Authorization via environment variables (ARM_CLIENT_ID, ...)"
}
elseif ($env:servicePrincipalId) {
    Write-Log "Detected Azure DevOps az configuration. Automatically setting Terraform env vars."
    $env:ARM_CLIENT_ID = $env:servicePrincipalId
    $env:ARM_CLIENT_SECRET = $env:servicePrincipalKey

    $defaultSubscriptionDetails = az account list --all --query "[?isDefault] | [0]" | ConvertFrom-Json 
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $env:ARM_SUBSCRIPTION_ID = $defaultSubscriptionDetails.id
    $env:ARM_TENANT_ID = $defaultSubscriptionDetails.tenantId

    $env:TF_VAR_team_foundation_collection_uri = $env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI
    $env:TF_VAR_team_project = $env:SYSTEM_TEAMPROJECT
}
elseif ($env:AZURE_CREDENTIALS) {
    Write-Log "Detected GitHub az configuration. Automatically setting Terraform env vars. "
    $GitHubJsonSettings = ConvertFrom-Json -InputObject $env:AZURE_CREDENTIALS
    $env:ARM_CLIENT_ID = $GitHubJsonSettings.clientId
    $env:ARM_CLIENT_SECRET = $GitHubJsonSettings.clientSecret
    $env:ARM_SUBSCRIPTION_ID = $GitHubJsonSettings.subscriptionId
    $env:ARM_TENANT_ID = $GitHubJsonSettings.tenantId
}
else {
    Write-Log "Using az authentication context for Terraform (default for interactive login)"

    $defaultSubscriptionDetails = az account list --all --query "[?isDefault] | [0]" | ConvertFrom-Json 
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $env:ARM_SUBSCRIPTION_ID = $defaultSubscriptionDetails.id
    $env:ARM_TENANT_ID = $defaultSubscriptionDetails.tenantId

    $currentAccount = az account show | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }
    $userName = $currentAccount.user.name

    $user = az ad user show --id "$userName" | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    Write-Log "Setting TF_VAR_az_cli_user_object_id=$($user.objectId)"
    $env:TF_VAR_az_cli_user_object_id=$user.objectId
}

# Fix (non-public) Cloud -------------------------------------------------------
$currentCloud = Start-NativeExecution { az cloud show --query "name" -o tsv }
if ($currentCloud -ne "AzureCloud") { 
    Write-Host "Detected non-public cloud."
    $tfCloud = GetTfCloudNameFromAzCloudName -azCloudName $currentCloud
    if ($tfCloud) {
        Write-Warning "As non public clouds require additional configuration for azurerm provider and state backend, we will now amend their configuration by setting the ARM_ENVIRONMENT environment variable to value '$tfCloud'."
        $env:ARM_ENVIRONMENT = $tfCloud
    }
    else {
        Write-Warning "Unfortunately, we do not know how to translate current cloud $currentCloud to a terraform cloud name. We are thus NOT setting the ARM_ENVIRONMENT."
    }
}

# Fix Environment --------------------------------------------------------------
PatchTerraformEnvironmentVariables

# Setup Terraform --------------------------------------------------------------
if ($DownloadTerraform) {
    $TerraformPath = DownloadCurrentTerraformVersionToTemporaryLocation
}
else {
    $TerraformPath = GetLocalTerraformInstallation
}

ValidateTerraformMinimumVersion
CleanTerraformDirectory -Path $TargetPath
InitTerraformWithLocalBackend -Path $TargetPath

if ($Apply) {
    # Only publish metrics when an actual apply happens.
    SendMetricsToApplicationInsights
}

RunTerraformValidate -Path $TargetPath

if ($Validate) {
    return
}

EnsureAzureCliContext

if ($Init -or $Destroy -or $Plan -or $Apply -or $Output) {
    try {
        try
        {
            CreateOrUpdateTerraformBackend
            CleanTerraformDirectory -Path $TargetPath
            InitTerraformWithRemoteBackend -Path $TargetPath
            SwitchToTerraformWorskpace -Path $TargetPath -Workspace $EnvironmentName
            InitTerraformWithRemoteBackend -Path $TargetPath
        }
        catch {
            if ($ShowFirewallErrorRetryMessage)
            {
                Write-Error "IMPORTANT: Sometimes the re-configuration of the State Storage Firewall can trigger an error. Please retry running the pipeline."
            }
            throw
        }

        if ($Init) {
            # Nothing further to do.
        } elseif ($Destroy) {
            TerraformDestroy -Path $TargetPath
        } elseif ($Plan) {
            TerraformPlan -Path $TargetPath
        } elseif ($Apply) {
            if (!$UseExistingTerraformPlan)
            {
                TerraformPlan -Path $TargetPath
            }
            TerraformApply -Path $TargetPath
        } 
        
        if ($Output) {
            TerraformOutput -Path $TargetPath
        }

    }
    finally
    {
        Close-StorageAccountFirewall -SubscriptionId $env:ARM_SUBSCRIPTION_ID -ResourceGroupName $UtilResourceGroupName -StorageAccountName $global:TfStateStorageAccountName
    }
} else {
    Write-Warning "Nothing modified or initialized. Please specify, -Init, -Destroy, -Plan, -Output or -Apply"
}
